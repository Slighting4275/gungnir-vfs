//! Mount health, client side (milestone 7). Mirrors src/daemon-rust/src/health.rs; keep
//! both in sync.
//!
//! gungnird probes network and FUSE mounts and pushes a snapshot of every mount that is
//! not healthy (plus every mount at or below one of them) to subscribed connections, as
//! msg_event slots on the reply ring. This file keeps the last complete snapshot and
//! answers `stateOf(path)` from it: a lexical longest-prefix lookup with no syscall at
//! all, least of all on the path, so gmeta.zig can fail a call on a hung mount before it
//! asks the daemon anything. Snapshots arrive through rpc.Client's on_event hook (while a
//! request waits for its reply) and link.zig's event thread (while the link is idle).
//!
//! Wire format (little-endian; see health.rs): event `epoch u64 | flags u8 | count u16 |
//! count x (mnt_id u64 | state u8 | len u16 | path)`; a snapshot is 1..4 slots, the first
//! flagged ev_first, the last ev_last, ev_incomplete if the daemon could not fit it all.
//! Query `by u8 | path bytes` or `by u8 | mnt_id u64`, reply body `mnt_id u64 | state u8 |
//! probed u8 | latency_us u32 | len u16 | mount point`. Subscribe: empty, reply `epoch u64`.
const std = @import("std");
const c = @import("c");
const ipc = @import("ipc.zig");
const rpc = @import("rpc.zig");
const proto = @import("proto.zig");

pub const msg_query = proto.msg_health_query;
pub const msg_subscribe = proto.msg_health_subscribe;
pub const msg_event = proto.msg_health_event;
pub const query_by_path: u8 = 0;
pub const query_by_id: u8 = 1;
pub const ev_first: u8 = 1;
pub const ev_last: u8 = 2;
pub const ev_incomplete: u8 = 4;

/// Mount states (plain integers, as on the wire).
pub const healthy: u8 = 0;
pub const slow: u8 = 1;
pub const hung: u8 = 2;
pub const gone: u8 = 3;
/// No usable snapshot covers the path: ask the daemon (which gates hung mounts itself).
pub const unknown: u8 = 0xff;

/// Snapshot capacity; a larger one makes every lookup `unknown` until the next.
pub const max_entries = 64;
pub const max_mount_path = 1024;
const path_max = 4096;

const Entry = struct {
    mnt_id: u64 = 0,
    state: u8 = healthy,
    len: u16 = 0,
    path: [max_mount_path]u8 = undefined,

    fn mountPoint(e: *const Entry) []const u8 {
        return e.path[0..e.len];
    }
};

const Table = struct {
    entries: [max_entries]Entry = undefined,
    n: usize = 0,
    usable: bool = true,
    epoch: u64 = 0,
};

/// The last complete snapshot. Read by lookups on any thread, under `table_lock` (held
/// for a memory scan or a copy only; a zero-initialised static GMutex needs no init).
var current: Table = .{};
var table_lock: c.GMutex = std.mem.zeroes(c.GMutex);
/// The snapshot being assembled. Only touched by whoever reads the reply ring, which
/// link.zig serialises (its lock), or by tests.
var staging: Table = .{};
var staging_active = false;

// ---- events -----------------------------------------------------------------

const Malformed = error{Malformed};

const Reader = struct {
    rest: []const u8,

    fn take(r: *Reader, n: usize) Malformed![]const u8 {
        if (r.rest.len < n) return error.Malformed;
        const out = r.rest[0..n];
        r.rest = r.rest[n..];
        return out;
    }

    fn int(r: *Reader, comptime T: type) Malformed!T {
        const b = try r.take(@sizeOf(T));
        return std.mem.readInt(T, b[0..@sizeOf(T)], .little);
    }
};

fn validMountPath(p: []const u8) bool {
    return p.len > 0 and p[0] == '/' and std.mem.findScalar(u8, p, 0) == null;
}

/// rpc.Client's on_event hook: apply one event slot. A malformed one drops the snapshot
/// being assembled (the daemon's next snapshot replaces it anyway).
pub fn onEvent(payload: []const u8) void {
    applyEvent(payload) catch {
        staging_active = false;
    };
}

fn applyEvent(p: []const u8) Malformed!void {
    var r: Reader = .{ .rest = p };
    const epoch = try r.int(u64);
    const flags = try r.int(u8);
    const count = try r.int(u16);
    if (flags & ev_first != 0) {
        staging.n = 0;
        staging.usable = true;
        staging.epoch = epoch;
        staging_active = true;
    } else if (!staging_active or staging.epoch != epoch) {
        return; // the tail of a snapshot whose head we missed: wait for the next one
    }
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const id = try r.int(u64);
        const st = try r.int(u8);
        const len = try r.int(u16);
        const path = try r.take(len);
        if (st > gone or !validMountPath(path)) return error.Malformed;
        if (staging.n == max_entries or len > max_mount_path) {
            staging.usable = false;
            continue;
        }
        const e = &staging.entries[staging.n];
        e.mnt_id = id;
        e.state = st;
        e.len = len;
        @memcpy(e.path[0..len], path);
        staging.n += 1;
    }
    if (r.rest.len != 0) return error.Malformed;
    if (flags & ev_incomplete != 0) staging.usable = false;
    if (flags & ev_last != 0) {
        commit();
        staging_active = false;
    }
}

fn commit() void {
    c.g_mutex_lock(&table_lock);
    defer c.g_mutex_unlock(&table_lock);
    for (staging.entries[0..staging.n], 0..) |*e, i| {
        const d = &current.entries[i];
        d.mnt_id = e.mnt_id;
        d.state = e.state;
        d.len = e.len;
        @memcpy(d.path[0..e.len], e.mountPoint());
    }
    current.n = staging.n;
    current.usable = staging.usable;
    current.epoch = staging.epoch;
}

/// Forget everything (connection lost or closed): no mount is known to be hung.
pub fn reset() void {
    staging_active = false;
    c.g_mutex_lock(&table_lock);
    defer c.g_mutex_unlock(&table_lock);
    current.n = 0;
    current.usable = true;
    current.epoch = 0;
}

// ---- lookups (pure: no syscall, the path is never touched) -----------------------

/// Lexically normalise an absolute path into `out` ("." dropped, ".." pops, repeated
/// slashes collapsed). Null for a relative or too long path.
pub fn lexical(path: []const u8, out: *[path_max]u8) ?[]const u8 {
    if (path.len == 0 or path[0] != '/') return null;
    var len: usize = 0;
    var start: usize = 0;
    while (start <= path.len) {
        const end = std.mem.findScalarPos(u8, path, start, '/') orelse path.len;
        const comp = path[start..end];
        start = end + 1;
        if (comp.len == 0 or std.mem.eql(u8, comp, ".")) continue;
        if (std.mem.eql(u8, comp, "..")) {
            len = std.mem.findScalarLast(u8, out[0..len], '/') orelse 0;
            continue;
        }
        if (len + 1 + comp.len > out.len) return null;
        out[len] = '/';
        @memcpy(out[len + 1 ..][0..comp.len], comp);
        len += 1 + comp.len;
    }
    if (len == 0) {
        out[0] = '/';
        len = 1;
    }
    return out[0..len];
}

fn under(path: []const u8, mount_point: []const u8) bool {
    if (std.mem.eql(u8, mount_point, "/")) return true;
    if (!std.mem.startsWith(u8, path, mount_point)) return false;
    return path.len == mount_point.len or path[mount_point.len] == '/';
}

/// The state of the mount `path` is on, as far as the last snapshot knows: healthy if
/// no listed mount covers it, `unknown` if the snapshot is unusable or the path is not
/// absolute. Longest mount-point prefix; a later entry wins a tie (mounted on top).
pub fn stateOf(path: []const u8) u8 {
    var buf: [path_max]u8 = undefined;
    const norm = lexical(path, &buf) orelse return unknown;
    c.g_mutex_lock(&table_lock);
    defer c.g_mutex_unlock(&table_lock);
    if (!current.usable) return unknown;
    var best: ?*const Entry = null;
    for (current.entries[0..current.n]) |*e| {
        if (!under(norm, e.mountPoint())) continue;
        if (best == null or e.len >= best.?.len) best = e;
    }
    return if (best) |b| b.state else healthy;
}

/// Is `path` on a mount the daemon reported hung or gone? Calls on it must fail fast.
pub fn blocks(path: []const u8) bool {
    const s = stateOf(path);
    return s == hung or s == gone;
}

/// Hung and gone mounts in the last snapshot (GungnirVfs:unhealthy-mounts).
pub fn unhealthyCount() c_int {
    c.g_mutex_lock(&table_lock);
    defer c.g_mutex_unlock(&table_lock);
    var n: c_int = 0;
    for (current.entries[0..current.n]) |*e| {
        if (e.state == hung or e.state == gone) n += 1;
    }
    return n;
}

// ---- requests ---------------------------------------------------------------

pub const Info = struct {
    mnt_id: u64,
    state: u8,
    probed: bool,
    /// std.math.maxInt(u32): never probed.
    latency_us: u32,
    buf: [ipc.payload_max]u8 = undefined,
    len: usize = 0,

    pub fn mountPoint(i: *const Info) []const u8 {
        return i.buf[0..i.len];
    }
};

fn parseInfo(body: []const u8) rpc.Error!Info {
    var r: Reader = .{ .rest = body };
    var info: Info = .{
        .mnt_id = r.int(u64) catch return error.Protocol,
        .state = r.int(u8) catch return error.Protocol,
        .probed = false,
        .latency_us = 0,
    };
    const probed = r.int(u8) catch return error.Protocol;
    info.latency_us = r.int(u32) catch return error.Protocol;
    const len = r.int(u16) catch return error.Protocol;
    const mp = r.take(len) catch return error.Protocol;
    if (info.state > gone or probed > 1 or !validMountPath(mp) or r.rest.len != 0) return error.Protocol;
    info.probed = probed == 1;
    @memcpy(info.buf[0..mp.len], mp);
    info.len = mp.len;
    return info;
}

/// The mount `path` is on and its health (an M6 daemon: error.Unsupported).
pub fn queryPath(cl: *rpc.Client, path: []const u8) rpc.Error!Info {
    if (path.len == 0 or path[0] != '/' or std.mem.findScalar(u8, path, 0) != null) return error.BadRequest;
    if (1 + path.len > ipc.payload_max) return error.PathTooLong;
    var p: [ipc.payload_max]u8 = undefined;
    p[0] = query_by_path;
    @memcpy(p[1..][0..path.len], path);
    var reply: ipc.Msg = undefined;
    return parseInfo(try cl.request(msg_query, p[0 .. 1 + path.len], &reply));
}

/// A mount by id (error.NotFound if the daemon never saw it).
pub fn queryId(cl: *rpc.Client, mnt_id: u64) rpc.Error!Info {
    var p: [9]u8 = undefined;
    p[0] = query_by_id;
    std.mem.writeInt(u64, p[1..9], mnt_id, .little);
    var reply: ipc.Msg = undefined;
    return parseInfo(try cl.request(msg_query, &p, &reply));
}

/// Ask for health events on this connection; returns the daemon's current epoch. The
/// first snapshot follows the reply on the ring.
pub fn subscribe(cl: *rpc.Client) rpc.Error!u64 {
    var reply: ipc.Msg = undefined;
    const body = try cl.request(msg_subscribe, "", &reply);
    if (body.len != 8) return error.Protocol;
    return std.mem.readInt(u64, body[0..8], .little);
}

// ---- tests ------------------------------------------------------------------

const testing = std.testing;

/// Encode one event slot (tests only; the daemon is the real producer).
fn testEvent(buf: []u8, epoch: u64, flags: u8, entries: []const struct { u64, u8, []const u8 }) []const u8 {
    std.mem.writeInt(u64, buf[0..8], epoch, .little);
    buf[8] = flags;
    std.mem.writeInt(u16, buf[9..11], @intCast(entries.len), .little);
    var n: usize = 11;
    for (entries) |e| {
        std.mem.writeInt(u64, buf[n..][0..8], e[0], .little);
        buf[n + 8] = e[1];
        std.mem.writeInt(u16, buf[n + 9 ..][0..2], @intCast(e[2].len), .little);
        @memcpy(buf[n + 11 ..][0..e[2].len], e[2]);
        n += 11 + e[2].len;
    }
    return buf[0..n];
}

test "lexical normalisation never touches the filesystem" {
    var b: [path_max]u8 = undefined;
    try testing.expectEqualStrings("/", lexical("/", &b).?);
    try testing.expectEqualStrings("/", lexical("//./..", &b).?);
    try testing.expectEqualStrings("/a/c", lexical("/a/b/../c/", &b).?);
    try testing.expectEqualStrings("/mnt/nfs/x", lexical("/mnt//nfs/./x", &b).?);
    try testing.expectEqualStrings("/x", lexical("/a/../../x", &b).?);
    try testing.expect(lexical("relative", &b) == null);
    try testing.expect(lexical("", &b) == null);
    const long: [path_max + 2]u8 = @splat('/');
    try testing.expectEqualStrings("/", lexical(&long, &b).?);
    var deep: [path_max + 2]u8 = @splat('a');
    deep[0] = '/';
    try testing.expect(lexical(&deep, &b) == null);
}

test "snapshots: longest prefix, nested healthy mounts, ties, reset" {
    reset();
    var buf: [ipc.payload_max]u8 = undefined;
    try testing.expectEqual(healthy, stateOf("/mnt/nfs/f"));
    onEvent(testEvent(&buf, 5, ev_first | ev_last, &.{
        .{ 40, hung, "/mnt/nfs" },
        .{ 41, healthy, "/mnt/nfs/scratch" },
        .{ 42, gone, "/mnt/fuse" },
        .{ 43, slow, "/mnt/smb" },
    }));
    try testing.expectEqual(hung, stateOf("/mnt/nfs"));
    try testing.expectEqual(hung, stateOf("/mnt/nfs/a/b"));
    try testing.expectEqual(hung, stateOf("/mnt/nfs/scratch/../f"));
    try testing.expectEqual(healthy, stateOf("/mnt/nfs/scratch/f"));
    try testing.expectEqual(healthy, stateOf("/mnt/nfsx"));
    try testing.expectEqual(healthy, stateOf("/etc/passwd"));
    try testing.expect(blocks("/mnt/fuse/x"));
    try testing.expect(!blocks("/mnt/smb/x"));
    try testing.expectEqual(slow, stateOf("/mnt/smb/x"));
    try testing.expectEqual(unknown, stateOf("relative/x"));
    try testing.expectEqual(@as(c_int, 2), unhealthyCount());
    // A healthy mount on top of the hung one (same mount point, later): it wins.
    onEvent(testEvent(&buf, 6, ev_first | ev_last, &.{ .{ 40, hung, "/mnt/nfs" }, .{ 46, healthy, "/mnt/nfs" } }));
    try testing.expectEqual(healthy, stateOf("/mnt/nfs/f"));
    // Each snapshot replaces the previous one; an empty one clears everything.
    onEvent(testEvent(&buf, 7, ev_first | ev_last, &.{}));
    try testing.expectEqual(healthy, stateOf("/mnt/fuse/x"));
    onEvent(testEvent(&buf, 8, ev_first | ev_last, &.{.{ 1, hung, "/" }}));
    try testing.expect(blocks("/anything"));
    reset();
    try testing.expect(!blocks("/anything"));
    try testing.expectEqual(@as(c_int, 0), unhealthyCount());
}

test "multi-slot snapshots commit only when complete and consistent" {
    reset();
    var buf: [ipc.payload_max]u8 = undefined;
    onEvent(testEvent(&buf, 9, ev_first, &.{.{ 40, hung, "/a" }}));
    try testing.expect(!blocks("/a/x")); // not committed yet
    onEvent(testEvent(&buf, 9, ev_last, &.{.{ 41, gone, "/b" }}));
    try testing.expect(blocks("/a/x") and blocks("/b/x"));
    // A tail without its head, or from another epoch, is ignored.
    onEvent(testEvent(&buf, 10, ev_last, &.{}));
    try testing.expect(blocks("/a/x"));
    onEvent(testEvent(&buf, 11, ev_first, &.{}));
    onEvent(testEvent(&buf, 12, ev_last, &.{}));
    try testing.expect(blocks("/a/x"));
    // Malformed: wrong state, relative path, trailing bytes, short. The old one stays.
    onEvent(testEvent(&buf, 13, ev_first | ev_last, &.{.{ 1, 9, "/x" }}));
    onEvent(testEvent(&buf, 13, ev_first | ev_last, &.{.{ 1, hung, "x" }}));
    const ok = testEvent(&buf, 13, ev_first | ev_last, &.{});
    var longer: [64]u8 = undefined;
    @memcpy(longer[0..ok.len], ok);
    longer[ok.len] = 0;
    onEvent(longer[0 .. ok.len + 1]);
    onEvent(&.{ 1, 2, 3 });
    try testing.expect(blocks("/a/x") and blocks("/b/x"));
    // Incomplete, or more entries than fit: lookups say "unknown" (ask the daemon).
    onEvent(testEvent(&buf, 14, ev_first | ev_last | ev_incomplete, &.{.{ 1, hung, "/a" }}));
    try testing.expectEqual(unknown, stateOf("/a/x"));
    try testing.expect(!blocks("/a/x"));
    onEvent(testEvent(&buf, 15, ev_first, &.{}));
    var i: u64 = 0;
    while (i <= max_entries) : (i += 1) onEvent(testEvent(&buf, 15, 0, &.{.{ i, hung, "/m" }}));
    onEvent(testEvent(&buf, 15, ev_last, &.{}));
    try testing.expectEqual(unknown, stateOf("/m"));
    onEvent(testEvent(&buf, 16, ev_first | ev_last, &.{.{ 1, hung, "/m" }}));
    try testing.expectEqual(hung, stateOf("/m"));
    reset();
}

test "a client waiting for its reply hands events to on_event; queries round-trip" {
    reset();
    var mem: [ipc.shm_size]u8 align(4096) = undefined;
    const shm: ipc.Shm = .{ .mem = &mem };
    shm.initHeader();
    var fds: [2]i32 = undefined;
    const linux = std.os.linux;
    try testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    var conn: ipc.Conn = .{ .fd = fds[0], .shm = shm };
    var cl: rpc.Client = .{ .conn = &conn, .timeout_ms = 200, .on_event = &onEvent };
    // The daemon's answer is already there: an event, then the reply to seq + 1.
    var buf: [ipc.payload_max]u8 = undefined;
    try shm.push(ipc.ring_d2c, msg_event, 0, testEvent(&buf, 3, ev_first | ev_last, &.{.{ 7, hung, "/n" }}));
    var body: [64]u8 = undefined;
    std.mem.writeInt(u32, body[0..4], proto.st_ok, .little);
    std.mem.writeInt(u64, body[4..12], 7, .little);
    body[12] = hung;
    body[13] = 1;
    std.mem.writeInt(u32, body[14..18], 1500, .little);
    std.mem.writeInt(u16, body[18..20], 2, .little);
    @memcpy(body[20..22], "/n");
    try shm.push(ipc.ring_d2c, proto.msg_reply, cl.seq + 1, body[0..22]);
    const info = try queryPath(&cl, "/n/f");
    try testing.expectEqual(@as(u64, 7), info.mnt_id);
    try testing.expectEqual(hung, info.state);
    try testing.expect(info.probed);
    try testing.expectEqual(@as(u32, 1500), info.latency_us);
    try testing.expectEqualStrings("/n", info.mountPoint());
    try testing.expect(blocks("/n/f")); // the event was applied on the way
    // The request had the documented layout.
    const req = (try shm.pop(ipc.ring_c2d)).?;
    try testing.expectEqual(msg_query, req.kind);
    try testing.expectEqualSlices(u8, "\x00/n/f", req.payload());
    // A malformed reply is a protocol error; bad requests are refused before sending.
    std.mem.writeInt(u16, body[18..20], 3, .little);
    try shm.push(ipc.ring_d2c, proto.msg_reply, cl.seq + 1, body[0..22]);
    try testing.expectError(error.Protocol, queryId(&cl, 7));
    try testing.expectError(error.BadRequest, queryPath(&cl, "rel"));
    // No answer: a bounded timeout.
    cl.timeout_ms = 20;
    try testing.expectError(error.Timeout, subscribe(&cl));
    reset();
}

// Events and query replies come from the peer: random ones never trip a safety check,
// and the table only ever holds valid mount paths.
test "random events and query replies are rejected or applied safely" {
    defer reset();
    var prng = std.Random.DefaultPrng.init(0x5eed_0202);
    const r = prng.random();
    var buf: [ipc.payload_max]u8 = undefined;
    for (0..100_000) |_| {
        const n = r.uintLessThan(usize, 200);
        r.bytes(buf[0..n]);
        if (n >= 11 and r.boolean()) {
            buf[8] = r.uintLessThan(u8, 8); // flags: first/last/incomplete
            buf[9] = r.uintLessThan(u8, 4); // count
            buf[10] = 0;
        }
        onEvent(buf[0..n]);
        _ = parseInfo(buf[0..n]) catch {};
        _ = blocks("/a/b");
    }
}
