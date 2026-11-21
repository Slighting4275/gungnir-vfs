//! Metadata client API (protocol v2, milestones 5 and 6). Mirrors src/daemon-rust/src/md.rs;
//! keep both in sync. Requests travel in ring slots; every call waits for its reply on
//! the daemon->client ring with a deadline, never longer, and notices a stopped daemon
//! (closed control socket) within `liveness_slice_ms`. The GIO metadata::* wiring on top
//! of it is gmeta.zig.
//!
//! A Client is not thread-safe: one request at a time per connection.
//! error.NoSuchFile from set or unset (and nothing from get) can also mean the identity is
//! outdated (its file was replaced on the same inode): identify the path again.
//! Everything read from the daemon is validated; malformed replies are error.Protocol.
const std = @import("std");
const ipc = @import("ipc.zig");
const proto = @import("proto.zig");
const Allocator = std.mem.Allocator;

pub const msg_identify = proto.msg_md_identify;
pub const msg_get = proto.msg_md_get;
pub const msg_set = proto.msg_md_set;
pub const msg_unset = proto.msg_md_unset;
pub const msg_list = proto.msg_md_list;
pub const msg_removed = proto.msg_md_removed;
pub const msg_moved = proto.msg_md_moved;
pub const msg_reply = proto.msg_reply;
/// Unsolicited daemon -> client slot (milestone 7, health.zig): never a reply.
pub const msg_health_event = proto.msg_health_event;

pub const st_ok = proto.st_ok;
pub const st_not_found = proto.st_not_found;
pub const st_busy = proto.st_busy;
pub const st_timeout = proto.st_timeout;
pub const st_suspect_mount = proto.st_suspect_mount;
pub const st_no_such_file = proto.st_no_such_file;
pub const st_bad_request = proto.st_bad_request;
pub const st_key_too_long = proto.st_key_too_long;
pub const st_value_too_large = proto.st_value_too_large;
pub const st_too_many_keys = proto.st_too_many_keys;
pub const st_bad_utf8 = proto.st_bad_utf8;
pub const st_io_error = proto.st_io_error;
pub const st_db_error = proto.st_db_error;
pub const st_unsupported = proto.st_unsupported;

pub const max_uuid_len = 64;
pub const max_key_len = 256;
/// Encoded value, type byte and length prefixes included.
pub const max_value_len = 3072;
pub const max_stringv_items = 64;
pub const max_keys_per_file = 128;

const value_string: u8 = 1;
const value_stringv: u8 = 2;

pub const Error = ipc.Error || Allocator.Error || error{
    NotFound,
    Busy,
    Cancelled,
    SuspectMount,
    NoSuchFile,
    BadRequest,
    KeyTooLong,
    ValueTooLarge,
    TooManyKeys,
    BadUtf8,
    PathTooLong,
    DaemonIo,
    DaemonDb,
    Unsupported,
    /// A system error; its errno is the reply body's first i32 (`proto.osErrno`).
    DaemonOs,
    WouldRecurse,
    MountInside,
    NotEmpty,
};

/// A reply status other than `st_ok` as an error: every status of the protocol, whichever
/// service sent it, so no caller has to look at the raw status.
pub fn statusError(st: u32) Error {
    return switch (st) {
        proto.st_cancelled => error.Cancelled,
        proto.st_os_error => error.DaemonOs,
        proto.st_would_recurse => error.WouldRecurse,
        proto.st_mount_inside => error.MountInside,
        proto.st_not_empty => error.NotEmpty,
        st_not_found => error.NotFound,
        st_busy => error.Busy,
        st_timeout => error.Timeout,
        st_suspect_mount => error.SuspectMount,
        st_no_such_file => error.NoSuchFile,
        st_bad_request => error.BadRequest,
        st_key_too_long => error.KeyTooLong,
        st_value_too_large => error.ValueTooLarge,
        st_too_many_keys => error.TooManyKeys,
        st_bad_utf8 => error.BadUtf8,
        st_io_error => error.DaemonIo,
        st_db_error => error.DaemonDb,
        st_unsupported => error.Unsupported,
        else => error.Protocol,
    };
}

/// A file's metadata key, as the daemon identified it (fs_uuid, subvol, inode,
/// generation) plus its btime for the daemon's staleness check.
pub const Identity = struct {
    uuid_buf: [max_uuid_len]u8 = @splat(0),
    uuid_len: u8 = 0,
    subvol_id: u64 = 0,
    inode_num: u64 = 0,
    generation: u64 = 0,
    btime_sec: i64 = 0,
    btime_nsec: u32 = 0,

    pub fn fsUuid(id: *const Identity) []const u8 {
        return id.uuid_buf[0..@min(id.uuid_len, max_uuid_len)];
    }

    pub fn eql(a: *const Identity, b: *const Identity) bool {
        return std.mem.eql(u8, a.fsUuid(), b.fsUuid()) and a.subvol_id == b.subvol_id and
            a.inode_num == b.inode_num and a.generation == b.generation and
            a.btime_sec == b.btime_sec and a.btime_nsec == b.btime_nsec;
    }
};

/// A metadata value; owned by the allocator passed to Client.get (free with deinit).
pub const Value = union(enum) {
    string: []u8,
    stringv: [][]u8,

    pub fn deinit(v: Value, gpa: Allocator) void {
        switch (v) {
            .string => |s| gpa.free(s),
            .stringv => |list| {
                for (list) |s| gpa.free(s);
                gpa.free(list);
            },
        }
    }
};

pub fn freeKeys(gpa: Allocator, keys: [][]u8) void {
    for (keys) |k| gpa.free(k);
    gpa.free(keys);
}

fn validText(s: []const u8) Error!void {
    if (std.mem.findScalar(u8, s, 0) != null) return error.BadRequest;
    if (!std.unicode.utf8ValidateSlice(s)) return error.BadUtf8;
}

/// 1..=max_key_len bytes of UTF-8 without NUL (checked before sending).
pub fn validKey(k: []const u8) Error!void {
    if (k.len == 0) return error.BadRequest;
    if (k.len > max_key_len) return error.KeyTooLong;
    try validText(k);
}

// ---- encoding (fixed buffer, no allocation) -----------------------------------

const Writer = struct {
    buf: [ipc.payload_max]u8 = undefined,
    len: usize = 0,

    fn bytes(w: *Writer, b: []const u8) Error!void {
        if (b.len > w.buf.len - w.len) return error.ValueTooLarge;
        @memcpy(w.buf[w.len..][0..b.len], b);
        w.len += b.len;
    }

    fn int(w: *Writer, comptime T: type, v: T) Error!void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .little);
        try w.bytes(&b);
    }

    fn blob16(w: *Writer, b: []const u8) Error!void {
        if (b.len > std.math.maxInt(u16)) return error.ValueTooLarge;
        try w.int(u16, @intCast(b.len));
        try w.bytes(b);
    }

    fn identity(w: *Writer, id: *const Identity) Error!void {
        const u = id.fsUuid();
        if (u.len == 0) return error.BadRequest;
        try w.int(u8, @intCast(u.len));
        try w.bytes(u);
        try w.int(u64, id.subvol_id);
        try w.int(u64, id.inode_num);
        try w.int(u64, id.generation);
        try w.int(i64, id.btime_sec);
        try w.int(u32, id.btime_nsec);
    }

    fn slice(w: *const Writer) []const u8 {
        return w.buf[0..w.len];
    }
};

// ---- decoding (untrusted: every short read is error.Protocol) -----------------

const Reader = struct {
    rest: []const u8,

    fn take(r: *Reader, n: usize) Error![]const u8 {
        if (r.rest.len < n) return error.Protocol;
        const out = r.rest[0..n];
        r.rest = r.rest[n..];
        return out;
    }

    fn int(r: *Reader, comptime T: type) Error!T {
        const b = try r.take(@sizeOf(T));
        return std.mem.readInt(T, b[0..@sizeOf(T)], .little);
    }

    fn blob16(r: *Reader) Error![]const u8 {
        return r.take(try r.int(u16));
    }

    fn end(r: *const Reader) Error!void {
        if (r.rest.len != 0) return error.Protocol;
    }

    fn identity(r: *Reader) Error!Identity {
        var id: Identity = .{};
        const n = try r.int(u8);
        if (n == 0 or n > max_uuid_len) return error.Protocol;
        const u = try r.take(n);
        for (u) |ch| if (ch <= ' ' or ch >= 0x7f) return error.Protocol;
        @memcpy(id.uuid_buf[0..n], u);
        id.uuid_len = n;
        id.subvol_id = try r.int(u64);
        id.inode_num = try r.int(u64);
        id.generation = try r.int(u64);
        id.btime_sec = try r.int(i64);
        id.btime_nsec = try r.int(u32);
        return id;
    }
};

fn dupeText(gpa: Allocator, s: []const u8) Error![]u8 {
    validText(s) catch return error.Protocol;
    return gpa.dupe(u8, s);
}

fn decodeValue(gpa: Allocator, body: []const u8) Error!Value {
    var r: Reader = .{ .rest = body };
    switch (try r.int(u8)) {
        value_string => {
            const s = try dupeText(gpa, try r.blob16());
            errdefer gpa.free(s);
            try r.end();
            return .{ .string = s };
        },
        value_stringv => {
            const n = try r.int(u16);
            if (n > max_stringv_items) return error.Protocol;
            const list = try gpa.alloc([]u8, n);
            var filled: usize = 0;
            errdefer {
                for (list[0..filled]) |s| gpa.free(s);
                gpa.free(list);
            }
            while (filled < n) : (filled += 1) list[filled] = try dupeText(gpa, try r.blob16());
            try r.end();
            return .{ .stringv = list };
        },
        else => return error.Protocol,
    }
}

// ---- client -----------------------------------------------------------------

/// While waiting for a reply, the control socket is re-checked this often, so a daemon
/// that stops mid-request costs at most this long, not the whole deadline.
pub const liveness_slice_ms: u64 = 20;

pub const Client = struct {
    /// Borrowed; the connection must outlive the client.
    conn: *ipc.Conn,
    seq: u64 = 1 << 32, // clear of the handshake ping's seq
    /// Upper bound for one request's round trip.
    timeout_ms: u32 = 1000,
    /// A message kind that only says the daemon is alive and working: 0 for none.
    beat_kind: u32 = 0,
    /// Polled while waiting: true gives up with `error.Cancelled`.
    stop: ?*const fn (?*anyopaque) bool = null,
    stop_ctx: ?*anyopaque = null,
    /// Absolute CLOCK_MONOTONIC deadline (ns) shared by a series of requests, e.g. all the
    /// round trips of one GIO call; 0 for none. The earlier of this and `timeout_ms` wins.
    deadline_ns: u64 = 0,
    /// Gets the payload of every health event met while waiting for a reply (milestone
    /// 7); null drops them.
    on_event: ?*const fn (payload: []const u8) void = null,

    /// Send one request and wait for its reply. Returns the body (a slice of `reply`)
    /// on st_ok, else the status as an error. Replies to earlier, timed-out requests
    /// are skipped. error.DaemonAbsent: the daemon closed the connection.
    fn call(c: *Client, kind: u32, payload: []const u8, reply: *ipc.Msg) Error![]const u8 {
        const own = nowNs() + @as(u64, c.timeout_ms) * std.time.ns_per_ms;
        var deadline = if (c.deadline_ns != 0) @min(own, c.deadline_ns) else own;
        if (nowNs() >= deadline) return error.Timeout;
        if (!c.conn.alive()) return error.DaemonAbsent;
        c.seq +%= 1;
        const seq = c.seq;
        try c.conn.shm.push(ipc.ring_c2d, kind, seq, payload);
        while (true) {
            const slice_end = @min(deadline, nowNs() + liveness_slice_ms * std.time.ns_per_ms);
            c.conn.shm.waitReadable(ipc.ring_d2c, slice_end) catch |err| switch (err) {
                error.Timeout => {
                    if (nowNs() >= deadline) return error.Timeout;
                    if (!c.conn.alive()) return error.DaemonAbsent;
                    if (c.stop) |f| if (f(c.stop_ctx)) return error.Cancelled;
                    continue;
                },
                else => return err,
            };
            while (try c.conn.shm.pop(ipc.ring_d2c)) |m| {
                if (m.kind == msg_health_event) {
                    if (c.on_event) |f| f(m.payload());
                    continue;
                }
                if (m.seq != seq) continue;
                // Alive and working: the silence bound starts again.
                if (c.beat_kind != 0 and m.kind == c.beat_kind) {
                    deadline = nowNs() + @as(u64, c.timeout_ms) * std.time.ns_per_ms;
                    continue;
                }
                if (m.kind != msg_reply) return error.Protocol;
                reply.* = m;
                var r: Reader = .{ .rest = reply.payload() };
                const st = try r.int(u32);
                if (st != st_ok) return statusError(st);
                return r.rest;
            }
        }
    }

    /// One raw request (other protocol modules, e.g. health.zig): the reply body on
    /// st_ok, a slice of `reply`; else the status as an error.
    pub fn request(c: *Client, kind: u32, payload: []const u8, reply: *ipc.Msg) Error![]const u8 {
        return c.call(kind, payload, reply);
    }

    /// Identify an absolute path (a symlink is identified as itself).
    pub fn identify(c: *Client, path: []const u8) Error!Identity {
        try checkPath(path);
        if (path.len > ipc.payload_max) return error.PathTooLong;
        var reply: ipc.Msg = undefined;
        var r: Reader = .{ .rest = try c.call(msg_identify, path, &reply) };
        const id = try r.identity();
        try r.end();
        return id;
    }

    fn keyed(id: *const Identity, key: []const u8) Error!Writer {
        try validKey(key);
        var w: Writer = .{};
        try w.identity(id);
        try w.blob16(key);
        return w;
    }

    /// The value of `key`, or null if it is not set. Free the result with Value.deinit.
    pub fn get(c: *Client, gpa: Allocator, id: *const Identity, key: []const u8) Error!?Value {
        var w = try keyed(id, key);
        var reply: ipc.Msg = undefined;
        const body = c.call(msg_get, w.slice(), &reply) catch |err| switch (err) {
            error.NotFound => return null,
            else => return err,
        };
        return try decodeValue(gpa, body);
    }

    pub fn setString(c: *Client, id: *const Identity, key: []const u8, value: []const u8) Error!void {
        try validText(value);
        if (3 + value.len > max_value_len) return error.ValueTooLarge;
        var w = try keyed(id, key);
        try w.int(u8, value_string);
        try w.blob16(value);
        var reply: ipc.Msg = undefined;
        _ = try c.call(msg_set, w.slice(), &reply);
    }

    pub fn setStringv(c: *Client, id: *const Identity, key: []const u8, values: []const []const u8) Error!void {
        if (values.len > max_stringv_items) return error.ValueTooLarge;
        var total: usize = 3;
        for (values) |v| {
            try validText(v);
            total += 2 + v.len;
        }
        if (total > max_value_len) return error.ValueTooLarge;
        var w = try keyed(id, key);
        try w.int(u8, value_stringv);
        try w.int(u16, @intCast(values.len));
        for (values) |v| try w.blob16(v);
        var reply: ipc.Msg = undefined;
        _ = try c.call(msg_set, w.slice(), &reply);
    }

    /// Remove `key`; not an error if it was not set.
    pub fn unset(c: *Client, id: *const Identity, key: []const u8) Error!void {
        var w = try keyed(id, key);
        var reply: ipc.Msg = undefined;
        _ = try c.call(msg_unset, w.slice(), &reply);
    }

    /// Report that the file at `path` was deleted (GIO's local_file_removed); the daemon
    /// drops the metadata of the files last seen there. Returns how many it dropped.
    pub fn removed(c: *Client, path: []const u8) Error!u32 {
        try checkPath(path);
        if (path.len > ipc.payload_max) return error.PathTooLong;
        var reply: ipc.Msg = undefined;
        var r: Reader = .{ .rest = try c.call(msg_removed, path, &reply) };
        const n = try r.int(u32);
        try r.end();
        return n;
    }

    pub const Moved = struct { rewritten: u32, forgotten: u32 };

    /// Report that `src` was renamed to `dest` (GIO's local_file_moved). Metadata is keyed
    /// by identity and stays with the file; the daemon updates its path hints.
    pub fn moved(c: *Client, src: []const u8, dest: []const u8) Error!Moved {
        try checkPath(src);
        try checkPath(dest);
        if (std.mem.eql(u8, src, dest)) return error.BadRequest;
        var w: Writer = .{};
        w.blob16(src) catch return error.PathTooLong;
        w.blob16(dest) catch return error.PathTooLong;
        var reply: ipc.Msg = undefined;
        var r: Reader = .{ .rest = try c.call(msg_moved, w.slice(), &reply) };
        const out: Moved = .{ .rewritten = try r.int(u32), .forgotten = try r.int(u32) };
        try r.end();
        return out;
    }

    /// Every key of the file in byte order, following the daemon's pagination. Free the
    /// result with freeKeys.
    pub fn listKeys(c: *Client, gpa: Allocator, id: *const Identity) Error![][]u8 {
        var keys: std.ArrayList([]u8) = .empty;
        errdefer {
            for (keys.items) |k| gpa.free(k);
            keys.deinit(gpa);
        }
        // Bounded: the daemon caps keys per file, each page makes progress.
        var pages: usize = 0;
        while (pages <= max_keys_per_file) : (pages += 1) {
            var w: Writer = .{};
            try w.identity(id);
            try w.blob16(if (keys.items.len == 0) "" else keys.items[keys.items.len - 1]);
            var reply: ipc.Msg = undefined;
            var r: Reader = .{ .rest = try c.call(msg_list, w.slice(), &reply) };
            const more = try r.int(u8);
            const n = try r.int(u16);
            if (more > 1 or (more == 1 and n == 0)) return error.Protocol;
            if (keys.items.len + n > max_keys_per_file) return error.Protocol;
            for (0..n) |_| {
                const k = try r.blob16();
                validKey(k) catch return error.Protocol;
                const owned = try gpa.dupe(u8, k);
                keys.append(gpa, owned) catch |err| {
                    gpa.free(owned);
                    return err;
                };
            }
            try r.end();
            if (more == 0) return keys.toOwnedSlice(gpa);
        }
        return error.Protocol;
    }
};

/// An absolute path without NUL.
fn checkPath(path: []const u8) Error!void {
    if (path.len == 0 or path[0] != '/' or std.mem.findScalar(u8, path, 0) != null) return error.BadRequest;
}

pub fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.errno(std.os.linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ---- tests ------------------------------------------------------------------

test "identity encoding round trip" {
    var id: Identity = .{ .uuid_len = 4, .subvol_id = 5, .inode_num = std.math.maxInt(u64), .generation = 7, .btime_sec = -3, .btime_nsec = 999 };
    @memcpy(id.uuid_buf[0..4], "ab-c");
    var w: Writer = .{};
    try w.identity(&id);
    try std.testing.expectEqual(@as(usize, 1 + 4 + 8 * 4 + 4), w.len);
    var r: Reader = .{ .rest = w.slice() };
    const back = try r.identity();
    try std.testing.expect(back.eql(&id));
    try r.end();
}

test "replies are validated, never trusted" {
    const gpa = std.testing.allocator;
    // Truncated identity, non-printable uuid, oversized uuid length.
    var r: Reader = .{ .rest = &.{ 4, 'a', 'b' } };
    try std.testing.expectError(error.Protocol, r.identity());
    r = .{ .rest = &.{ 1, 0x01 } };
    try std.testing.expectError(error.Protocol, r.identity());
    r = .{ .rest = &.{ 65, 'a' } };
    try std.testing.expectError(error.Protocol, r.identity());
    // Values: good string, bad UTF-8, trailing bytes, unknown type, short stringv.
    const v = try decodeValue(gpa, &.{ 1, 2, 0, 'h', 'i' });
    defer v.deinit(gpa);
    try std.testing.expectEqualStrings("hi", v.string);
    try std.testing.expectError(error.Protocol, decodeValue(gpa, &.{ 1, 2, 0, 0xc3, 0x28 }));
    try std.testing.expectError(error.Protocol, decodeValue(gpa, &.{ 1, 1, 0, 'a', 'b' }));
    try std.testing.expectError(error.Protocol, decodeValue(gpa, &.{3}));
    try std.testing.expectError(error.Protocol, decodeValue(gpa, &.{ 2, 2, 0, 1, 0, 'a' }));
    const sv = try decodeValue(gpa, &.{ 2, 2, 0, 1, 0, 'a', 0, 0 });
    defer sv.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 2), sv.stringv.len);
    try std.testing.expectEqualStrings("", sv.stringv[1]);
}

test "client-side limits" {
    try std.testing.expectError(error.BadRequest, validKey(""));
    try std.testing.expectError(error.BadRequest, validKey("a\x00b"));
    try std.testing.expectError(error.BadUtf8, validKey("\xff\xfe"));
    const long: [max_key_len + 1]u8 = @splat('k');
    try std.testing.expectError(error.KeyTooLong, validKey(&long));
    try validKey(long[0..max_key_len]);
    try std.testing.expectEqual(st_unsupported, @as(u32, 13));
    try std.testing.expectEqual(error.Busy, statusError(st_busy));
    try std.testing.expectEqual(error.Protocol, statusError(1000));
}

test "moved and removed requests" {
    var buf: [ipc.shm_size]u8 align(4096) = undefined;
    const shm: ipc.Shm = .{ .mem = &buf };
    shm.initHeader();
    var fds: [2]i32 = undefined;
    const linux = std.os.linux;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    var conn: ipc.Conn = .{ .fd = fds[0], .shm = shm };
    var client: Client = .{ .conn = &conn, .timeout_ms = 30 };
    // Refused before anything is sent.
    try std.testing.expectError(error.BadRequest, client.removed("relative"));
    try std.testing.expectError(error.BadRequest, client.moved("/a", "/a"));
    try std.testing.expectError(error.BadRequest, client.moved("/a", "b"));
    const long: [ipc.payload_max]u8 = @splat('/');
    try std.testing.expectError(error.PathTooLong, client.moved(&long, "/b"));
    try std.testing.expect((try shm.pop(ipc.ring_c2d)) == null);
    // Sent with the documented layout; nobody answers: a bounded timeout.
    try std.testing.expectError(error.Timeout, client.moved("/a", "/bc"));
    const m = (try shm.pop(ipc.ring_c2d)).?;
    try std.testing.expectEqual(msg_moved, m.kind);
    try std.testing.expectEqualSlices(u8, &.{ 2, 0, '/', 'a', 3, 0, '/', 'b', 'c' }, m.payload());
    // A spent shared deadline fails at once, without sending.
    client.deadline_ns = 1;
    try std.testing.expectError(error.Timeout, client.removed("/x"));
    try std.testing.expect((try shm.pop(ipc.ring_c2d)) == null);
    // The daemon hangs up: noticed without waiting for the deadline.
    client.deadline_ns = 0;
    client.timeout_ms = 10_000;
    _ = linux.close(fds[1]);
    fds[1] = -1;
    const t0 = nowNs();
    try std.testing.expectError(error.DaemonAbsent, client.removed("/x"));
    try std.testing.expect(nowNs() - t0 < 100 * std.time.ns_per_ms);
}

test "a maximal set request fits one slot" {
    try std.testing.expect(1 + max_uuid_len + 8 * 4 + 4 + 2 + max_key_len + max_value_len <= ipc.payload_max);
}

// Replies come from the peer's memory: no input may trip a safety check or leak.
test "decodeValue survives random replies without leaks" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0101);
    const r = prng.random();
    var buf: [700]u8 = undefined;
    for (0..100_000) |_| {
        const n = r.uintLessThan(usize, buf.len);
        r.bytes(buf[0..n]);
        if (n >= 3) {
            buf[0] = if (r.boolean()) value_string else value_stringv;
            // Small counts and lengths, so valid shapes come up too.
            buf[1] = r.uintLessThan(u8, 8);
            buf[2] = 0;
        }
        if (decodeValue(std.testing.allocator, buf[0..n])) |v| v.deinit(std.testing.allocator) else |_| {}
    }
}
