//! Client half of the control plane, protocol v2 (AGENTS.md §1.B "Handshake protocol").
//! Mirrors src/daemon-rust/src/ipc.rs; keep both in sync. Raw Linux syscalls only, all
//! non-blocking or bounded by a deadline: nothing here can hang the calling thread.
//! Everything read from the socket or the shared memory is untrusted and validated.
const std = @import("std");
const linux = std.os.linux;

/// "GNGR" read as a little-endian u32.
pub const magic: u32 = 0x5247_4E47;
/// Bumped for every layout change; the daemon refuses another version with a reject
/// frame (status_bad_version), reported as error.VersionMismatch.
pub const version: u16 = 2;
pub const kind_hello: u16 = 1;
pub const kind_ack: u16 = 2;
pub const kind_reject: u16 = 3;
pub const frame_len = 16;
pub const status_bad_version: u32 = 2;

pub const slot_count: u32 = 32;
pub const slot_size: usize = 4096;
/// kind u32 | len u32 | seq u64.
pub const slot_header: usize = 16;
pub const payload_max: usize = slot_size - slot_header;
pub const shm_size: usize = 4096 + 2 * slot_count * slot_size;
pub const msg_ping: u32 = 1;
pub const msg_pong: u32 = 2;

pub const Ring = struct { head: usize, tail: usize, slots: usize };
/// Client -> daemon.
pub const ring_c2d: Ring = .{ .head = 64, .tail = 128, .slots = 4096 };
/// Daemon -> client.
pub const ring_d2c: Ring = .{ .head = 192, .tail = 256, .slots = 4096 + slot_count * slot_size };

pub const Error = error{
    NoSocketPath,
    SocketPathTooLong,
    DaemonAbsent,
    Timeout,
    Io,
    Protocol,
    Rejected,
    VersionMismatch,
    BadShm,
    RingFull,
    RingCorrupt,
    ForeignPeer,
};

// ---- setup frame ------------------------------------------------------------

/// magic u32 | version u16 | kind u16 | status u32 | shm_size u32, little-endian.
pub const Frame = struct {
    magic: u32 = magic,
    version: u16 = version,
    kind: u16,
    status: u32 = 0,
    shm_size: u32 = 0,

    pub fn encode(f: Frame) [frame_len]u8 {
        var b: [frame_len]u8 = undefined;
        std.mem.writeInt(u32, b[0..4], f.magic, .little);
        std.mem.writeInt(u16, b[4..6], f.version, .little);
        std.mem.writeInt(u16, b[6..8], f.kind, .little);
        std.mem.writeInt(u32, b[8..12], f.status, .little);
        std.mem.writeInt(u32, b[12..16], f.shm_size, .little);
        return b;
    }

    pub fn decode(b: *const [frame_len]u8) Frame {
        return .{
            .magic = std.mem.readInt(u32, b[0..4], .little),
            .version = std.mem.readInt(u16, b[4..6], .little),
            .kind = std.mem.readInt(u16, b[6..8], .little),
            .status = std.mem.readInt(u32, b[8..12], .little),
            .shm_size = std.mem.readInt(u32, b[12..16], .little),
        };
    }
};

// ---- socket path ------------------------------------------------------------

/// A socket path that fits sun_path (108 bytes including the NUL). No allocation.
pub const SocketPath = struct {
    buf: [108]u8 = @splat(0),
    len: usize = 0,

    pub fn slice(p: *const SocketPath) []const u8 {
        return p.buf[0..p.len];
    }

    fn join(parts: []const []const u8) Error!SocketPath {
        var p: SocketPath = .{};
        for (parts) |part| {
            if (part.len >= p.buf.len - p.len) return error.SocketPathTooLong;
            @memcpy(p.buf[p.len..][0..part.len], part);
            p.len += part.len;
        }
        return p;
    }
};

fn absolute(v: ?[]const u8) ?[]const u8 {
    const s = v orelse return null;
    return if (s.len > 0 and s[0] == '/') s else null;
}

/// First match wins, absolute values only: $GUNGNIR_SOCKET,
/// $XDG_RUNTIME_DIR/gungnir/gungnird.sock, $HOME/.cache/gungnir/gungnird.sock.
pub fn resolveSocketPath(override: ?[]const u8, runtime_dir: ?[]const u8, home: ?[]const u8) Error!SocketPath {
    if (absolute(override)) |p| return SocketPath.join(&.{p});
    if (absolute(runtime_dir)) |d| return SocketPath.join(&.{ d, "/gungnir/gungnird.sock" });
    if (absolute(home)) |h| return SocketPath.join(&.{ h, "/.cache/gungnir/gungnird.sock" });
    return error.NoSocketPath;
}

// ---- time -------------------------------------------------------------------

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Milliseconds left until `deadline`, 0 if it has passed.
fn remainingMs(deadline: u64) i32 {
    const now = nowNs();
    if (now >= deadline) return 0;
    return @intCast(@min((deadline - now) / std.time.ns_per_ms + 1, std.math.maxInt(i32)));
}

// ---- shared memory rings ----------------------------------------------------

pub const Msg = struct {
    kind: u32,
    seq: u64,
    len: usize,
    buf: [payload_max]u8,

    pub fn payload(m: *const Msg) []const u8 {
        return m.buf[0..m.len];
    }
};

/// A view of the shared ring memory (exactly `shm_size` bytes, page-aligned).
pub const Shm = struct {
    mem: []align(4096) u8,

    fn word(s: Shm, off: usize) *u32 {
        return @ptrCast(@alignCast(s.mem[off..][0..4]));
    }

    /// One slot as slot_size / 8 u64 words. The peer process may write a slot at any time,
    /// so slot bytes are only accessed atomically and validated after the copy.
    fn slotWords(s: Shm, ring: Ring, index: u32) *[slot_size / 8]u64 {
        const off = ring.slots + @as(usize, index % slot_count) * slot_size;
        return @ptrCast(@alignCast(s.mem[off..][0..slot_size]));
    }

    pub fn headerOk(s: Shm) bool {
        return @atomicLoad(u32, s.word(0), .acquire) == magic and
            @atomicLoad(u32, s.word(4), .monotonic) == version and
            @atomicLoad(u32, s.word(8), .monotonic) == slot_count and
            @atomicLoad(u32, s.word(12), .monotonic) == slot_size;
    }

    /// Daemon-side initialisation; the client only uses it in tests.
    pub fn initHeader(s: Shm) void {
        @memset(s.mem, 0);
        @atomicStore(u32, s.word(4), version, .monotonic);
        @atomicStore(u32, s.word(8), slot_count, .monotonic);
        @atomicStore(u32, s.word(12), slot_size, .monotonic);
        @atomicStore(u32, s.word(0), magic, .release);
    }

    /// Producer: append one message, then FUTEX_WAKE the consumer (process-shared).
    pub fn push(s: Shm, ring: Ring, kind: u32, seq: u64, payload: []const u8) Error!void {
        if (payload.len > payload_max) return error.Protocol;
        const head_p = s.word(ring.head);
        const head = @atomicLoad(u32, head_p, .monotonic);
        const used = head -% @atomicLoad(u32, s.word(ring.tail), .acquire);
        if (used > slot_count) return error.RingCorrupt;
        if (used == slot_count) return error.RingFull;
        var local: [slot_size]u8 = @splat(0);
        std.mem.writeInt(u32, local[0..4], kind, .little);
        std.mem.writeInt(u32, local[4..8], @intCast(payload.len), .little);
        std.mem.writeInt(u64, local[8..16], seq, .little);
        @memcpy(local[slot_header..][0..payload.len], payload);
        // Only the words holding the header and the payload are written.
        const words = (slot_header + payload.len + 7) / 8;
        for (s.slotWords(ring, head)[0..words], 0..) |*w, i| {
            @atomicStore(u64, w, std.mem.readInt(u64, local[i * 8 ..][0..8], .little), .monotonic);
        }
        @atomicStore(u32, head_p, head +% 1, .release);
        _ = linux.futex_3arg(head_p, .{ .cmd = .WAKE, .private = false }, 1);
    }

    /// Consumer: take one message, null if empty.
    pub fn pop(s: Shm, ring: Ring) Error!?Msg {
        const tail_p = s.word(ring.tail);
        const tail = @atomicLoad(u32, tail_p, .monotonic);
        const used = @atomicLoad(u32, s.word(ring.head), .acquire) -% tail;
        if (used > slot_count) return error.RingCorrupt;
        if (used == 0) return null;
        const words = s.slotWords(ring, tail);
        var slot: [slot_size]u8 = @splat(0);
        for (words[0 .. slot_header / 8], 0..) |*w, i| {
            std.mem.writeInt(u64, slot[i * 8 ..][0..8], @atomicLoad(u64, w, .monotonic), .little);
        }
        var m: Msg = .{
            .kind = std.mem.readInt(u32, slot[0..4], .little),
            .seq = std.mem.readInt(u64, slot[8..16], .little),
            .len = std.mem.readInt(u32, slot[4..8], .little),
            .buf = undefined,
        };
        // Validate the length (read once, into the local copy) before copying the payload.
        if (m.len > payload_max) return error.Protocol;
        const n = (slot_header + m.len + 7) / 8;
        for (words[slot_header / 8 .. n], slot_header / 8..) |*w, i| {
            std.mem.writeInt(u64, slot[i * 8 ..][0..8], @atomicLoad(u64, w, .monotonic), .little);
        }
        @memcpy(&m.buf, slot[slot_header..][0..payload_max]);
        @atomicStore(u32, tail_p, tail +% 1, .release);
        return m;
    }

    /// Consumer: FUTEX_WAIT (process-shared) until non-empty or `deadline` passes.
    pub fn waitReadable(s: Shm, ring: Ring, deadline: u64) Error!void {
        const head_p = s.word(ring.head);
        while (true) {
            const head = @atomicLoad(u32, head_p, .acquire);
            if (head != @atomicLoad(u32, s.word(ring.tail), .monotonic)) return;
            const now = nowNs();
            if (now >= deadline) return error.Timeout;
            const left = deadline - now;
            const ts: linux.timespec = .{
                .sec = @intCast(left / std.time.ns_per_s),
                .nsec = @intCast(left % std.time.ns_per_s),
            };
            // SUCCESS, AGAIN (head moved), INTR and TIMEDOUT all lead to the re-check above.
            _ = linux.futex_4arg(head_p, .{ .cmd = .WAIT, .private = false }, head, &ts);
        }
    }
};

// ---- connection -------------------------------------------------------------

/// A live daemon connection: the control socket (kept open; closing it tells the daemon
/// to drop the rings) and the mapped ring pair.
pub const Conn = struct {
    fd: linux.fd_t,
    shm: Shm,

    pub fn close(conn: *Conn) void {
        _ = linux.munmap(conn.shm.mem.ptr, conn.shm.mem.len);
        _ = linux.close(conn.fd);
    }
};

fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

/// Non-blocking connect to `path`. ENOENT/ECONNREFUSED: no daemon. EAGAIN: the
/// listen backlog is full, i.e. a hung daemon.
pub fn connectNonBlocking(path: *const SocketPath) Error!linux.fd_t {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Io;
    const fd: linux.fd_t = @intCast(rc);
    errdefer closeFd(fd);
    var addr: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path.slice());
    return switch (linux.errno(linux.connect(fd, &addr, @sizeOf(linux.sockaddr.un)))) {
        .SUCCESS => fd,
        .NOENT, .CONNREFUSED, .NOTDIR => error.DaemonAbsent,
        .AGAIN => error.Timeout,
        else => error.Io,
    };
}

/// struct ucred from <sys/socket.h> (not in std.os.linux).
const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };

/// The peer of a connected AF_UNIX socket must run as our own effective uid: a socket
/// path under $HOME or $GUNGNIR_SOCKET may be reachable by others, and a foreign listener
/// must never get to hand us shared memory.
fn checkPeer(fd: linux.fd_t) Error!void {
    var cred: Ucred = .{ .pid = 0, .uid = std.math.maxInt(u32), .gid = std.math.maxInt(u32) };
    var len: linux.socklen_t = @sizeOf(Ucred);
    const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.PEERCRED, @ptrCast(&cred), &len);
    if (linux.errno(rc) != .SUCCESS or len != @sizeOf(Ucred)) return error.Io;
    if (cred.uid != linux.geteuid()) return error.ForeignPeer;
}

fn pollIn(fd: linux.fd_t, deadline: u64) Error!void {
    while (true) {
        const ms = remainingMs(deadline);
        if (ms == 0) return error.Timeout;
        var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN }};
        const rc = linux.poll(&pfd, 1, ms);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc > 0) return,
            .INTR => {},
            else => return error.Io,
        }
    }
}

/// Control buffer for one SCM_RIGHTS fd: cmsghdr (16 bytes) + int, padded to 8.
const cmsg_space = 24;
const cmsg_len_one_fd = @sizeOf(linux.cmsghdr) + @sizeOf(linux.fd_t);

/// Receive the 16-byte reply and the memfd passed with it.
fn recvReply(fd: linux.fd_t, deadline: u64) Error!struct { frame: Frame, memfd: ?linux.fd_t } {
    try pollIn(fd, deadline);
    var data: [frame_len]u8 = undefined;
    var cbuf: [cmsg_space]u8 align(8) = @splat(0);
    var iov = [1]std.posix.iovec{.{ .base = &data, .len = data.len }};
    var msg: linux.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &cbuf,
        .controllen = cbuf.len,
        .flags = 0,
    };
    const rc = linux.recvmsg(fd, &msg, linux.MSG.CMSG_CLOEXEC | linux.MSG.DONTWAIT);
    if (linux.errno(rc) != .SUCCESS) return error.Io;
    var memfd: ?linux.fd_t = null;
    const hdr: *const linux.cmsghdr = @ptrCast(&cbuf);
    if (msg.controllen >= cmsg_len_one_fd and hdr.level == linux.SOL.SOCKET and hdr.type == linux.SCM.RIGHTS) {
        if (hdr.len != cmsg_len_one_fd) {
            // More than one fd: close every one we were handed, then fail.
            const end = @min(hdr.len, cbuf.len);
            var off: usize = @sizeOf(linux.cmsghdr);
            while (off + 4 <= end) : (off += 4) closeFd(std.mem.readInt(i32, cbuf[off..][0..4], .little));
            return error.Protocol;
        }
        memfd = std.mem.readInt(i32, cbuf[@sizeOf(linux.cmsghdr)..][0..4], .little);
    }
    errdefer if (memfd) |m| closeFd(m);
    if (msg.flags & linux.MSG.CTRUNC != 0) return error.Protocol;
    if (rc == 0) return error.DaemonAbsent; // daemon closed the socket
    if (rc != frame_len) return error.Protocol;
    return .{ .frame = Frame.decode(&data), .memfd = memfd };
}

/// Validate a received memfd (size, seals) and map it shared.
fn mapShm(memfd: linux.fd_t) Error!Shm {
    if (linux.lseek(memfd, 0, linux.SEEK.END) != shm_size) return error.BadShm;
    const seals = linux.fcntl(memfd, linux.F.GET_SEALS, 0);
    if (linux.errno(seals) != .SUCCESS) return error.BadShm;
    const need: usize = linux.F.SEAL_SHRINK | linux.F.SEAL_GROW;
    if (seals & need != need) return error.BadShm; // a shrinkable mapping could SIGBUS the host app
    const addr = linux.mmap(null, shm_size, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, memfd, 0);
    if (linux.errno(addr) != .SUCCESS) return error.BadShm;
    const ptr: [*]align(4096) u8 = @ptrFromInt(addr);
    const shm: Shm = .{ .mem = ptr[0..shm_size] };
    if (!shm.headerOk()) {
        _ = linux.munmap(ptr, shm_size);
        return error.BadShm;
    }
    return shm;
}

/// The error for a reply that came without a ring: a reject frame (a daemon speaking
/// another protocol version says so with status_bad_version), or garbage.
fn refusal(f: Frame) Error {
    if (f.magic != magic or f.kind != kind_reject) return error.Protocol;
    return if (f.status == status_bad_version) error.VersionMismatch else error.Rejected;
}

/// Connect, exchange hellos, map the ring pair and round-trip one ping, all within
/// `timeout_ms`. Never blocks past the deadline; run it off the GIO calling thread.
pub fn connectAndPing(path: *const SocketPath, timeout_ms: u32) Error!Conn {
    const deadline = nowNs() + @as(u64, timeout_ms) * std.time.ns_per_ms;
    const fd = try connectNonBlocking(path);
    errdefer closeFd(fd);
    try checkPeer(fd);

    const hello = (Frame{ .kind = kind_hello }).encode();
    const sent = linux.sendto(fd, &hello, hello.len, linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != hello.len) return error.Io;

    const reply = try recvReply(fd, deadline);
    const memfd = reply.memfd orelse return refusal(reply.frame);
    defer closeFd(memfd); // the mapping keeps the memory alive
    const f = reply.frame;
    if (f.magic != magic or f.version != version or f.kind != kind_ack or f.status != 0 or f.shm_size != shm_size)
        return error.Protocol;

    var conn: Conn = .{ .fd = fd, .shm = try mapShm(memfd) };
    errdefer _ = linux.munmap(conn.shm.mem.ptr, conn.shm.mem.len);

    const seq: u64 = 1;
    try conn.shm.push(ring_c2d, msg_ping, seq, "ping");
    try conn.shm.waitReadable(ring_d2c, deadline);
    const pong = (try conn.shm.pop(ring_d2c)) orelse return error.Protocol;
    if (pong.kind != msg_pong or pong.seq != seq or !std.mem.eql(u8, pong.payload(), "ping")) return error.Protocol;
    return conn;
}

// ---- tests ------------------------------------------------------------------

test "frame layout matches the daemon" {
    const b = (Frame{ .kind = kind_ack, .status = 3, .shm_size = shm_size }).encode();
    try std.testing.expectEqualStrings("GNGR", b[0..4]);
    const f = Frame.decode(&b);
    try std.testing.expectEqual(kind_ack, f.kind);
    try std.testing.expectEqual(@as(u32, 3), f.status);
    try std.testing.expectEqual(@as(u32, 4096 + 2 * 32 * 4096), f.shm_size);
}

test "a version mismatch is reported as such" {
    try std.testing.expectEqual(error.VersionMismatch, refusal(.{ .kind = kind_reject, .status = status_bad_version }));
    try std.testing.expectEqual(error.Rejected, refusal(.{ .kind = kind_reject, .status = 1 }));
    try std.testing.expectEqual(error.Protocol, refusal(.{ .kind = kind_ack }));
    try std.testing.expectEqual(error.Protocol, refusal(.{ .magic = 0, .kind = kind_reject }));
}

test "a full-size payload round-trips and a lying length is refused" {
    var buf: [shm_size]u8 align(4096) = undefined;
    const shm: Shm = .{ .mem = &buf };
    shm.initHeader();
    var big: [payload_max]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i *% 31);
    try shm.push(ring_c2d, 18, 7, &big);
    const m = (try shm.pop(ring_c2d)).?;
    try std.testing.expectEqualSlices(u8, &big, m.payload());
    try shm.push(ring_c2d, 18, 8, "x");
    // Corrupt the len field of the queued slot: the consumer must refuse it.
    const off = ring_c2d.slots + 1 * slot_size + 4;
    @atomicStore(u32, @as(*u32, @ptrCast(@alignCast(buf[off..][0..4]))), payload_max + 1, .monotonic);
    try std.testing.expectError(error.Protocol, shm.pop(ring_c2d));
}

test "socket path precedence and limits" {
    var p = try resolveSocketPath("/o/g.sock", "/run/user/1", "/h");
    try std.testing.expectEqualStrings("/o/g.sock", p.slice());
    p = try resolveSocketPath("", "/run/user/1", "/h");
    try std.testing.expectEqualStrings("/run/user/1/gungnir/gungnird.sock", p.slice());
    p = try resolveSocketPath(null, "relative", "/h");
    try std.testing.expectEqualStrings("/h/.cache/gungnir/gungnird.sock", p.slice());
    try std.testing.expectError(error.NoSocketPath, resolveSocketPath(null, null, ""));
    var long: [121]u8 = @splat('a');
    long[0] = '/';
    try std.testing.expectError(error.SocketPathTooLong, resolveSocketPath(&long, null, null));
}

test "ring fills, wraps and rejects corrupt indices" {
    var buf: [shm_size]u8 align(4096) = undefined;
    const shm: Shm = .{ .mem = &buf };
    shm.initHeader();
    try std.testing.expect(shm.headerOk());
    for (0..3) |round| {
        for (0..slot_count) |i| try shm.push(ring_c2d, msg_ping, round * 100 + i, "x");
        try std.testing.expectError(error.RingFull, shm.push(ring_c2d, msg_ping, 0, "x"));
        for (0..slot_count) |i| {
            const m = (try shm.pop(ring_c2d)).?;
            try std.testing.expectEqual(@as(u64, round * 100 + i), m.seq);
            try std.testing.expectEqualStrings("x", m.payload());
        }
        try std.testing.expect((try shm.pop(ring_c2d)) == null);
    }
    const too_big: [payload_max + 1]u8 = @splat(0);
    try std.testing.expectError(error.Protocol, shm.push(ring_c2d, msg_ping, 0, &too_big));
    @atomicStore(u32, shm.word(ring_d2c.head), 1000, .release);
    try std.testing.expectError(error.RingCorrupt, shm.pop(ring_d2c));
}

test "ring indices wrap past maxInt(u32)" {
    var buf: [shm_size]u8 align(4096) = undefined;
    const shm: Shm = .{ .mem = &buf };
    shm.initHeader();
    const start: u32 = std.math.maxInt(u32) - 20;
    @atomicStore(u32, shm.word(ring_c2d.head), start, .release);
    @atomicStore(u32, shm.word(ring_c2d.tail), start, .release);
    for (0..3 * slot_count) |i| {
        var p: [8]u8 = undefined;
        std.mem.writeInt(u64, &p, i, .little);
        try shm.push(ring_c2d, msg_ping, i, &p);
        const m = (try shm.pop(ring_c2d)).?;
        try std.testing.expectEqual(@as(u64, i), m.seq);
        try std.testing.expectEqualSlices(u8, &p, m.payload());
    }
    for (0..slot_count) |i| try shm.push(ring_c2d, msg_ping, i, "f");
    try std.testing.expectError(error.RingFull, shm.push(ring_c2d, msg_ping, 0, "x"));
    try std.testing.expect(@atomicLoad(u32, shm.word(ring_c2d.head), .acquire) < start);
}

test "peer credentials: our own uid passes" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);
    try checkPeer(fds[0]);
}

test "empty ring wait is bounded" {
    var buf: [shm_size]u8 align(4096) = undefined;
    const shm: Shm = .{ .mem = &buf };
    shm.initHeader();
    const t0 = nowNs();
    try std.testing.expectError(error.Timeout, shm.waitReadable(ring_d2c, t0 + 20 * std.time.ns_per_ms));
    try std.testing.expect(nowNs() - t0 < 1000 * std.time.ns_per_ms);
}

test "missing daemon fails fast" {
    const p = try resolveSocketPath("/nonexistent-gungnir-dir/gungnird.sock", null, null);
    const t0 = nowNs();
    try std.testing.expectError(error.DaemonAbsent, connectAndPing(&p, 500));
    try std.testing.expect(nowNs() - t0 < 100 * std.time.ns_per_ms);
}
