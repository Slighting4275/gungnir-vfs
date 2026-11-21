//! One request and its reply over a connection's rings: the client every request/reply
//! service speaks through (metadata in md.zig, health.zig, the trash and recent requests
//! in vfsfile.zig, the shared link). It owns the reply envelope (`status u32 | body`, kind
//! `proto.msg_reply`) and turns every status into an error (`statusError`). File
//! operations (fileop.zig) are the one exception: an op streams progress and ends with a
//! done on its own connection, so fileop reads those slots itself and maps the done's
//! status through `gioerr.ofStatus`. Every wait has a deadline, and a stopped daemon
//! (closed control socket) is noticed within `liveness_slice_ms`.
//!
//! A Client is not thread-safe: one request at a time per connection.
const std = @import("std");
const ipc = @import("ipc.zig");
const proto = @import("proto.zig");

/// Every way a request can fail: the transport's errors, and one error per reply status.
pub const Error = ipc.Error || std.mem.Allocator.Error || error{
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
/// service sent it.
pub fn statusError(st: u32) Error {
    return switch (st) {
        proto.st_not_found => error.NotFound,
        proto.st_busy => error.Busy,
        proto.st_timeout => error.Timeout,
        proto.st_suspect_mount => error.SuspectMount,
        proto.st_no_such_file => error.NoSuchFile,
        proto.st_bad_request => error.BadRequest,
        proto.st_key_too_long => error.KeyTooLong,
        proto.st_value_too_large => error.ValueTooLarge,
        proto.st_too_many_keys => error.TooManyKeys,
        proto.st_bad_utf8 => error.BadUtf8,
        proto.st_io_error => error.DaemonIo,
        proto.st_db_error => error.DaemonDb,
        proto.st_unsupported => error.Unsupported,
        proto.st_cancelled => error.Cancelled,
        proto.st_os_error => error.DaemonOs,
        proto.st_would_recurse => error.WouldRecurse,
        proto.st_mount_inside => error.MountInside,
        proto.st_not_empty => error.NotEmpty,
        else => error.Protocol,
    };
}

/// While waiting for a reply, the control socket is re-checked this often, so a daemon
/// that stops mid-request costs at most this long, not the whole deadline.
pub const liveness_slice_ms: u64 = 20;

pub fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.errno(std.os.linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

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
    pub fn request(c: *Client, kind: u32, payload: []const u8, reply: *ipc.Msg) Error![]const u8 {
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
                if (m.kind == proto.msg_health_event) {
                    if (c.on_event) |f| f(m.payload());
                    continue;
                }
                if (m.seq != seq) continue;
                // Alive and working: the silence bound starts again.
                if (c.beat_kind != 0 and m.kind == c.beat_kind) {
                    deadline = nowNs() + @as(u64, c.timeout_ms) * std.time.ns_per_ms;
                    continue;
                }
                if (m.kind != proto.msg_reply) return error.Protocol;
                reply.* = m;
                const p = reply.payload();
                if (p.len < 4) return error.Protocol;
                const st = std.mem.readInt(u32, p[0..4], .little);
                if (st != proto.st_ok) return statusError(st);
                return p[4..];
            }
        }
    }
};

test "every status is an error of its own" {
    const t = std.testing;
    try t.expectEqual(error.NotEmpty, statusError(proto.st_not_empty));
    try t.expectEqual(error.DaemonOs, statusError(proto.st_os_error));
    try t.expectEqual(error.Cancelled, statusError(proto.st_cancelled));
    try t.expectEqual(error.Protocol, statusError(99));
}
