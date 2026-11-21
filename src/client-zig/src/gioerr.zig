//! The one map from a failed gungnird call to a GIOErrorEnum code. Every service reports
//! through it (metadata in gmeta.zig, file operations in fileop.zig, trash and recent in
//! vfsfile.zig); each keeps only its own message text. A reply status reaches it as the
//! error `rpc.statusError` gives, so a status means the same GIO error whoever sent it.
const std = @import("std");
const c = @import("c");
const rpc = @import("rpc.zig");
const proto = @import("proto.zig");

/// The GIOErrorEnum code for `err`. `errno` is the daemon's for `error.DaemonOs`
/// (`proto.osErrno` of the reply body), ignored otherwise.
pub fn code(err: anyerror, errno: i32) c_int {
    return switch (err) {
        // No daemon, or none that speaks this: GIO falls back where it can.
        error.Unavailable, error.DaemonAbsent, error.NoSocketPath, error.VersionMismatch, error.Rejected, error.ForeignPeer, error.Unsupported => c.G_IO_ERROR_NOT_SUPPORTED,
        error.Busy, error.RingFull => c.G_IO_ERROR_BUSY,
        // A mount inside an item: retryable once it is unmounted, like busy.
        error.MountInside => c.G_IO_ERROR_BUSY,
        error.Timeout, error.SuspectMount, error.MountHung => c.G_IO_ERROR_TIMED_OUT,
        error.NotFound, error.NoSuchFile => c.G_IO_ERROR_NOT_FOUND,
        error.PathTooLong => c.G_IO_ERROR_FILENAME_TOO_LONG,
        error.BadRequest, error.KeyTooLong, error.ValueTooLarge, error.BadUtf8, error.WrongType => c.G_IO_ERROR_INVALID_ARGUMENT,
        error.TooManyKeys => c.G_IO_ERROR_NO_SPACE,
        error.Cancelled => c.G_IO_ERROR_CANCELLED,
        error.WouldRecurse => c.G_IO_ERROR_WOULD_RECURSE,
        error.NotEmpty => c.G_IO_ERROR_NOT_EMPTY,
        error.DaemonOs => @intCast(c.g_io_error_from_errno(errno)),
        else => c.G_IO_ERROR_FAILED,
    };
}

/// [`code`] for a raw reply status (an op's done carries one, not a reply).
pub fn ofStatus(status: u32, errno: i32) c_int {
    return code(rpc.statusError(status), errno);
}

test "every status maps to the GIO error it means" {
    const t = std.testing;
    const E = std.os.linux.E;
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_FOUND), ofStatus(proto.st_not_found, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_BUSY), ofStatus(proto.st_busy, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_TIMED_OUT), ofStatus(proto.st_timeout, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_TIMED_OUT), ofStatus(proto.st_suspect_mount, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_FOUND), ofStatus(proto.st_no_such_file, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_INVALID_ARGUMENT), ofStatus(proto.st_bad_request, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_INVALID_ARGUMENT), ofStatus(proto.st_key_too_long, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_INVALID_ARGUMENT), ofStatus(proto.st_value_too_large, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_NO_SPACE), ofStatus(proto.st_too_many_keys, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_INVALID_ARGUMENT), ofStatus(proto.st_bad_utf8, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_FAILED), ofStatus(proto.st_io_error, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_FAILED), ofStatus(proto.st_db_error, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_SUPPORTED), ofStatus(proto.st_unsupported, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_CANCELLED), ofStatus(proto.st_cancelled, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_EXISTS), ofStatus(proto.st_os_error, @backingInt(E.EXIST)));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_WOULD_RECURSE), ofStatus(proto.st_would_recurse, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_BUSY), ofStatus(proto.st_mount_inside, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_EMPTY), ofStatus(proto.st_not_empty, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_FAILED), ofStatus(99, 0));
}

test "transport failures say the daemon is not there" {
    const t = std.testing;
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_SUPPORTED), code(error.DaemonAbsent, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_SUPPORTED), code(error.Unavailable, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_BUSY), code(error.RingFull, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_TIMED_OUT), code(error.MountHung, 0));
    try t.expectEqual(@as(c_int, c.G_IO_ERROR_FAILED), code(error.Protocol, 0));
}
