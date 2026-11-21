//! The wire protocol's numbers (protocol v2): the handshake, the shared-memory layout,
//! every slot kind and the one status space every reply shares. The modules that speak
//! a part of it (ipc, md, health, fileop, vfsfile) take their values from here.
//!
//! The values are checked against `protocol/wire.txt` at the repo root, which the daemon's
//! `proto.rs` is checked against too: a value that drifts on either side fails that side's
//! tests.
const std = @import("std");

// Handshake frames on the control socket.
/// "GNGR" read as a little-endian u32.
pub const magic: u32 = 0x5247_4E47;
pub const version: u16 = 2;
pub const frame_len = 16;
pub const kind_hello: u16 = 1;
pub const kind_ack: u16 = 2;
pub const kind_reject: u16 = 3;
pub const status_ok: u32 = 0;
pub const status_bad_magic: u32 = 1;
pub const status_bad_version: u32 = 2;
pub const status_bad_kind: u32 = 3;

// Shared memory.
pub const slot_count: u32 = 32;
pub const slot_size: usize = 4096;
/// kind u32 | len u32 | seq u64.
pub const slot_header: usize = 16;
pub const payload_max: usize = slot_size - slot_header;
pub const shm_size: usize = 4096 + 2 * slot_count * slot_size;

// Slot kinds.
pub const msg_ping: u32 = 1;
pub const msg_pong: u32 = 2;
pub const msg_md_identify: u32 = 16;
pub const msg_md_get: u32 = 17;
pub const msg_md_set: u32 = 18;
pub const msg_md_unset: u32 = 19;
pub const msg_md_list: u32 = 20;
pub const msg_md_removed: u32 = 21;
pub const msg_md_moved: u32 = 22;
pub const msg_health_query: u32 = 23;
pub const msg_health_subscribe: u32 = 24;
pub const msg_op_start: u32 = 25;
pub const msg_op_cancel: u32 = 26;
/// The reply to every request: `status u32 | body`.
pub const msg_reply: u32 = 32;
/// Unsolicited daemon -> client slot: never a reply.
pub const msg_health_event: u32 = 33;
pub const msg_op_progress: u32 = 34;
pub const msg_op_done: u32 = 35;
pub const msg_vfs_list: u32 = 40;
pub const msg_vfs_delete: u32 = 41;
pub const msg_vfs_restore: u32 = 42;
pub const msg_trash_empty: u32 = 43;
/// Same seq as a request still under way, no payload: the daemon is alive and working.
pub const msg_vfs_beat: u32 = 44;
pub const msg_vfs_stat: u32 = 45;
pub const msg_vfs_children: u32 = 46;
pub const msg_vfs_stamp: u32 = 47;

// Statuses: the first u32 of every reply body, and of an op's done.
pub const st_ok: u32 = 0;
pub const st_not_found: u32 = 1;
pub const st_busy: u32 = 2;
pub const st_timeout: u32 = 3;
pub const st_suspect_mount: u32 = 4;
pub const st_no_such_file: u32 = 5;
pub const st_bad_request: u32 = 6;
pub const st_key_too_long: u32 = 7;
pub const st_value_too_large: u32 = 8;
pub const st_too_many_keys: u32 = 9;
pub const st_bad_utf8: u32 = 10;
pub const st_io_error: u32 = 11;
pub const st_db_error: u32 = 12;
pub const st_unsupported: u32 = 13;
pub const st_cancelled: u32 = 14;
/// A system error: the body (after the status) starts with `errno i32`.
pub const st_os_error: u32 = 15;
pub const st_would_recurse: u32 = 16;
pub const st_mount_inside: u32 = 17;
pub const st_not_empty: u32 = 18;

// Schemes of the trash and recent kinds.
pub const scheme_trash: u8 = 0;
pub const scheme_recent: u8 = 1;

// What a listed trash or recent item is (the `kind u8` of a list entry).
pub const item_file: u8 = 1;
pub const item_dir: u8 = 2;
pub const item_symlink: u8 = 3;
pub const item_special: u8 = 4;

/// The errno of an `st_os_error` reply body (after its status), EIO when it is missing.
pub fn osErrno(body: []const u8) i32 {
    if (body.len < 4) return 5;
    return std.mem.readInt(i32, body[0..4], .little);
}

const wire = @embedFile("wire.txt");

/// Every value this side defines, by its name in the table.
const ours = [_]struct { group: []const u8, name: []const u8, value: u64 }{
    .{ .group = "handshake", .name = "magic", .value = magic },
    .{ .group = "handshake", .name = "version", .value = version },
    .{ .group = "handshake", .name = "frame_len", .value = frame_len },
    .{ .group = "handshake", .name = "kind_hello", .value = kind_hello },
    .{ .group = "handshake", .name = "kind_ack", .value = kind_ack },
    .{ .group = "handshake", .name = "kind_reject", .value = kind_reject },
    .{ .group = "handshake", .name = "status_ok", .value = status_ok },
    .{ .group = "handshake", .name = "status_bad_magic", .value = status_bad_magic },
    .{ .group = "handshake", .name = "status_bad_version", .value = status_bad_version },
    .{ .group = "handshake", .name = "status_bad_kind", .value = status_bad_kind },
    .{ .group = "shm", .name = "slot_count", .value = slot_count },
    .{ .group = "shm", .name = "slot_size", .value = slot_size },
    .{ .group = "shm", .name = "slot_header", .value = slot_header },
    .{ .group = "shm", .name = "payload_max", .value = payload_max },
    .{ .group = "shm", .name = "shm_size", .value = shm_size },
    .{ .group = "kind", .name = "ping", .value = msg_ping },
    .{ .group = "kind", .name = "pong", .value = msg_pong },
    .{ .group = "kind", .name = "md_identify", .value = msg_md_identify },
    .{ .group = "kind", .name = "md_get", .value = msg_md_get },
    .{ .group = "kind", .name = "md_set", .value = msg_md_set },
    .{ .group = "kind", .name = "md_unset", .value = msg_md_unset },
    .{ .group = "kind", .name = "md_list", .value = msg_md_list },
    .{ .group = "kind", .name = "md_removed", .value = msg_md_removed },
    .{ .group = "kind", .name = "md_moved", .value = msg_md_moved },
    .{ .group = "kind", .name = "health_query", .value = msg_health_query },
    .{ .group = "kind", .name = "health_subscribe", .value = msg_health_subscribe },
    .{ .group = "kind", .name = "op_start", .value = msg_op_start },
    .{ .group = "kind", .name = "op_cancel", .value = msg_op_cancel },
    .{ .group = "kind", .name = "reply", .value = msg_reply },
    .{ .group = "kind", .name = "health_event", .value = msg_health_event },
    .{ .group = "kind", .name = "op_progress", .value = msg_op_progress },
    .{ .group = "kind", .name = "op_done", .value = msg_op_done },
    .{ .group = "kind", .name = "vfs_list", .value = msg_vfs_list },
    .{ .group = "kind", .name = "vfs_delete", .value = msg_vfs_delete },
    .{ .group = "kind", .name = "vfs_restore", .value = msg_vfs_restore },
    .{ .group = "kind", .name = "trash_empty", .value = msg_trash_empty },
    .{ .group = "kind", .name = "vfs_beat", .value = msg_vfs_beat },
    .{ .group = "kind", .name = "vfs_stat", .value = msg_vfs_stat },
    .{ .group = "kind", .name = "vfs_children", .value = msg_vfs_children },
    .{ .group = "kind", .name = "vfs_stamp", .value = msg_vfs_stamp },
    .{ .group = "status", .name = "ok", .value = st_ok },
    .{ .group = "status", .name = "not_found", .value = st_not_found },
    .{ .group = "status", .name = "busy", .value = st_busy },
    .{ .group = "status", .name = "timeout", .value = st_timeout },
    .{ .group = "status", .name = "suspect_mount", .value = st_suspect_mount },
    .{ .group = "status", .name = "no_such_file", .value = st_no_such_file },
    .{ .group = "status", .name = "bad_request", .value = st_bad_request },
    .{ .group = "status", .name = "key_too_long", .value = st_key_too_long },
    .{ .group = "status", .name = "value_too_large", .value = st_value_too_large },
    .{ .group = "status", .name = "too_many_keys", .value = st_too_many_keys },
    .{ .group = "status", .name = "bad_utf8", .value = st_bad_utf8 },
    .{ .group = "status", .name = "io_error", .value = st_io_error },
    .{ .group = "status", .name = "db_error", .value = st_db_error },
    .{ .group = "status", .name = "unsupported", .value = st_unsupported },
    .{ .group = "status", .name = "cancelled", .value = st_cancelled },
    .{ .group = "status", .name = "os_error", .value = st_os_error },
    .{ .group = "status", .name = "would_recurse", .value = st_would_recurse },
    .{ .group = "status", .name = "mount_inside", .value = st_mount_inside },
    .{ .group = "status", .name = "not_empty", .value = st_not_empty },
    .{ .group = "scheme", .name = "trash", .value = scheme_trash },
    .{ .group = "scheme", .name = "recent", .value = scheme_recent },
    .{ .group = "item", .name = "file", .value = item_file },
    .{ .group = "item", .name = "dir", .value = item_dir },
    .{ .group = "item", .name = "symlink", .value = item_symlink },
    .{ .group = "item", .name = "special", .value = item_special },
};

const Line = struct { group: []const u8, name: []const u8, value: []const u8 };

fn nextLine(it: *std.mem.SplitIterator(u8, .scalar)) ?Line {
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const l: Line = .{ .group = f.next() orelse "", .name = f.next() orelse "", .value = f.next() orelse "" };
        return l;
    }
    return null;
}

fn parseValue(s: []const u8) !u64 {
    if (std.mem.startsWith(u8, s, "0x")) return std.fmt.parseInt(u64, s[2..], 16);
    return std.fmt.parseInt(u64, s, 10);
}

test "every value matches the shared table" {
    var it = std.mem.splitScalar(u8, wire, '\n');
    var lines: usize = 0;
    while (nextLine(&it)) |l| {
        if (std.mem.eql(u8, l.group, "frame")) continue;
        lines += 1;
        const mine = for (ours) |o| {
            if (std.mem.eql(u8, o.group, l.group) and std.mem.eql(u8, o.name, l.name)) break o;
        } else {
            std.debug.print("protocol/wire.txt has {s} {s}, which proto.zig lacks\n", .{ l.group, l.name });
            return error.MissingName;
        };
        const theirs = try parseValue(l.value);
        if (theirs != mine.value) {
            std.debug.print("{s} {s}: this side has {d}, protocol/wire.txt {d}\n", .{ l.group, l.name, mine.value, theirs });
            return error.Drift;
        }
    }
    // Every name here was found above at most once; equal counts mean none is missing there.
    try std.testing.expectEqual(ours.len, lines);
}

test "the hello frame encodes as the shared table says" {
    const ipc = @import("ipc.zig");
    var it = std.mem.splitScalar(u8, wire, '\n');
    var checked: usize = 0;
    while (nextLine(&it)) |l| {
        if (!std.mem.eql(u8, l.group, "frame")) continue;
        var want: [frame_len]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, l.value);
        const f: ipc.Frame = if (std.mem.eql(u8, l.name, "hello"))
            .{ .kind = kind_hello }
        else if (std.mem.eql(u8, l.name, "ack"))
            .{ .kind = kind_ack, .shm_size = shm_size }
        else
            return error.UncheckedFrame;
        try std.testing.expectEqualSlices(u8, &want, &f.encode());
        checked += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), checked);
}

test "an os error body gives its errno" {
    try std.testing.expectEqual(@as(i32, -2), osErrno(&.{ 0xfe, 0xff, 0xff, 0xff }));
    try std.testing.expectEqual(@as(i32, 5), osErrno(&.{1}));
}
