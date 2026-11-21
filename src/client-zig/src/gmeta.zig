//! GIO metadata::* attributes for local files (milestone 6), served by gungnird.
//!
//! GLib's GLocalFile calls the default VFS's private GVfsClass hooks: local_file_add_info
//! (from every query_info / enumerate on a local path), local_file_set_attributes (for
//! attributes GLib does not handle itself), add_writable_namespaces, local_file_removed and
//! local_file_moved (after a delete, trash or rename succeeded). gvfs's GDaemonVfs serves
//! its metadata through the same hooks. GungnirVfs (main.zig) points them here.
//!
//! Non-blocking rule: every hook finishes by a deadline (query_budget_ms for reads,
//! update_budget_ms for writes), lock and connection waits included. When the daemon is
//! unavailable, busy or slow, a query just carries no metadata attributes and a set fails
//! with G_IO_ERROR_NOT_SUPPORTED / BUSY / TIMED_OUT. Hooks run on whatever thread made the
//! GIO call (query_info_async runs query_info on a GTask worker); link.zig serialises them.
//! On the UI thread every hook gets link.ui_budget_ms instead and skips a daemon that just
//! timed out (see link.zig): a query there carries no metadata rather than stall the UI.
//!
//! Hung mounts (milestone 7): before any of that, a path on a mount gungnird reported
//! hung or gone (health.zig, a lookup in memory) fails at once: no metadata in a query,
//! G_IO_ERROR_TIMED_OUT for a set, no removed/moved notification. Neither the daemon's
//! resolver nor the path itself is touched.
const std = @import("std");
const c = @import("c");
const md = @import("md.zig");
const gioerr = @import("gioerr.zig");
const link = @import("link.zig");
const health = @import("health.zig");
const Allocator = std.mem.Allocator;

pub const namespace = "metadata";
const prefix = namespace ++ "::";

/// Whole budget of one query (identify, list, every get).
pub const query_budget_ms: u64 = 200;
/// Whole budget of one set_attribute(s), removed or moved notification.
pub const update_budget_ms: u64 = 300;

pub const Error = md.Error || link.AcquireError || error{ WrongType, MountHung };

fn errOf(r: anytype) ?anyerror {
    return if (r) |_| null else |err| err;
}

/// The key of a "metadata::<key>" attribute name, null for other names or invalid keys.
pub fn keyOf(attribute: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, attribute, prefix)) return null;
    const key = attribute[prefix.len..];
    md.validKey(key) catch return null;
    return key;
}

fn reason(err: Error) [*:0]const u8 {
    return switch (err) {
        error.Unavailable, error.DaemonAbsent => "the metadata daemon is not available",
        error.Busy, error.RingFull => "the metadata daemon is busy",
        error.Timeout => "the metadata daemon did not answer in time",
        error.SuspectMount => "the file's mount is not responding",
        error.MountHung => "the file's mount is hung or gone (reported by the gungnird mount health monitor)",
        error.WrongType => "values must be string or list of strings",
        else => @errorName(err).ptr,
    };
}

// ---- query --------------------------------------------------------------------

const Entry = struct { key: []u8, value: md.Value };

fn freeEntries(gpa: Allocator, list: *std.ArrayList(Entry)) void {
    for (list.items) |e| {
        gpa.free(e.key);
        e.value.deinit(gpa);
    }
    list.deinit(gpa);
}

/// Fetch the wanted keys (all of them if `wanted` is null) of the file at `path`.
fn fetch(gpa: Allocator, cl: *md.Client, path: []const u8, wanted: ?[]const []const u8) Error!std.ArrayList(Entry) {
    var out: std.ArrayList(Entry) = .empty;
    errdefer freeEntries(gpa, &out);
    const id = try cl.identify(path);
    var listed: ?[][]u8 = null;
    defer if (listed) |l| md.freeKeys(gpa, l);
    const keys: []const []const u8 = if (wanted) |w| w else blk: {
        listed = try cl.listKeys(gpa, &id);
        break :blk listed.?;
    };
    try out.ensureTotalCapacity(gpa, keys.len);
    for (keys) |k| {
        // Unset between the list and the get, or simply not set: no attribute.
        const v = (try cl.get(gpa, &id, k)) orelse continue;
        const key = gpa.dupe(u8, k) catch |err| {
            v.deinit(gpa);
            return err;
        };
        out.appendAssumeCapacity(.{ .key = key, .value = v });
    }
    return out;
}

/// One attribute into `info` (GLib copies everything it is given).
fn putAttribute(gpa: Allocator, info: *c.GFileInfo, e: Entry) Allocator.Error!void {
    const name = try std.mem.concatWithSentinel(gpa, u8, &.{ prefix, e.key }, 0);
    defer gpa.free(name);
    switch (e.value) {
        .string => |s| {
            const z = try std.mem.concatWithSentinel(gpa, u8, &.{s}, 0);
            defer gpa.free(z);
            c.g_file_info_set_attribute_string(info, name.ptr, z.ptr);
        },
        .stringv => |list| {
            const v = try gpa.alloc([*c]u8, list.len + 1);
            defer gpa.free(v);
            var made: usize = 0;
            defer for (v[0..made]) |p| gpa.free(std.mem.span(@as([*:0]u8, @ptrCast(p))));
            for (list) |s| {
                const z = try std.mem.concatWithSentinel(gpa, u8, &.{s}, 0);
                v[made] = z.ptr;
                made += 1;
            }
            v[list.len] = null;
            c.g_file_info_set_attribute_stringv(info, name.ptr, v.ptr);
        },
    }
}

/// local_file_add_info: add the matcher's metadata::* attributes of `filename` to
/// `info`, all or none. Any failure (no daemon, busy, deadline) leaves them out.
pub fn addInfo(gpa: Allocator, filename: [*c]const u8, matcher: ?*c.GFileAttributeMatcher, info: ?*c.GFileInfo) void {
    const m = matcher orelse return;
    const inf = info orelse return;
    if (filename == null) return;
    var wanted: std.ArrayList([]const u8) = .empty;
    defer wanted.deinit(gpa);
    const all = c.g_file_attribute_matcher_enumerate_namespace(m, namespace) != 0;
    if (!all) {
        // Specific keys ("metadata::a,metadata::b"). The names are GLib's interned strings.
        while (true) {
            const a = c.g_file_attribute_matcher_enumerate_next(m);
            if (a == null) break;
            const key = keyOf(std.mem.span(a)) orelse continue;
            wanted.append(gpa, key) catch return;
        }
        if (wanted.items.len == 0) return;
    }
    if (health.blocks(std.mem.span(filename))) {
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: no metadata for %s: its mount is hung", filename);
        return;
    }
    var entries = query(gpa, std.mem.span(filename), if (all) null else wanted.items, link.budget(query_budget_ms)) catch |err| {
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: no metadata for %s: %s", filename, @errorName(err).ptr);
        return;
    };
    defer freeEntries(gpa, &entries);
    for (entries.items) |e| putAttribute(gpa, inf, e) catch return;
}

fn query(gpa: Allocator, path: []const u8, wanted: ?[]const []const u8, b: link.Budget) Error!std.ArrayList(Entry) {
    const cl = try link.acquire(b);
    const r = fetch(gpa, cl, path, wanted);
    link.release(cl, errOf(r));
    return r;
}

// ---- set ----------------------------------------------------------------------

fn setError(err_out: [*c][*c]c.GError, err: Error, attribute: [*c]const u8) void {
    c.g_set_error(err_out, c.g_io_error_quark(), gioerr.code(err, 0), "Error setting file metadata %s: %s", attribute, reason(err));
}

/// Store one metadata attribute of `info`: string, stringv, or unset (type INVALID).
fn setOne(cl: *md.Client, id: *const md.Identity, info: *c.GFileInfo, attribute: [*c]const u8) Error!void {
    const key = keyOf(std.mem.span(attribute)) orelse return error.BadRequest;
    var t: c.GFileAttributeType = c.G_FILE_ATTRIBUTE_TYPE_INVALID;
    var value: c.gpointer = null;
    if (c.g_file_info_get_attribute_data(info, attribute, &t, &value, null) == 0) return error.BadRequest;
    switch (t) {
        c.G_FILE_ATTRIBUTE_TYPE_INVALID => try cl.unset(id, key),
        c.G_FILE_ATTRIBUTE_TYPE_STRING => {
            if (value == null) return error.BadRequest;
            try cl.setString(id, key, std.mem.span(@as([*:0]const u8, @ptrCast(value))));
        },
        c.G_FILE_ATTRIBUTE_TYPE_STRINGV => {
            var items: [md.max_stringv_items][]const u8 = undefined;
            var n: usize = 0;
            if (value != null) {
                const v: [*]const [*c]const u8 = @ptrCast(@alignCast(value));
                while (v[n] != null) : (n += 1) {
                    if (n == items.len) return error.ValueTooLarge;
                    items[n] = std.mem.span(@as([*:0]const u8, @ptrCast(v[n])));
                }
            }
            try cl.setStringv(id, key, items[0..n]);
        },
        else => return error.WrongType,
    }
}

fn markAll(info: *c.GFileInfo, attrs: [*c][*c]u8, status: c.GFileAttributeStatus) void {
    var i: usize = 0;
    while (attrs[i] != null) : (i += 1) _ = c.g_file_info_set_attribute_status(info, attrs[i], status);
}

/// local_file_set_attributes: store every metadata::* attribute of `info`, marking each
/// SET or ERROR_SETTING (GLib reports an attribute left unmarked as not supported).
/// Returns FALSE with `err_out` set (once) if any failed.
pub fn setAttributes(filename: [*c]const u8, info: ?*c.GFileInfo, cancellable: [*c]c.GCancellable, err_out: [*c][*c]c.GError) c.gboolean {
    const inf = info orelse return 1;
    const attrs = c.g_file_info_list_attributes(inf, namespace);
    defer c.g_strfreev(attrs);
    if (attrs == null or attrs[0] == null) return 1;
    if (filename == null) {
        markAll(inf, attrs, c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING);
        setError(err_out, error.BadRequest, attrs[0]);
        return 0;
    }
    if (cancellable != null and c.g_cancellable_set_error_if_cancelled(cancellable, err_out) != 0) {
        markAll(inf, attrs, c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING);
        return 0;
    }
    if (health.blocks(std.mem.span(filename))) {
        markAll(inf, attrs, c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING);
        setError(err_out, error.MountHung, attrs[0]);
        return 0;
    }
    const cl = link.acquire(link.budget(update_budget_ms)) catch |err| {
        markAll(inf, attrs, c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING);
        setError(err_out, err, attrs[0]);
        return 0;
    };
    // The error that matters to the link: a fatal one over a timeout over any other.
    var failure: ?anyerror = null;
    defer link.release(cl, failure);
    const id = cl.identify(std.mem.span(filename)) catch |err| {
        failure = err;
        markAll(inf, attrs, c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING);
        setError(err_out, err, attrs[0]);
        return 0;
    };
    var ok = true;
    var i: usize = 0;
    while (attrs[i] != null) : (i += 1) {
        if (setOne(cl, &id, inf, attrs[i])) {
            _ = c.g_file_info_set_attribute_status(inf, attrs[i], c.G_FILE_ATTRIBUTE_STATUS_SET);
        } else |err| {
            _ = c.g_file_info_set_attribute_status(inf, attrs[i], c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING);
            if (ok) setError(err_out, err, attrs[i]); // GLib convention: the first error only
            ok = false;
            if (failure == null or link.isFatal(err) or (err == error.Timeout and !link.isFatal(failure.?))) failure = err;
        }
    }
    return @intFromBool(ok);
}

// ---- writable namespaces, removed, moved ---------------------------------------

/// add_writable_namespaces: "metadata" is settable, and g_file_copy / cross-device moves
/// carry it along (the same flags as gvfs's metadata).
pub fn addWritableNamespaces(list: [*c]c.GFileAttributeInfoList) void {
    if (list == null) return;
    c.g_file_attribute_info_list_add(list, namespace, c.G_FILE_ATTRIBUTE_TYPE_STRING, c.G_FILE_ATTRIBUTE_INFO_COPY_WITH_FILE | c.G_FILE_ATTRIBUTE_INFO_COPY_WHEN_MOVED);
}

/// local_file_removed: best effort, bounded; GIO has already deleted the file.
pub fn fileRemoved(filename: [*c]const u8) void {
    if (filename == null) return;
    notify(.{ .removed = std.mem.span(filename) });
}

/// local_file_moved (rename and trash): best effort, bounded; already renamed.
pub fn fileMoved(source: [*c]const u8, dest: [*c]const u8) void {
    if (source == null or dest == null) return;
    notify(.{ .moved = .{ std.mem.span(source), std.mem.span(dest) } });
}

const Notice = union(enum) { removed: []const u8, moved: [2][]const u8 };

fn notify(n: Notice) void {
    // The daemon would identify what is at the path now (removed) or at the destination.
    const target = switch (n) {
        .removed => |p| p,
        .moved => |p| p[1],
    };
    if (health.blocks(target)) {
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: metadata not updated for a %s: the mount is hung", @tagName(n).ptr);
        return;
    }
    const cl = link.acquire(link.budget(update_budget_ms)) catch |err| {
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: metadata not updated for a %s: %s", @tagName(n).ptr, @errorName(err).ptr);
        return;
    };
    const r: Error!void = switch (n) {
        .removed => |p| if (cl.removed(p)) |_| {} else |err| err,
        .moved => |p| if (cl.moved(p[0], p[1])) |_| {} else |err| err,
    };
    link.release(cl, errOf(r));
    r catch |err| c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: metadata not updated for a %s: %s", @tagName(n).ptr, @errorName(err).ptr);
}

// ---- tests --------------------------------------------------------------------

test "attribute names map to keys" {
    try std.testing.expectEqualStrings("custom-icon", keyOf("metadata::custom-icon").?);
    try std.testing.expectEqualStrings("a::b", keyOf("metadata::a::b").?);
    try std.testing.expect(keyOf("metadata::") == null);
    try std.testing.expect(keyOf("standard::name") == null);
    try std.testing.expect(keyOf("metadata:x") == null);
    var long: [prefix.len + md.max_key_len + 1]u8 = @splat('k');
    @memcpy(long[0..prefix.len], prefix);
    try std.testing.expect(keyOf(&long) == null);
    try std.testing.expect(keyOf(long[0 .. long.len - 1]) != null);
}

test "metadata errors map to the documented GIO codes" {
    const code = gioerr.code;
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_SUPPORTED), code(error.Unavailable, 0));
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_SUPPORTED), code(error.DaemonAbsent, 0));
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_BUSY), code(error.Busy, 0));
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_BUSY), code(error.RingFull, 0));
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_TIMED_OUT), code(error.Timeout, 0));
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_TIMED_OUT), code(error.SuspectMount, 0));
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_INVALID_ARGUMENT), code(error.WrongType, 0));
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_NO_SPACE), code(error.TooManyKeys, 0));
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_FAILED), code(error.DaemonDb, 0));
}

test "values reach GFileInfo intact and nothing leaks" {
    const gpa = std.testing.allocator;
    const info = c.g_file_info_new() orelse return error.OutOfMemory;
    defer c.g_object_unref(info);
    const s = try gpa.dupe(u8, "spear \u{2603}");
    var list = try gpa.alloc([]u8, 3);
    list[0] = try gpa.dupe(u8, "a");
    list[1] = try gpa.dupe(u8, "");
    list[2] = try gpa.dupe(u8, "c");
    var entries: std.ArrayList(Entry) = .empty;
    defer freeEntries(gpa, &entries);
    try entries.append(gpa, .{ .key = try gpa.dupe(u8, "icon"), .value = .{ .string = s } });
    try entries.append(gpa, .{ .key = try gpa.dupe(u8, "emblems"), .value = .{ .stringv = list } });
    for (entries.items) |e| try putAttribute(gpa, info, e);
    try std.testing.expectEqualStrings("spear \u{2603}", std.mem.span(c.g_file_info_get_attribute_string(info, "metadata::icon")));
    const v = c.g_file_info_get_attribute_stringv(info, "metadata::emblems");
    try std.testing.expectEqualStrings("a", std.mem.span(v[0]));
    try std.testing.expectEqualStrings("", std.mem.span(v[1]));
    try std.testing.expectEqualStrings("c", std.mem.span(v[2]));
    try std.testing.expect(v[3] == null);
}

test "setting without a daemon fails fast with a GIO error, every attribute marked" {
    const info = c.g_file_info_new() orelse return error.OutOfMemory;
    defer c.g_object_unref(info);
    c.g_file_info_set_attribute_string(info, "metadata::a", "x");
    c.g_file_info_set_attribute(info, "metadata::b", c.G_FILE_ATTRIBUTE_TYPE_INVALID, null);
    var err: [*c]c.GError = null;
    const t0 = md.nowNs();
    // No GungnirVfs was created in the unit tests: the link stays "connecting", so the
    // set waits out its budget and reports a timeout.
    try std.testing.expectEqual(@as(c.gboolean, 0), setAttributes("/nonexistent", info, null, &err));
    try std.testing.expect(md.nowNs() - t0 < (update_budget_ms + 200) * std.time.ns_per_ms);
    try std.testing.expect(err != null);
    defer c.g_error_free(err);
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_TIMED_OUT), err.*.code);
    try std.testing.expectEqual(@as(c.GFileAttributeStatus, c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING), c.g_file_info_get_attribute_status(info, "metadata::a"));
    try std.testing.expectEqual(@as(c.GFileAttributeStatus, c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING), c.g_file_info_get_attribute_status(info, "metadata::b"));
    // Nothing to do: TRUE without touching the daemon.
    const plain = c.g_file_info_new() orelse return error.OutOfMemory;
    defer c.g_object_unref(plain);
    c.g_file_info_set_attribute_string(plain, "standard::name", "x");
    try std.testing.expectEqual(@as(c.gboolean, 1), setAttributes("/nonexistent", plain, null, null));
}

test "a mount known to be hung fails at once, without the daemon" {
    health.reset();
    defer health.reset();
    var buf: [64]u8 = undefined;
    std.mem.writeInt(u64, buf[0..8], 1, .little);
    buf[8] = health.ev_first | health.ev_last;
    std.mem.writeInt(u16, buf[9..11], 1, .little);
    std.mem.writeInt(u64, buf[11..19], 40, .little);
    buf[19] = health.hung;
    std.mem.writeInt(u16, buf[20..22], 7, .little);
    @memcpy(buf[22..29], "/hung-m");
    health.onEvent(buf[0..29]);
    const info = c.g_file_info_new() orelse return error.OutOfMemory;
    defer c.g_object_unref(info);
    c.g_file_info_set_attribute_string(info, "metadata::a", "x");
    var err: [*c]c.GError = null;
    const t0 = md.nowNs();
    // The link is still "connecting" in the unit tests: a set that asked it would wait
    // out its whole budget. This one does not even try.
    try std.testing.expectEqual(@as(c.gboolean, 0), setAttributes("/hung-m/f", info, null, &err));
    try std.testing.expect(md.nowNs() - t0 < 50 * std.time.ns_per_ms);
    try std.testing.expect(err != null);
    defer c.g_error_free(err);
    try std.testing.expectEqual(@as(c_int, c.G_IO_ERROR_TIMED_OUT), err.*.code);
    try std.testing.expect(std.mem.find(u8, std.mem.span(err.*.message), "health monitor") != null);
    try std.testing.expectEqual(@as(c.GFileAttributeStatus, c.G_FILE_ATTRIBUTE_STATUS_ERROR_SETTING), c.g_file_info_get_attribute_status(info, "metadata::a"));
    // A query just has no metadata, at once.
    const m = c.g_file_attribute_matcher_new("metadata::*");
    defer c.g_file_attribute_matcher_unref(m);
    const q = c.g_file_info_new() orelse return error.OutOfMemory;
    defer c.g_object_unref(q);
    const t1 = md.nowNs();
    addInfo(std.testing.allocator, "/hung-m/f", m, q);
    try std.testing.expect(md.nowNs() - t1 < 50 * std.time.ns_per_ms);
    try std.testing.expect(c.g_file_info_has_namespace(q, namespace) == 0);
    // Notifications are skipped (they would wait for the link otherwise).
    const t2 = md.nowNs();
    fileRemoved("/hung-m/f");
    fileMoved("/elsewhere", "/hung-m/g");
    try std.testing.expect(md.nowNs() - t2 < 50 * std.time.ns_per_ms);
}

test "namespace is listed as writable and copied with the file" {
    const list = c.g_file_attribute_info_list_new();
    defer c.g_file_attribute_info_list_unref(list);
    addWritableNamespaces(list);
    const found = c.g_file_attribute_info_list_lookup(list, namespace);
    try std.testing.expect(found != null);
    try std.testing.expect(found.*.flags & c.G_FILE_ATTRIBUTE_INFO_COPY_WITH_FILE != 0);
}

/// A stand-in daemon on in-memory rings: identify, list (keys "a", "b"), get ("a" is a
/// string, "b" a stringv), so the query path runs under the leak-checking allocator.
const FakeDaemon = struct {
    shm: @import("ipc.zig").Shm,
    stop: bool = false,

    fn main(data: c.gpointer) callconv(.c) c.gpointer {
        const ipc = @import("ipc.zig");
        const f: *FakeDaemon = @ptrCast(@alignCast(data));
        while (!@atomicLoad(bool, &f.stop, .acquire)) {
            f.shm.waitReadable(ipc.ring_c2d, md.nowNs() + 10 * std.time.ns_per_ms) catch continue;
            while (f.shm.pop(ipc.ring_c2d) catch null) |m| {
                var buf: [64]u8 = @splat(0);
                var n: usize = 4; // status 0 (ok)
                const body: []const u8 = switch (m.kind) {
                    // uuid_len 4 | "fake" | subvol, inode, generation (u64) | btime (i64, u32)
                    md.msg_identify => &.{ 4, 'f', 'a', 'k', 'e', 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                    md.msg_list => &.{ 0, 2, 0, 1, 0, 'a', 1, 0, 'b' },
                    md.msg_get => if (m.payload()[m.len - 1] == 'a') &.{ 1, 1, 0, 'x' } else &.{ 2, 2, 0, 1, 0, 'p', 0, 0 },
                    else => &.{},
                };
                @memcpy(buf[n..][0..body.len], body);
                n += body.len;
                f.shm.push(ipc.ring_d2c, md.msg_reply, m.seq, buf[0..n]) catch {};
            }
        }
        return null;
    }
};

test "the query path is leak-free and all-or-nothing" {
    const ipc = @import("ipc.zig");
    const linux = std.os.linux;
    const gpa = std.testing.allocator;
    var buf: [ipc.shm_size]u8 align(4096) = undefined;
    var fake: FakeDaemon = .{ .shm = .{ .mem = &buf } };
    fake.shm.initHeader();
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    var conn: ipc.Conn = .{ .fd = fds[0], .shm = fake.shm };
    var cl: md.Client = .{ .conn = &conn, .timeout_ms = 2_000 };
    const t = c.g_thread_new("fake-gungnird", &FakeDaemon.main, &fake);
    defer {
        @atomicStore(bool, &fake.stop, true, .release);
        _ = c.g_thread_join(t);
    }

    var all = try fetch(gpa, &cl, "/f", null);
    defer freeEntries(gpa, &all);
    try std.testing.expectEqual(@as(usize, 2), all.items.len);
    try std.testing.expectEqualStrings("a", all.items[0].key);
    try std.testing.expectEqualStrings("x", all.items[0].value.string);
    try std.testing.expectEqual(@as(usize, 2), all.items[1].value.stringv.len);

    var some = try fetch(gpa, &cl, "/f", &.{"b"});
    defer freeEntries(gpa, &some);
    try std.testing.expectEqual(@as(usize, 1), some.items.len);
    try std.testing.expectEqualStrings("p", some.items[0].value.stringv[0]);

    const info = c.g_file_info_new() orelse return error.OutOfMemory;
    defer c.g_object_unref(info);
    for (all.items) |e| try putAttribute(gpa, info, e);
    try std.testing.expectEqualStrings("x", std.mem.span(c.g_file_info_get_attribute_string(info, "metadata::a")));

    // Out of time: an error, no partial result, nothing leaked.
    cl.deadline_ns = md.nowNs();
    try std.testing.expectError(error.Timeout, fetch(gpa, &cl, "/f", null));
}
