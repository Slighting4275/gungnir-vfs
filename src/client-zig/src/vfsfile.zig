//! `trash:///` and `recent:///` as GFiles (milestone 9), served by gungnird
//! (`src/daemon-rust/src/vfssvc.rs` is the other half of the protocol).
//!
//! A `GungnirFile` is the root of a scheme, one item in it, or an entry inside a trashed
//! folder (`<item>/<path>`, read-only: the trash only has records of whole items). Every call opens its own
//! connection, so a long empty or delete never holds the shared metadata link, and every
//! wait is bounded. These are GIO's blocking calls, made on the caller's thread: file
//! managers run them on worker threads. A daemon that is not there gives
//! `G_IO_ERROR_NOT_SUPPORTED`, never a hang.
//!
//! A monitor on a root polls a cheap change stamp from the daemon on its own thread and
//! emits what changed. An item is read through a stream whose every call has a deadline
//! on a worker thread, so a mount that hangs under a read costs that thread, not the caller.

const std = @import("std");
const health = @import("health.zig");
const c = @import("c");
const ipc = @import("ipc.zig");
const rpc = @import("rpc.zig");
const proto = @import("proto.zig");
const gioerr = @import("gioerr.zig");
const build_options = @import("build_options");

const msg_list = proto.msg_vfs_list;
const msg_delete = proto.msg_vfs_delete;
const msg_restore = proto.msg_vfs_restore;
const msg_stat = proto.msg_vfs_stat;
const msg_children = proto.msg_vfs_children;
const msg_stamp = proto.msg_vfs_stamp;

const scheme_trash = proto.scheme_trash;
const scheme_recent = proto.scheme_recent;

const item_file = proto.item_file;
const item_dir = proto.item_dir;
const item_symlink = proto.item_symlink;

const connect_timeout_ms = 500;
const list_timeout_ms = 5_000;
/// Longest silence from the daemon. An op under way sends a beat every 5 s, so a big
/// restore takes what it takes, and only a daemon stuck outside its engine runs this out.
const op_timeout_ms = 65_000;
const msg_beat = proto.msg_vfs_beat;
/// A list refused because every request slot is taken is tried again this often.
const busy_retries = 100;
const busy_wait_us = 20_000;

pub const GungnirFile = extern struct {
    parent: c.GObject,
    scheme: u8,
    /// The URI name; null for the root.
    name: [*c]u8,
};

const GungnirFileClass = extern struct {
    parent_class: c.GObjectClass,
};

const GungnirEnum = extern struct {
    parent: c.GFileEnumerator,
    infos: ?*c.GPtrArray,
    at: c.guint,
    partial: c_int,
};

const GungnirEnumClass = extern struct {
    parent_class: c.GFileEnumeratorClass,
};

var file_type: c.GType = 0;
var enum_type: c.GType = 0;
var monitor_type: c.GType = 0;
var stream_type: c.GType = 0;

fn asSelf(f: ?*c.GFile) *GungnirFile {
    return @ptrCast(@alignCast(f));
}

fn isOurs(f: ?*c.GFile) bool {
    return f != null and c.g_type_check_instance_is_a(@ptrCast(@alignCast(f)), file_type) != 0;
}

fn newFile(scheme: u8, name: [*c]const u8) ?*c.GFile {
    const raw = c.g_object_new(file_type, null) orelse return null;
    const self: *GungnirFile = @ptrCast(@alignCast(raw));
    self.scheme = scheme;
    self.name = if (name != null) c.g_strdup(name) else null;
    return @ptrCast(@alignCast(raw));
}

fn schemeName(s: u8) [*c]const u8 {
    return if (s == scheme_recent) "recent" else "trash";
}

/// The GFile for a `trash:` or `recent:` URI, null for any other. `trash:///x`,
/// `trash://x` and `trash:x` all name the item x; a name with a slash in it is no item
/// and answers not-found when used.
pub fn forUri(uri: [*c]const u8) ?*c.GFile {
    const s = std.mem.span(uri);
    const scheme: u8, const rest = blk: {
        if (std.ascii.startsWithIgnoreCase(s, "trash:")) break :blk .{ scheme_trash, s["trash:".len..] };
        if (std.ascii.startsWithIgnoreCase(s, "recent:")) break :blk .{ scheme_recent, s["recent:".len..] };
        return null;
    };
    const trimmed = std.mem.trimStart(u8, rest, "/");
    if (trimmed.len == 0) return newFile(scheme, null);
    const z = c.g_uri_unescape_string(trimmed.ptr, null);
    if (z == null) {
        // Not valid escaping (%00, a stray %): no item has that name, and above all it
        // must not silently mean the root.
        // The raw text could be a real item's name, so it gets a slash, which none has.
        const raw = dupz(trimmed);
        defer c.g_free(raw);
        const none = c.g_strconcat("/", raw, @as([*c]const u8, null));
        defer c.g_free(none);
        return newFile(scheme, none);
    }
    defer c.g_free(z);
    // `trash:///h-dir/` is the folder: children are built on the name, one slash apart.
    const clean = std.mem.trimEnd(u8, std.mem.span(z), "/");
    if (clean.len == 0) return newFile(scheme, null);
    const name = dupz(clean);
    defer c.g_free(name);
    return newFile(scheme, name);
}

// ---- talking to the daemon --------------------------------------------------------

fn setError(err: [*c][*c]c.GError, code: c_int, msg: [*c]const u8) void {
    c.g_set_error_literal(err, c.g_io_error_quark(), code, msg);
}

fn envValue(name: [*c]const u8) ?[]const u8 {
    const v = c.g_getenv(name);
    return if (v == null) null else std.mem.span(v);
}

const Link = struct {
    conn: ipc.Conn,
    client: rpc.Client,

    /// A fresh connection. `self` must not move afterwards.
    fn open(self: *Link, timeout_ms: u32, err: [*c][*c]c.GError) bool {
        const sock = ipc.resolveSocketPath(envValue("GUNGNIR_SOCKET"), envValue("XDG_RUNTIME_DIR"), envValue("HOME")) catch {
            setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "gungnird is not available");
            return false;
        };
        self.conn = ipc.connectAndPing(&sock, connect_timeout_ms) catch {
            setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "gungnird is not available");
            return false;
        };
        self.client = .{ .conn = &self.conn, .timeout_ms = timeout_ms };
        return true;
    }

    fn close(self: *Link) void {
        self.conn.close();
    }
};

/// Turn a failed request into a GError.
fn cancelled(ctx: ?*anyopaque) bool {
    const k: [*c]c.GCancellable = @ptrCast(@alignCast(ctx));
    return c.g_cancellable_is_cancelled(k) != 0;
}

/// Have `link` honour `k`: closing the connection is what stops the daemon's op.
fn watch(link: *Link, k: [*c]c.GCancellable) void {
    link.client.beat_kind = msg_beat;
    if (k != null) {
        link.client.stop = &cancelled;
        link.client.stop_ctx = @ptrCast(k);
    }
}

/// A request, tried again while every request slot is taken: each query of one item is a
/// list, so a folder view's worth of them at once is normal, and `busy` means a moment.
fn requestRetry(link: *Link, kind: u32, payload: []const u8, reply: *ipc.Msg) rpc.Error![]const u8 {
    const Call = struct {
        link: *Link,
        kind: u32,
        payload: []const u8,
        reply: *ipc.Msg,
        fn run(a: @This()) rpc.Error![]const u8 {
            return a.link.client.request(a.kind, a.payload, a.reply);
        }
    };
    return whileBusy(Call{ .link = link, .kind = kind, .payload = payload, .reply = reply }, busy_retries, busy_wait_us);
}

fn whileBusy(call: anytype, retries: u32, wait_us: c.gulong) rpc.Error![]const u8 {
    var tries: u32 = 0;
    while (true) {
        return call.run() catch |e| {
            if (e != error.Busy or tries >= retries) return e;
            tries += 1;
            c.g_usleep(wait_us);
            continue;
        };
    }
}

/// Report `e` from a trash or recent call: the code is the shared map's (gioerr.zig), the
/// words are this service's.
fn failure(reply: *ipc.Msg, e: rpc.Error, err: [*c][*c]c.GError) void {
    const p = reply.payload();
    const errno: i32 = if (e == error.DaemonOs) proto.osErrno(if (p.len >= 4) p[4..] else p[0..0]) else 0;
    const code = gioerr.code(e, errno);
    const text: [*c]const u8 = switch (e) {
        error.Cancelled => "cancelled",
        error.Busy => "gungnird is busy; try again",
        error.Timeout => "gungnird did not answer in time",
        error.SuspectMount => "a volume is hung or gone (reported by the gungnird mount health monitor)",
        error.NotFound, error.NoSuchFile => "no such item",
        error.BadRequest => "not a valid item",
        error.Unsupported => "this gungnird has no trash service",
        error.MountInside => "contains a mounted filesystem; unmount it and try again",
        error.NotEmpty => "some items remain",
        error.WouldRecurse => "a folder cannot be restored to another filesystem this way",
        error.DaemonOs => c.g_strerror(errno),
        error.Protocol, error.DaemonIo, error.DaemonDb => "bad reply from gungnird",
        else => if (code == c.G_IO_ERROR_NOT_SUPPORTED) "gungnird is not available" else @errorName(e).ptr,
    };
    setError(err, code, text);
}

/// One listed entry, slices of a reply.
const Row = struct {
    name: []const u8,
    orig: []const u8,
    target: []const u8,
    deleted: []const u8,
    link: []const u8,
    kind: u8,
    size: u64,
    mtime: i64,
};

const Parser = struct {
    rest: []const u8,

    fn str(p: *Parser) ?[]const u8 {
        if (p.rest.len < 2) return null;
        const n = std.mem.readInt(u16, p.rest[0..2], .little);
        if (p.rest.len < 2 + @as(usize, n)) return null;
        const s = p.rest[2 .. 2 + n];
        p.rest = p.rest[2 + n ..];
        return s;
    }

    fn row(p: *Parser) ?Row {
        const name = p.str() orelse return null;
        const orig = p.str() orelse return null;
        const target = p.str() orelse return null;
        const deleted = p.str() orelse return null;
        const link = p.str() orelse return null;
        if (p.rest.len < 17) return null;
        const r: Row = .{
            .name = name,
            .orig = orig,
            .target = target,
            .deleted = deleted,
            .link = link,
            .kind = p.rest[0],
            .size = std.mem.readInt(u64, p.rest[1..9], .little),
            .mtime = std.mem.readInt(i64, p.rest[9..17], .little),
        };
        p.rest = p.rest[17..];
        return r;
    }
};

/// A NUL-terminated copy for GLib, freed with g_free.
fn dupz(s: []const u8) [*c]u8 {
    return c.g_strndup(s.ptr, s.len);
}

fn lastComponent(s: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, s, "/");
    const at = std.mem.lastIndexOfScalar(u8, t, '/') orelse return t;
    return t[at + 1 ..];
}

fn setCommon(info: *c.GFileInfo) void {
    c.g_file_info_set_attribute_boolean(info, "access::can-read", 1);
    c.g_file_info_set_attribute_boolean(info, "access::can-write", 0);
    c.g_file_info_set_attribute_boolean(info, "access::can-rename", 0);
    c.g_file_info_set_attribute_boolean(info, "access::can-trash", 0);
}

fn infoFor(scheme: u8, r: *const Row) ?*c.GFileInfo {
    const info = c.g_file_info_new() orelse return null;
    // Inside a folder the name is the last part: g_file_get_child builds the rest.
    const inner = std.mem.indexOfScalar(u8, r.name, '/') != null;
    const name = dupz(lastComponent(r.name));
    defer c.g_free(name);
    c.g_file_info_set_name(info, name);

    // What the user sees: the original name; for a degraded item, the entry's.
    const shown = dupz(blk: {
        if (r.orig.len != 0) break :blk lastComponent(r.orig);
        if (inner) break :blk lastComponent(r.name);
        if (std.mem.indexOfScalar(u8, r.name, '-')) |at| break :blk r.name[at + 1 ..];
        break :blk r.name;
    });
    defer c.g_free(shown);
    const unescaped = if (scheme == scheme_recent) c.g_uri_unescape_string(shown, null) else null;
    defer c.g_free(unescaped);
    const show_raw: [*c]const u8 = if (unescaped != null) unescaped else shown;
    const display = c.g_filename_display_name(show_raw);
    defer c.g_free(display);
    c.g_file_info_set_display_name(info, display);

    const file_kind: c.GFileType = switch (r.kind) {
        item_file => c.G_FILE_TYPE_REGULAR,
        item_dir => c.G_FILE_TYPE_DIRECTORY,
        item_symlink => c.G_FILE_TYPE_SYMBOLIC_LINK,
        else => c.G_FILE_TYPE_SPECIAL,
    };
    c.g_file_info_set_file_type(info, file_kind);
    c.g_file_info_set_size(info, @intCast(@min(r.size, std.math.maxInt(i64))));
    c.g_file_info_set_is_hidden(info, 0);
    c.g_file_info_set_attribute_boolean(info, "standard::is-backup", 0);
    c.g_file_info_set_is_symlink(info, 0);
    c.g_file_info_set_attribute_uint64(info, "time::modified", @intCast(@max(r.mtime, 0)));
    c.g_file_info_set_attribute_boolean(info, "access::can-delete", 1);
    setCommon(info);
    if (inner) c.g_file_info_set_attribute_boolean(info, "access::can-delete", 0);
    if (r.kind == item_symlink) {
        c.g_file_info_set_is_symlink(info, 1);
        // g_file_copy with NOFOLLOW recreates the link from this, instead of reading it.
        const l = dupz(r.link);
        defer c.g_free(l);
        if (r.link.len != 0) c.g_file_info_set_symlink_target(info, l);
    }

    if (r.kind == item_dir) {
        c.g_file_info_set_content_type(info, "inode/directory");
        setIcons(info, "inode/directory");
    } else {
        const guess = c.g_content_type_guess(show_raw, null, 0, null);
        defer c.g_free(guess);
        c.g_file_info_set_content_type(info, guess);
        setIcons(info, guess);
    }
    if (r.target.len != 0) {
        const tz = dupz(r.target);
        defer c.g_free(tz);
        const uri = c.g_filename_to_uri(tz, null, null);
        defer c.g_free(uri);
        if (uri != null) {
            c.g_file_info_set_attribute_string(info, "standard::target-uri", uri);
            setThumbnail(info, uri);
        }
    }
    if (scheme == scheme_trash) {
        const o = dupz(r.orig);
        defer c.g_free(o);
        if (r.orig.len != 0) c.g_file_info_set_attribute_byte_string(info, "trash::orig-path", o);
        const d = dupz(r.deleted);
        defer c.g_free(d);
        if (r.deleted.len != 0) c.g_file_info_set_attribute_string(info, "trash::deletion-date", d);
    } else {
        const o = dupz(r.orig);
        defer c.g_free(o);
        c.g_file_info_set_attribute_string(info, "standard::target-uri", o);
    }
    return info;
}

/// Every item of `scheme` as GFileInfos, in a new array owning them.
/// Everything listed; `partial` says it may not be everything there is.
fn fetch(scheme: u8, partial: ?*bool, err: [*c][*c]c.GError) ?*c.GPtrArray {
    return fetchFrom(scheme, null, partial, err);
}

/// A page of a root's list, or of the folder `dir` inside the trash.
fn pageRequest(buf: []u8, scheme: u8, dir: ?[]const u8, cursor: u32) ?struct { kind: u32, len: usize } {
    if (dir) |d| {
        if (d.len + 6 > buf.len) return null;
        std.mem.writeInt(u32, buf[0..4], cursor, .little);
        std.mem.writeInt(u16, buf[4..6], @intCast(d.len), .little);
        @memcpy(buf[6 .. 6 + d.len], d);
        return .{ .kind = msg_children, .len = 6 + d.len };
    }
    buf[0] = scheme;
    std.mem.writeInt(u32, buf[1..5], cursor, .little);
    return .{ .kind = msg_list, .len = 5 };
}

fn fetchFrom(scheme: u8, dir: ?[]const u8, partial: ?*bool, err: [*c][*c]c.GError) ?*c.GPtrArray {
    var link: Link = undefined;
    if (!link.open(list_timeout_ms, err)) return null;
    defer link.close();
    const out: *c.GPtrArray = c.g_ptr_array_new_with_free_func(&c.g_object_unref) orelse return null;
    var cursor: u32 = 0;
    while (true) {
        var req: [ipc.payload_max]u8 = undefined;
        const r0 = pageRequest(&req, scheme, dir, cursor) orelse {
            setError(err, c.G_IO_ERROR_NOT_FOUND, "no such item");
            _ = c.g_ptr_array_free(out, 1);
            return null;
        };
        var reply: ipc.Msg = undefined;
        const body = requestRetry(&link, r0.kind, req[0..r0.len], &reply) catch |e| {
            failure(&reply, e, err);
            _ = c.g_ptr_array_free(out, 1);
            return null;
        };
        if (body.len < 7) {
            setError(err, c.G_IO_ERROR_FAILED, "bad reply from gungnird");
            _ = c.g_ptr_array_free(out, 1);
            return null;
        }
        const next = std.mem.readInt(u32, body[0..4], .little);
        const count = std.mem.readInt(u16, body[4..6], .little);
        if (partial) |o| o.* = o.* or body[6] != 0;
        var p: Parser = .{ .rest = body[7..] };
        var i: u16 = 0;
        while (i < count) : (i += 1) {
            const r = p.row() orelse {
                setError(err, c.G_IO_ERROR_FAILED, "bad reply from gungnird");
                _ = c.g_ptr_array_free(out, 1);
                return null;
            };
            if (infoFor(scheme, &r)) |info| c.g_ptr_array_add(out, info);
        }
        if (next == 0) return out;
        // A cursor that does not move would loop for ever on a confused daemon.
        if (next <= cursor) {
            setError(err, c.G_IO_ERROR_FAILED, "bad reply from gungnird");
            _ = c.g_ptr_array_free(out, 1);
            return null;
        }
        cursor = next;
    }
}

fn rootInfo(scheme: u8, count: c.guint) ?*c.GFileInfo {
    const info = c.g_file_info_new() orelse return null;
    c.g_file_info_set_name(info, "/");
    c.g_file_info_set_display_name(info, if (scheme == scheme_recent) "Recent" else "Trash");
    c.g_file_info_set_file_type(info, c.G_FILE_TYPE_DIRECTORY);
    c.g_file_info_set_content_type(info, "inode/directory");
    const name: [*c]const u8 = if (scheme == scheme_recent) "document-open-recent" else "user-trash";
    const sym: [*c]const u8 = if (scheme == scheme_recent) "document-open-recent-symbolic" else "user-trash-symbolic";
    const icon = c.g_themed_icon_new(name);
    defer c.g_object_unref(icon);
    const symbolic = c.g_themed_icon_new(sym);
    defer c.g_object_unref(symbolic);
    c.g_file_info_set_icon(info, icon);
    c.g_file_info_set_symbolic_icon(info, symbolic);
    c.g_file_info_set_size(info, 0);
    c.g_file_info_set_is_hidden(info, 0);
    c.g_file_info_set_attribute_boolean(info, "standard::is-backup", 0);
    c.g_file_info_set_is_symlink(info, 0);
    setCommon(info);
    c.g_file_info_set_attribute_boolean(info, "access::can-delete", 0);
    if (scheme == scheme_trash) c.g_file_info_set_attribute_uint32(info, "trash::item-count", count);
    return info;
}

/// File managers read these unconditionally, and GLib logs a critical for each that is absent.
fn setIcons(info: *c.GFileInfo, content_type: [*c]const u8) void {
    const icon = c.g_content_type_get_icon(content_type);
    defer c.g_object_unref(icon);
    const symbolic = c.g_content_type_get_symbolic_icon(content_type);
    defer c.g_object_unref(symbolic);
    c.g_file_info_set_icon(info, icon);
    c.g_file_info_set_symbolic_icon(info, symbolic);
}

/// The file's thumbnail from the shared cache, keyed by the URI of the file itself. With
/// none, say so: a file manager would otherwise try to make one for a `trash:` URI, get
/// nowhere, reload the item and try again, several times a second, for ever.
fn setThumbnail(info: *c.GFileInfo, uri: [*c]const u8) void {
    const sum = c.g_compute_checksum_for_string(c.G_CHECKSUM_MD5, uri, -1);
    defer c.g_free(sum);
    const name = c.g_strconcat(sum, ".png", @as([*c]const u8, null));
    defer c.g_free(name);
    for ([_][*c]const u8{ "x-large", "large", "normal" }) |size| {
        const path = c.g_build_filename(c.g_get_user_cache_dir(), "thumbnails", size, name, @as([*c]const u8, null));
        defer c.g_free(path);
        if (c.g_file_test(path, c.G_FILE_TEST_IS_REGULAR) != 0) {
            c.g_file_info_set_attribute_byte_string(info, "thumbnail::path", path);
            return;
        }
    }
    c.g_file_info_set_attribute_boolean(info, "thumbnail::failed", 1);
}

/// One item's info, as a new reference. Asked for by name: the daemon looks at this one
/// entry, whatever the size of the trash.
fn findInfo(self: *GungnirFile, err: [*c][*c]c.GError) ?*c.GFileInfo {
    const name = std.mem.span(self.name);
    var req: [ipc.payload_max]u8 = undefined;
    if (name.len + 3 > req.len) {
        setError(err, c.G_IO_ERROR_NOT_FOUND, "no such item");
        return null;
    }
    req[0] = self.scheme;
    std.mem.writeInt(u16, req[1..3], @intCast(name.len), .little);
    @memcpy(req[3 .. 3 + name.len], name);
    var link: Link = undefined;
    if (!link.open(list_timeout_ms, err)) return null;
    defer link.close();
    var reply: ipc.Msg = undefined;
    const body = requestRetry(&link, msg_stat, req[0 .. 3 + name.len], &reply) catch |e| {
        failure(&reply, e, err);
        return null;
    };
    if (body.len < 7) {
        setError(err, c.G_IO_ERROR_FAILED, "bad reply from gungnird");
        return null;
    }
    var p: Parser = .{ .rest = body[7..] };
    const row = p.row() orelse {
        setError(err, c.G_IO_ERROR_FAILED, "bad reply from gungnird");
        return null;
    };
    return infoFor(self.scheme, &row);
}

// ---- GFile -------------------------------------------------------------------------

fn fileDup(f: ?*c.GFile) callconv(.c) ?*c.GFile {
    const s = asSelf(f);
    return newFile(s.scheme, s.name);
}

fn fileHash(f: ?*c.GFile) callconv(.c) c.guint {
    const s = asSelf(f);
    return (if (s.name != null) c.g_str_hash(s.name) else 0) +% s.scheme;
}

fn fileEqual(a: ?*c.GFile, b: ?*c.GFile) callconv(.c) c.gboolean {
    if (!isOurs(b)) return 0;
    const x = asSelf(a);
    const y = asSelf(b);
    return @intFromBool(x.scheme == y.scheme and c.g_strcmp0(x.name, y.name) == 0);
}

fn fileIsNative(f: ?*c.GFile) callconv(.c) c.gboolean {
    _ = f;
    return 0;
}

fn fileHasScheme(f: ?*c.GFile, scheme: [*c]const u8) callconv(.c) c.gboolean {
    return @intFromBool(c.g_ascii_strcasecmp(schemeName(asSelf(f).scheme), scheme) == 0);
}

fn fileGetScheme(f: ?*c.GFile) callconv(.c) [*c]u8 {
    return c.g_strdup(schemeName(asSelf(f).scheme));
}

fn fileBasename(f: ?*c.GFile) callconv(.c) [*c]u8 {
    const s = asSelf(f);
    if (s.name == null) return c.g_strdup("/");
    const n = std.mem.span(s.name);
    return c.g_strdup(n[if (std.mem.lastIndexOfScalar(u8, n, '/')) |i| i + 1 else 0..].ptr);
}

fn fileGetPath(f: ?*c.GFile) callconv(.c) [*c]u8 {
    _ = f;
    return null;
}

fn fileUri(f: ?*c.GFile) callconv(.c) [*c]u8 {
    const s = asSelf(f);
    if (s.name == null) return c.g_strconcat(schemeName(s.scheme), ":///", @as([*c]const u8, null));
    // A leading slash marks a name that failed unescaping: it must not read as a path.
    const keep: [*c]const u8 = if (s.name[0] == '/') null else "/";
    const esc = c.g_uri_escape_string(s.name, keep, 1);
    defer c.g_free(esc);
    return c.g_strconcat(schemeName(s.scheme), ":///", esc, @as([*c]const u8, null));
}

fn fileParent(f: ?*c.GFile) callconv(.c) ?*c.GFile {
    const s = asSelf(f);
    if (s.name == null) return null;
    const n = std.mem.span(s.name);
    const at = std.mem.lastIndexOfScalar(u8, n, '/') orelse return newFile(s.scheme, null);
    if (at == 0) return newFile(s.scheme, null); // a name that failed unescaping
    const up = dupz(n[0..at]);
    defer c.g_free(up);
    return newFile(s.scheme, up);
}

fn filePrefixMatches(prefix: ?*c.GFile, f: ?*c.GFile) callconv(.c) c.gboolean {
    if (!isOurs(f)) return 0;
    const p = asSelf(prefix);
    const s = asSelf(f);
    if (p.scheme != s.scheme or s.name == null) return 0;
    if (p.name == null) return 1;
    const n = std.mem.span(s.name);
    const q = std.mem.span(p.name);
    return @intFromBool(n.len > q.len + 1 and n[q.len] == '/' and std.mem.startsWith(u8, n, q));
}

fn fileRelative(parent: ?*c.GFile, d: ?*c.GFile) callconv(.c) [*c]u8 {
    if (filePrefixMatches(parent, d) == 0) return null;
    const p = asSelf(parent);
    const n = std.mem.span(asSelf(d).name);
    return c.g_strdup(if (p.name == null) n.ptr else n[c.strlen(p.name) + 1 ..].ptr);
}

fn fileResolve(f: ?*c.GFile, rel: [*c]const u8) callconv(.c) ?*c.GFile {
    const s = asSelf(f);
    const r = std.mem.trim(u8, std.mem.span(rel), "/");
    if (r.len == 0 or std.mem.eql(u8, r, ".")) return newFile(s.scheme, s.name);
    if (s.name != null) {
        // A child must never alias its item: a name with a slash is read-only, and only
        // ever means what is really there.
        const rz = dupz(r);
        defer c.g_free(rz);
        const child = c.g_strconcat(s.name, "/", rz, @as([*c]const u8, null));
        defer c.g_free(child);
        return newFile(s.scheme, child);
    }
    const z = dupz(r);
    defer c.g_free(z);
    return newFile(s.scheme, z);
}

fn fileChildDisplay(f: ?*c.GFile, name: [*c]const u8, err: [*c][*c]c.GError) callconv(.c) ?*c.GFile {
    _ = f;
    _ = name;
    setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "not available here");
    return null;
}

fn fileEnumerate(
    f: ?*c.GFile,
    attributes: [*c]const u8,
    flags: c.GFileQueryInfoFlags,
    cancellable: [*c]c.GCancellable,
    err: [*c][*c]c.GError,
) callconv(.c) [*c]c.GFileEnumerator {
    _ = attributes;
    _ = flags;
    _ = cancellable;
    const s = asSelf(f);
    if (s.name != null and s.scheme != scheme_trash) {
        setError(err, c.G_IO_ERROR_NOT_DIRECTORY, "this item is no folder");
        return null;
    }
    var partial = false;
    const infos = fetchFrom(s.scheme, if (s.name != null) std.mem.span(s.name) else null, &partial, err) orelse return null;
    const raw = c.g_object_new(enum_type, "container", f, @as([*c]const u8, null));
    if (raw == null) {
        _ = c.g_ptr_array_free(infos, 1);
        setError(err, c.G_IO_ERROR_FAILED, "cannot create an enumerator");
        return null;
    }
    const e: *GungnirEnum = @ptrCast(@alignCast(raw));
    e.infos = infos;
    e.at = 0;
    e.partial = @intFromBool(partial);
    return @ptrCast(@alignCast(raw));
}

fn fileQueryInfo(
    f: ?*c.GFile,
    attributes: [*c]const u8,
    flags: c.GFileQueryInfoFlags,
    cancellable: [*c]c.GCancellable,
    err: [*c][*c]c.GError,
) callconv(.c) ?*c.GFileInfo {
    _ = attributes;
    _ = flags;
    _ = cancellable;
    const s = asSelf(f);
    if (s.name != null) return findInfo(s, err);
    const all = fetch(s.scheme, null, err) orelse return null;
    defer _ = c.g_ptr_array_free(all, 1);
    return rootInfo(s.scheme, all.*.len);
}

/// A local GFile for an item's payload, as a new reference.
fn targetFile(self: *GungnirFile, err: [*c][*c]c.GError) ?*c.GFile {
    const info = findInfo(self, err) orelse return null;
    defer c.g_object_unref(info);
    const uri = c.g_file_info_get_attribute_string(info, "standard::target-uri");
    if (uri == null) {
        setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "this item has no file behind it");
        return null;
    }
    const t = c.g_vfs_get_file_for_uri(c.g_vfs_get_local(), uri) orelse return null;
    if (targetBlocked(t, err)) {
        c.g_object_unref(t);
        return null;
    }
    return t;
}

/// One open of a target on its own thread. Two owners, the caller and the thread; once
/// the caller stops waiting, the thread cleans up whenever the kernel lets it go.
const OpenJob = struct {
    refs: std.atomic.Value(u32) = .init(2),
    file: *c.GFile,
    cancellable: [*c]c.GCancellable,
    lock: c.GMutex = undefined,
    cond: c.GCond = undefined,
    done: bool = false,
    abandoned: bool = false,
    stream: [*c]c.GFileInputStream = null,
    err: [*c]c.GError = null,

    fn unref(j: *OpenJob) void {
        if (j.refs.fetchSub(1, .acq_rel) != 1) return;
        c.g_object_unref(j.file);
        if (j.cancellable != null) c.g_object_unref(j.cancellable);
        c.g_mutex_clear(&j.lock);
        c.g_cond_clear(&j.cond);
        c.g_free(j);
    }
};

/// Open threads alive, stuck or not; past the bound, nothing more is tried. Counted before
/// the thread starts, so callers arriving together cannot all get past it.
var opens_running: std.atomic.Value(u32) = .init(0);
const opens_running_max = 32;
const open_timeout_us = 5 * std.time.us_per_s;

fn openThread(data: c.gpointer) callconv(.c) c.gpointer {
    const j: *OpenJob = @ptrCast(@alignCast(data));
    var e: [*c]c.GError = null;
    const s = c.g_file_read(j.file, j.cancellable, &e);
    c.g_mutex_lock(&j.lock);
    const abandoned = j.abandoned;
    j.done = true;
    if (!abandoned) {
        j.stream = s;
        j.err = e;
        c.g_cond_signal(&j.cond);
    }
    c.g_mutex_unlock(&j.lock);
    if (abandoned) {
        if (s != null) c.g_object_unref(s);
        if (e != null) c.g_error_free(e);
    }
    j.unref();
    _ = opens_running.fetchSub(1, .acq_rel);
    return null;
}

/// `g_file_read` with a deadline. It follows links, and any part of the way may be a
/// hung mount the health table cannot see from the path; a FIFO blocks too.
fn readBounded(t: *c.GFile, cancellable: [*c]c.GCancellable, err: [*c][*c]c.GError) [*c]c.GFileInputStream {
    if (opens_running.fetchAdd(1, .acq_rel) >= opens_running_max) {
        _ = opens_running.fetchSub(1, .acq_rel);
        setError(err, c.G_IO_ERROR_BUSY, "too many opens are stuck");
        return null;
    }
    const j: *OpenJob = @ptrCast(@alignCast(c.g_malloc0(@sizeOf(OpenJob))));
    j.* = .{ .file = @ptrCast(@alignCast(c.g_object_ref(t))), .cancellable = cancellable };
    if (cancellable != null) _ = c.g_object_ref(cancellable);
    c.g_mutex_init(&j.lock);
    c.g_cond_init(&j.cond);
    const th = c.g_thread_try_new("gungnir-open", openThread, j, err);
    if (th == null) {
        j.unref();
        j.unref();
        _ = opens_running.fetchSub(1, .acq_rel);
        return null;
    }
    c.g_thread_unref(th);
    const deadline = c.g_get_monotonic_time() + open_timeout_us;
    c.g_mutex_lock(&j.lock);
    while (!j.done) {
        if (c.g_cond_wait_until(&j.cond, &j.lock, deadline) == 0) break;
    }
    const finished = j.done;
    const s = j.stream;
    const e = j.err;
    if (!finished) j.abandoned = true;
    c.g_mutex_unlock(&j.lock);
    j.unref();
    if (!finished) {
        setError(err, c.G_IO_ERROR_TIMED_OUT, "the file did not open in time");
        return null;
    }
    if (e != null) {
        if (err != null) err.* = e else c.g_error_free(e);
    }
    return s;
}

/// A target on a mount known hung or gone is refused here, in memory, without even
/// spending a thread on it.
fn targetBlocked(t: *c.GFile, err: [*c][*c]c.GError) bool {
    const p = c.g_file_get_path(t);
    if (p == null) return false;
    defer c.g_free(p);
    if (!health.blocks(std.mem.span(p))) return false;
    setError(err, c.G_IO_ERROR_NOT_MOUNTED, "the file's mount is hung or gone (reported by the gungnird mount health monitor)");
    return true;
}

fn fileRead(f: ?*c.GFile, cancellable: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) [*c]c.GFileInputStream {
    const t = targetFile(asSelf(f), err) orelse return null;
    defer c.g_object_unref(t);
    retryUnclosed();
    // The place comes first: once a file is open, giving up on it means a close, and on a
    // hung FUSE mount a close can block for ever.
    if (streams_running.fetchAdd(1, .acq_rel) >= streams_running_max) {
        _ = streams_running.fetchSub(1, .acq_rel);
        setError(err, c.G_IO_ERROR_BUSY, "too many open files here are stuck");
        return null;
    }
    const inner = readBounded(t, cancellable, err);
    if (inner == null) {
        _ = streams_running.fetchSub(1, .acq_rel);
        return null;
    }
    return boundedStream(inner, err);
}

/// Inside a trashed folder: nothing there has a record of its own to act on.
fn inside(s: *GungnirFile, err: [*c][*c]c.GError) bool {
    const n = std.mem.span(s.name);
    if (n.len == 0 or n[0] == '/' or std.mem.indexOfScalar(u8, n, '/') == null) return false;
    setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "only a whole item can be changed; restore the folder first");
    return true;
}

fn fileDelete(f: ?*c.GFile, cancellable: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) c.gboolean {
    const s = asSelf(f);
    if (s.name == null) {
        setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "the root cannot be deleted");
        return 0;
    }
    if (inside(s, err)) return 0;
    const name = std.mem.span(s.name);
    var req: [ipc.payload_max]u8 = undefined;
    if (name.len + 3 > req.len) {
        setError(err, c.G_IO_ERROR_NOT_FOUND, "no such item");
        return 0;
    }
    req[0] = s.scheme;
    std.mem.writeInt(u16, req[1..3], @intCast(name.len), .little);
    @memcpy(req[3 .. 3 + name.len], name);
    var link: Link = undefined;
    if (!link.open(op_timeout_ms, err)) return 0;
    defer link.close();
    watch(&link, cancellable);
    var reply: ipc.Msg = undefined;
    _ = requestRetry(&link, msg_delete, req[0 .. 3 + name.len], &reply) catch |e| {
        failure(&reply, e, err);
        return 0;
    };
    return 1;
}

/// Moving an item out of the trash to a local path restores it: the daemon renames it
/// back (same file, so its metadata stays with it), never replacing anything.
/// G_FILE_COPY_OVERWRITE allows a replace, it does not ask for one: `gio move` sets it on
/// every move, and refusing it sent every such restore to GLib's copy-and-delete
/// fallback, a new file without the item's metadata (M9-F02). So the restore is always
/// tried; only when the destination is taken and OVERWRITE allows replacing it does this
/// answer NOT_SUPPORTED, leaving that explicit replace to GLib's fallback.
fn fileMove(
    src: ?*c.GFile,
    dest: ?*c.GFile,
    flags: c.GFileCopyFlags,
    cancellable: [*c]c.GCancellable,
    progress: c.GFileProgressCallback,
    progress_data: c.gpointer,
    err: [*c][*c]c.GError,
) callconv(.c) c.gboolean {
    _ = progress;
    _ = progress_data;
    const s = asSelf(src);
    if (s.scheme != scheme_trash or s.name == null) {
        setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "only a move out of the trash");
        return 0;
    }
    if (inside(s, err)) return 0;
    const path = c.g_file_get_path(dest);
    if (path == null) {
        setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "the destination is not a local file");
        return 0;
    }
    defer c.g_free(path);
    const name = std.mem.span(s.name);
    const to = std.mem.span(path);
    var req: [ipc.payload_max]u8 = undefined;
    if (name.len + to.len + 4 > req.len) {
        setError(err, c.G_IO_ERROR_FILENAME_TOO_LONG, "path too long");
        return 0;
    }
    std.mem.writeInt(u16, req[0..2], @intCast(name.len), .little);
    @memcpy(req[2 .. 2 + name.len], name);
    var at = 2 + name.len;
    std.mem.writeInt(u16, req[at..][0..2], @intCast(to.len), .little);
    at += 2;
    @memcpy(req[at .. at + to.len], to);
    var link: Link = undefined;
    if (!link.open(op_timeout_ms, err)) return 0;
    defer link.close();
    watch(&link, cancellable);
    var reply: ipc.Msg = undefined;
    _ = requestRetry(&link, msg_restore, req[0 .. at + to.len], &reply) catch |e| {
        var mine: [*c]c.GError = null;
        failure(&reply, e, &mine);
        if (flags & c.G_FILE_COPY_OVERWRITE != 0 and
            c.g_error_matches(mine, c.g_io_error_quark(), c.G_IO_ERROR_EXISTS) != 0)
        {
            c.g_error_free(mine);
            setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "the destination exists; replacing it is left to the copy fallback");
            return 0;
        }
        c.g_propagate_error(err, mine);
        return 0;
    };
    return 1;
}

// ---- a stream whose every call has a deadline ---------------------------------------

/// Reads and seeks stuck past this fail, and the stream with them. A mount that hangs
/// under an open file blocks in the kernel, where no cancel reaches.
const stream_timeout_us = 30 * std.time.us_per_s;
const stream_chunk = 1 << 20;
var streams_running: std.atomic.Value(u32) = .init(0);
const streams_running_max = 32;

const StreamOp = enum(c_int) { none, read, seek, info, close, exit };

/// Shared by a stream and its worker. Two owners; the worker's buffer outlives a caller
/// that gave up on it.
const StreamIo = struct {
    refs: std.atomic.Value(u32) = .init(2),
    inner: [*c]c.GFileInputStream,
    lock: c.GMutex = undefined,
    cond: c.GCond = undefined,
    op: StreamOp = .none,
    done: bool = false,
    /// A call gave up: the worker is stuck, or will find this and leave.
    dead: bool = false,
    closed: bool = false,
    buf: [*c]u8,
    count: usize = 0,
    offset: i64 = 0,
    whence: c.GSeekType = c.G_SEEK_SET,
    attrs: [*c]u8 = null,
    cancellable: [*c]c.GCancellable = null,
    got: isize = 0,
    info: ?*c.GFileInfo = null,
    err: [*c]c.GError = null,

    fn unref(j: *StreamIo) void {
        if (j.refs.fetchSub(1, .acq_rel) != 1) return;
        if (j.err != null) c.g_error_free(j.err);
        if (j.info != null) c.g_object_unref(j.info);
        if (j.cancellable != null) c.g_object_unref(j.cancellable);
        c.g_free(j.attrs);
        c.g_free(j.buf);
        c.g_mutex_clear(&j.lock);
        c.g_cond_clear(&j.cond);
        c.g_free(j);
    }
};

const GungnirStream = extern struct {
    parent: c.GFileInputStream,
    io: ?*anyopaque,
    pos: i64,
    timeout_us: i64,
    /// What the file behind it can do: asked once, before any worker exists.
    seekable: c.gboolean,
};

const GungnirStreamClass = extern struct {
    parent_class: c.GFileInputStreamClass,
};

fn streamWorker(data: c.gpointer) callconv(.c) c.gpointer {
    const j: *StreamIo = @ptrCast(@alignCast(data));
    const seekable: *c.GSeekable = @ptrCast(@alignCast(j.inner));
    const input: *c.GInputStream = @ptrCast(@alignCast(j.inner));
    c.g_mutex_lock(&j.lock);
    while (true) {
        while (j.op == .none and !j.dead) c.g_cond_wait(&j.cond, &j.lock);
        if (j.dead or j.op == .exit) break;
        const op = j.op;
        const k = j.cancellable;
        c.g_mutex_unlock(&j.lock);
        var e: [*c]c.GError = null;
        var got: isize = 0;
        var info: ?*c.GFileInfo = null;
        switch (op) {
            .read => got = c.g_input_stream_read(input, j.buf, j.count, k, &e),
            .seek => got = c.g_seekable_seek(seekable, j.offset, j.whence, k, &e),
            .info => info = c.g_file_input_stream_query_info(j.inner, j.attrs, k, &e),
            .close => got = c.g_input_stream_close(input, k, &e),
            else => {},
        }
        c.g_mutex_lock(&j.lock);
        j.got = got;
        j.info = info;
        j.err = e;
        j.done = true;
        j.op = .none;
        c.g_cond_signal(&j.cond);
        if (op == .close) break;
    }
    c.g_mutex_unlock(&j.lock);
    c.g_object_unref(j.inner);
    _ = streams_running.fetchSub(1, .acq_rel);
    j.unref();
    return null;
}

/// Run one call on the worker. False: it failed or timed out; `err` says so. On true the
/// results are in `j`, and the caller may read them until its next call.
fn streamCall(s: *GungnirStream, op: StreamOp, k: [*c]c.GCancellable, err: [*c][*c]c.GError, setup: anytype) bool {
    const j: *StreamIo = @ptrCast(@alignCast(s.io orelse {
        setError(err, c.G_IO_ERROR_CLOSED, "the stream is closed");
        return false;
    }));
    c.g_mutex_lock(&j.lock);
    defer c.g_mutex_unlock(&j.lock);
    if (j.dead or j.closed) {
        setError(err, c.G_IO_ERROR_TIMED_OUT, "the file stopped answering");
        return false;
    }
    if (j.cancellable != null) c.g_object_unref(j.cancellable);
    j.cancellable = if (k != null) @ptrCast(@alignCast(c.g_object_ref(k))) else null;
    if (j.err != null) {
        c.g_error_free(j.err);
        j.err = null;
    }
    if (j.info != null) {
        c.g_object_unref(j.info);
        j.info = null;
    }
    setup.apply(j);
    j.done = false;
    j.op = op;
    c.g_cond_signal(&j.cond);
    const deadline = c.g_get_monotonic_time() + s.timeout_us;
    while (!j.done) {
        // In slices: a cancel gets an answer even while the kernel does not.
        const slice = @min(deadline, c.g_get_monotonic_time() + 100 * std.time.us_per_ms);
        _ = c.g_cond_wait_until(&j.cond, &j.lock, slice);
        if (j.done) break;
        if (k != null and c.g_cancellable_is_cancelled(k) != 0) {
            j.dead = true;
            c.g_cond_signal(&j.cond);
            setError(err, c.G_IO_ERROR_CANCELLED, "cancelled");
            return false;
        }
        if (c.g_get_monotonic_time() >= deadline) {
            j.dead = true;
            c.g_cond_signal(&j.cond);
            setError(err, c.G_IO_ERROR_TIMED_OUT, "the file stopped answering");
            return false;
        }
    }
    if (j.err != null) {
        if (err != null) {
            err.* = j.err;
            j.err = null;
        }
        return false;
    }
    return true;
}

fn streamRead(i: [*c]c.GInputStream, buffer: ?*anyopaque, count: usize, k: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) isize {
    const s: *GungnirStream = @ptrCast(@alignCast(i));
    const n = @min(count, stream_chunk);
    if (!streamCall(s, .read, k, err, struct {
        n: usize,
        fn apply(a: @This(), j: *StreamIo) void {
            j.count = a.n;
        }
    }{ .n = n })) return -1;
    const j: *StreamIo = @ptrCast(@alignCast(s.io));
    const got = j.got;
    if (got > 0) {
        @memcpy(@as([*]u8, @ptrCast(buffer))[0..@intCast(got)], j.buf[0..@intCast(got)]);
        s.pos += got;
    }
    return got;
}

fn streamTell(f: [*c]c.GFileInputStream) callconv(.c) c.goffset {
    const s: *GungnirStream = @ptrCast(@alignCast(f));
    return s.pos;
}

fn streamCanSeek(f: [*c]c.GFileInputStream) callconv(.c) c.gboolean {
    const s: *GungnirStream = @ptrCast(@alignCast(f));
    return s.seekable;
}

fn streamSeek(f: [*c]c.GFileInputStream, offset: c.goffset, whence: c.GSeekType, k: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) c.gboolean {
    const s: *GungnirStream = @ptrCast(@alignCast(f));
    const Set = struct {
        off: i64,
        w: c.GSeekType,
        fn apply(a: @This(), j: *StreamIo) void {
            j.offset = a.off;
            j.whence = a.w;
        }
    };
    if (!streamCall(s, .seek, k, err, Set{ .off = offset, .w = whence })) return 0;
    const j: *StreamIo = @ptrCast(@alignCast(s.io));
    if (j.got == 0) return 0;
    // Where it landed: the file's end is only known to the file.
    const seekable: *c.GSeekable = @ptrCast(@alignCast(j.inner));
    s.pos = c.g_seekable_tell(seekable);
    return 1;
}

fn streamQueryInfo(f: [*c]c.GFileInputStream, attrs: [*c]const u8, k: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) ?*c.GFileInfo {
    const s: *GungnirStream = @ptrCast(@alignCast(f));
    const Set = struct {
        a: [*c]const u8,
        fn apply(x: @This(), j: *StreamIo) void {
            c.g_free(j.attrs);
            j.attrs = c.g_strdup(x.a);
        }
    };
    if (!streamCall(s, .info, k, err, Set{ .a = attrs })) return null;
    const j: *StreamIo = @ptrCast(@alignCast(s.io));
    const info = j.info;
    j.info = null;
    return info;
}

const NoSetup = struct {
    fn apply(_: @This(), _: *StreamIo) void {}
};

fn streamClose(i: [*c]c.GInputStream, k: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) c.gboolean {
    const s: *GungnirStream = @ptrCast(@alignCast(i));
    const io = s.io orelse return 1;
    const j: *StreamIo = @ptrCast(@alignCast(io));
    c.g_mutex_lock(&j.lock);
    const dead = j.dead;
    c.g_mutex_unlock(&j.lock);
    // Stuck: the worker closes what it holds, whenever the kernel lets it go.
    var ok = true;
    if (!dead) ok = streamCall(s, .close, k, err, NoSetup{});
    if (ok and !dead) {
        c.g_mutex_lock(&j.lock);
        j.closed = true;
        c.g_mutex_unlock(&j.lock);
    }
    return @intFromBool(ok or dead);
}

/// Dropped without a close: GInputStream's own dispose would close, and wait. Let the
/// worker do that instead, whenever the file lets it.
fn streamDispose(obj: [*c]c.GObject) callconv(.c) void {
    const s: *GungnirStream = @ptrCast(@alignCast(obj));
    if (s.io) |io| {
        const j: *StreamIo = @ptrCast(@alignCast(io));
        c.g_mutex_lock(&j.lock);
        if (j.op == .none and !j.dead and !j.closed) j.op = .exit;
        j.dead = true;
        c.g_cond_signal(&j.cond);
        c.g_mutex_unlock(&j.lock);
        j.unref();
        s.io = null;
    }
    const parent: *c.GObjectClass = @ptrCast(@alignCast(c.g_type_class_peek_parent(c.g_type_class_peek(stream_type))));
    if (parent.dispose) |d| d(obj);
}

fn streamClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    const k: *GungnirStreamClass = @ptrCast(@alignCast(g_class));
    k.parent_class.tell = &streamTell;
    k.parent_class.can_seek = &streamCanSeek;
    k.parent_class.seek = &streamSeek;
    k.parent_class.query_info = &streamQueryInfo;
    k.parent_class.parent_class.read_fn = &streamRead;
    k.parent_class.parent_class.close_fn = &streamClose;
    const o: *c.GObjectClass = @ptrCast(@alignCast(g_class));
    o.dispose = &streamDispose;
}

/// Opened files with no worker to close them, each still holding its place. A plain stream
/// would have no deadline, and closing one here could block the caller for ever.
var unclosed_lock: c.GMutex = std.mem.zeroes(c.GMutex);
var unclosed: ?*c.GPtrArray = null;

fn closeUnclosed(data: c.gpointer) callconv(.c) c.gpointer {
    _ = data;
    while (true) {
        c.g_mutex_lock(&unclosed_lock);
        const list = unclosed;
        const f: ?*c.GObject = if (list != null and list.?.*.len != 0)
            @ptrCast(@alignCast(c.g_ptr_array_steal_index_fast(list, list.?.*.len - 1)))
        else
            null;
        c.g_mutex_unlock(&unclosed_lock);
        const obj = f orelse return null;
        c.g_object_unref(obj);
        _ = streams_running.fetchSub(1, .acq_rel);
    }
}

/// Another try at closing those: thread creation failing is usually passing.
fn retryUnclosed() void {
    c.g_mutex_lock(&unclosed_lock);
    const any = unclosed != null and unclosed.?.*.len != 0;
    c.g_mutex_unlock(&unclosed_lock);
    if (!any) return;
    const th = c.g_thread_try_new("gungnir-close", closeUnclosed, null, null);
    if (th != null) c.g_thread_unref(th);
}

fn keepUnclosed(inner: [*c]c.GFileInputStream) void {
    c.g_mutex_lock(&unclosed_lock);
    defer c.g_mutex_unlock(&unclosed_lock);
    if (unclosed == null) unclosed = c.g_ptr_array_new();
    c.g_ptr_array_add(unclosed, inner);
}

/// Wrap an opened target, whose place in `streams_running` the caller holds. No stream
/// leaves here without its worker: without one the open fails and the file waits above.
fn boundedStream(inner: [*c]c.GFileInputStream, err: [*c][*c]c.GError) [*c]c.GFileInputStream {
    const raw = c.g_object_new(stream_type, null);
    if (raw == null) {
        keepUnclosed(inner);
        setError(err, c.G_IO_ERROR_BUSY, "no resources for a stream");
        return null;
    }
    const s: *GungnirStream = @ptrCast(@alignCast(raw));
    s.timeout_us = stream_timeout_us;
    s.seekable = c.g_seekable_can_seek(@ptrCast(@alignCast(inner)));
    // Test hook, compiled in only for the integration test's copy of the module (build
    // option `test_hooks`): the shipped library never reads it.
    if (build_options.test_hooks) {
        if (envValue("GUNGNIR_TEST_READ_TIMEOUT_MS")) |v| {
            if (std.fmt.parseInt(i64, v, 10)) |ms| {
                s.timeout_us = std.math.clamp(ms, 1, 3_600_000) * std.time.us_per_ms;
            } else |_| {}
        }
    }
    const j: *StreamIo = @ptrCast(@alignCast(c.g_malloc0(@sizeOf(StreamIo))));
    j.* = .{ .inner = inner, .buf = @ptrCast(c.g_malloc(stream_chunk)) };
    c.g_mutex_init(&j.lock);
    c.g_cond_init(&j.cond);
    const th = c.g_thread_try_new("gungnir-stream", streamWorker, j, null);
    if (th == null) {
        keepUnclosed(inner);
        j.unref();
        j.unref();
        c.g_object_unref(raw);
        setError(err, c.G_IO_ERROR_BUSY, "no thread for a stream");
        return null;
    }
    c.g_thread_unref(th);
    s.io = j;
    return @ptrCast(@alignCast(raw));
}

// ---- a monitor on a root ------------------------------------------------------------

const monitor_poll_ms = 2_000;
const monitor_slice_us = 100 * std.time.us_per_ms;
var monitors_running: std.atomic.Value(u32) = .init(0);
const monitors_running_max = 16;
const monitor_queue_max = 256;
const baseline_pending: u32 = 0;
const baseline_ready: u32 = 1;
/// The creator stopped waiting, so a view may have listed before the baseline.
const baseline_late: u32 = 2;
const baseline_wait_ui_us = 3 * std.time.us_per_ms;
const baseline_wait_us = 200 * std.time.us_per_ms;

/// Shared by a monitor and its thread, which holds no reference to the monitor: dropping
/// the last one is how a monitor ends.
const Watch = struct {
    refs: std.atomic.Value(u32) = .init(2),
    stop: std.atomic.Value(bool) = .init(false),
    /// Changes waiting for the creator's main context.
    queued: std.atomic.Value(u32) = .init(0),
    scheme: u8,
    /// Only the thread uses this, and it lets go on leaving: a queued change refers to the
    /// watch and sits in the context, so the watch must not keep the context alive.
    ctx: ?*c.GMainContext,
    weak: c.GWeakRef = undefined,
    /// How the first listing went: see `baseline_*`.
    baseline: std.atomic.Value(u32) = .init(baseline_pending),

    fn ref(w: *Watch) void {
        _ = w.refs.fetchAdd(1, .monotonic);
    }

    fn unref(w: *Watch) void {
        if (w.refs.fetchSub(1, .acq_rel) != 1) return;
        c.g_weak_ref_clear(&w.weak);
        c.g_free(w);
    }
};

const GungnirMonitor = extern struct {
    parent: c.GFileMonitor,
    watch: ?*anyopaque,
};

const GungnirMonitorClass = extern struct {
    parent_class: c.GFileMonitorClass,
};

const Change = struct {
    watch: *Watch,
    child: ?*c.GFile,
    event: c.GFileMonitorEvent,
};

fn changeRun(data: c.gpointer) callconv(.c) c.gboolean {
    const e: *Change = @ptrCast(@alignCast(data));
    const m = c.g_weak_ref_get(&e.watch.weak);
    if (m != null) {
        defer c.g_object_unref(m);
        c.g_file_monitor_emit_event(@ptrCast(@alignCast(m)), e.child, null, e.event);
    }
    return 0;
}

fn changeFree(data: c.gpointer) callconv(.c) void {
    const e: *Change = @ptrCast(@alignCast(data));
    if (e.child) |f| c.g_object_unref(f);
    _ = e.watch.queued.fetchSub(1, .acq_rel);
    e.watch.unref();
    c.g_free(e);
}

fn emitChange(w: *Watch, name: [*c]const u8, event: c.GFileMonitorEvent) void {
    const e: *Change = @ptrCast(@alignCast(c.g_malloc0(@sizeOf(Change))));
    w.ref();
    _ = w.queued.fetchAdd(1, .acq_rel);
    e.* = .{ .watch = w, .child = newFile(w.scheme, name), .event = event };
    // Always a source, never g_main_context_invoke: that may run it right here, on this
    // thread, and handlers belong on the creator's.
    const src = c.g_idle_source_new();
    c.g_source_set_priority(src, c.G_PRIORITY_DEFAULT);
    c.g_source_set_callback(src, &changeRun, e, &changeFree);
    _ = c.g_source_attach(src, w.ctx);
    c.g_source_unref(src);
}

fn stampOf(scheme: u8) ?u64 {
    var link: Link = undefined;
    if (!link.open(list_timeout_ms, null)) return null;
    defer link.close();
    var reply: ipc.Msg = undefined;
    const req = [1]u8{scheme};
    const body = requestRetry(&link, msg_stamp, &req, &reply) catch return null;
    if (body.len != 8) return null;
    return std.mem.readInt(u64, body[0..8], .little);
}

/// The names now, as a set of new strings; null when the daemon would not say.
fn namesNow(scheme: u8, partial: ?*bool) ?*c.GHashTable {
    const all = fetch(scheme, partial, null) orelse return null;
    defer _ = c.g_ptr_array_free(all, 1);
    const set = c.g_hash_table_new_full(&c.g_str_hash, &c.g_str_equal, &c.g_free, null) orelse return null;
    var i: c.guint = 0;
    while (i < all.*.len) : (i += 1) {
        const info: *c.GFileInfo = @ptrCast(@alignCast(all.*.pdata[i]));
        _ = c.g_hash_table_add(set, c.g_strdup(c.g_file_info_get_name(info)));
    }
    return set;
}

/// What the daemon says of `name`. Only "no such item" means gone.
fn lookup(scheme: u8, name: [*c]const u8) enum { there, gone, unknown } {
    const f = newFile(scheme, name) orelse return .unknown;
    defer c.g_object_unref(f);
    var e: [*c]c.GError = null;
    const info = findInfo(asSelf(f), &e);
    if (info != null) {
        c.g_object_unref(info);
        return .there;
    }
    defer if (e != null) c.g_error_free(e);
    if (e != null and c.g_error_matches(e, c.g_io_error_quark(), c.G_IO_ERROR_NOT_FOUND) != 0) return .gone;
    return .unknown;
}

fn watchSleep(w: *Watch) void {
    var left: i64 = monitor_poll_ms * std.time.us_per_ms;
    while (left > 0 and !w.stop.load(.acquire)) : (left -= monitor_slice_us) c.g_usleep(monitor_slice_us);
}

fn monitorThread(data: c.gpointer) callconv(.c) c.gpointer {
    const w: *Watch = @ptrCast(@alignCast(data));
    var last = stampOf(w.scheme);
    var fresh = namesNow(w.scheme, null);
    // Too late to be sure no view listed first, or no listing at all: start from nothing,
    // so the first round reports everything there is. A view ignores what it already has.
    const on_time = w.baseline.cmpxchgStrong(baseline_pending, baseline_ready, .acq_rel, .acquire) == null;
    if ((!on_time or fresh == null) and fresh != null) {
        c.g_hash_table_unref(fresh);
        fresh = null;
    }
    if (fresh == null) last = null;
    const known = fresh orelse c.g_hash_table_new_full(&c.g_str_hash, &c.g_str_equal, &c.g_free, null) orelse {
        _ = monitors_running.fetchSub(1, .acq_rel);
        if (w.ctx) |x| c.g_main_context_unref(x);
        w.ctx = null;
        w.unref();
        return null;
    };
    while (!w.stop.load(.acquire)) {
        if (last != null) watchSleep(w) else c.g_usleep(monitor_slice_us);
        if (w.stop.load(.acquire)) break;
        // Nobody is dispatching: the changes wait in the next round, not in memory.
        if (w.queued.load(.acquire) >= monitor_queue_max) {
            watchSleep(w);
            continue;
        }
        const now = stampOf(w.scheme) orelse {
            watchSleep(w);
            continue;
        };
        if (last != null and last.? == now) continue;
        var partial = false;
        const names = namesNow(w.scheme, &partial) orelse {
            watchSleep(w);
            continue;
        };
        defer c.g_hash_table_unref(names);
        // `known` follows what was really reported, so a round cut short by the queue
        // bound resumes where it stopped.
        var whole = true;
        var it: c.GHashTableIter = undefined;
        var key: c.gpointer = null;
        // Removals first: `known` only grows once it holds nothing that is gone, so it stays
        // the size of the real list however a round is cut short.
        // Missing from a list that may not be whole says nothing about being gone, so such
        // an item is asked about by name, a bounded number per round.
        var asked: u32 = 0;
        var unsure = false;
        c.g_hash_table_iter_init(&it, known);
        while (c.g_hash_table_iter_next(&it, &key, null) != 0) {
            if (c.g_hash_table_contains(names, key) != 0) continue;
            if (partial) {
                if (asked >= monitor_queue_max) {
                    unsure = true;
                    continue;
                }
                asked += 1;
                switch (lookup(w.scheme, @ptrCast(key))) {
                    .there => continue,
                    .unknown => {
                        unsure = true;
                        continue;
                    },
                    .gone => {},
                }
            }
            if (w.queued.load(.acquire) >= monitor_queue_max) {
                whole = false;
                break;
            }
            emitChange(w, @ptrCast(key), c.G_FILE_MONITOR_EVENT_DELETED);
            c.g_hash_table_iter_remove(&it);
        }
        if (whole) {
            c.g_hash_table_iter_init(&it, names);
            while (c.g_hash_table_iter_next(&it, &key, null) != 0) {
                if (c.g_hash_table_contains(known, key) != 0) continue;
                if (w.queued.load(.acquire) >= monitor_queue_max) {
                    whole = false;
                    break;
                }
                emitChange(w, @ptrCast(key), c.G_FILE_MONITOR_EVENT_CREATED);
                _ = c.g_hash_table_add(known, c.g_strdup(@ptrCast(key)));
            }
        }
        last = if (whole and !unsure) now else null;
        // Answers still owed: the next round is the normal one, not a tight loop.
        if (unsure) watchSleep(w);
    }
    c.g_hash_table_unref(known);
    if (w.ctx) |x| c.g_main_context_unref(x);
    w.ctx = null;
    _ = monitors_running.fetchSub(1, .acq_rel);
    w.unref();
    return null;
}

fn monitorCancel(m: [*c]c.GFileMonitor) callconv(.c) c.gboolean {
    const s: *GungnirMonitor = @ptrCast(@alignCast(m));
    if (s.watch) |p| {
        const w: *Watch = @ptrCast(@alignCast(p));
        w.stop.store(true, .release);
    }
    return 1;
}

fn monitorFinalize(obj: [*c]c.GObject) callconv(.c) void {
    const s: *GungnirMonitor = @ptrCast(@alignCast(obj));
    if (s.watch) |p| {
        const w: *Watch = @ptrCast(@alignCast(p));
        w.stop.store(true, .release);
        w.unref();
        s.watch = null;
    }
    const parent: *c.GObjectClass = @ptrCast(@alignCast(c.g_type_class_peek_parent(c.g_type_class_peek(monitor_type))));
    if (parent.finalize) |fin| fin(obj);
}

fn monitorClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    const k: *GungnirMonitorClass = @ptrCast(@alignCast(g_class));
    k.parent_class.cancel = &monitorCancel;
    const o: *c.GObjectClass = @ptrCast(@alignCast(g_class));
    o.finalize = &monitorFinalize;
}

fn fileMonitor(f: ?*c.GFile, flags: c.GFileMonitorFlags, cancellable: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) [*c]c.GFileMonitor {
    _ = flags;
    _ = cancellable;
    const s = asSelf(f);
    if (s.name != null) {
        setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "only the whole trash can be watched");
        return null;
    }
    if (monitors_running.fetchAdd(1, .acq_rel) >= monitors_running_max) {
        _ = monitors_running.fetchSub(1, .acq_rel);
        setError(err, c.G_IO_ERROR_BUSY, "too many monitors");
        return null;
    }
    // The thread runs this module's code: never unload it under one.
    _ = c.g_type_class_ref(monitor_type);
    const raw = c.g_object_new(monitor_type, null);
    if (raw == null) {
        _ = monitors_running.fetchSub(1, .acq_rel);
        setError(err, c.G_IO_ERROR_FAILED, "cannot create a monitor");
        return null;
    }
    const w: *Watch = @ptrCast(@alignCast(c.g_malloc0(@sizeOf(Watch))));
    w.* = .{ .scheme = s.scheme, .ctx = c.g_main_context_ref_thread_default() };
    c.g_weak_ref_init(&w.weak, raw);
    const th = c.g_thread_try_new("gungnir-monitor", monitorThread, w, err);
    if (th == null) {
        _ = monitors_running.fetchSub(1, .acq_rel);
        if (w.ctx) |x| c.g_main_context_unref(x);
        w.unref();
        w.unref();
        c.g_object_unref(raw);
        return null;
    }
    c.g_thread_unref(th);
    const m: *GungnirMonitor = @ptrCast(@alignCast(raw));
    m.watch = w;
    // A view usually lists right after this, and the baseline should come first. The wait
    // is short, on a UI thread very short: past it the thread makes up for it.
    const ui = c.g_main_context_is_owner(c.g_main_context_default()) != 0;
    const end = c.g_get_monotonic_time() + @as(i64, if (ui) baseline_wait_ui_us else baseline_wait_us);
    while (w.baseline.load(.acquire) == baseline_pending and c.g_get_monotonic_time() < end) c.g_usleep(500);
    _ = w.baseline.cmpxchgStrong(baseline_pending, baseline_late, .acq_rel, .acquire);
    return @ptrCast(@alignCast(raw));
}

fn fileIfaceInit(g_iface: c.gpointer, iface_data: c.gpointer) callconv(.c) void {
    _ = iface_data;
    const i: *c.GFileIface = @ptrCast(@alignCast(g_iface));
    i.dup = &fileDup;
    i.hash = &fileHash;
    i.equal = &fileEqual;
    i.is_native = &fileIsNative;
    i.has_uri_scheme = &fileHasScheme;
    i.get_uri_scheme = &fileGetScheme;
    i.get_basename = &fileBasename;
    i.get_path = &fileGetPath;
    i.get_uri = &fileUri;
    i.get_parse_name = &fileUri;
    i.get_parent = &fileParent;
    i.prefix_matches = &filePrefixMatches;
    i.get_relative_path = &fileRelative;
    i.resolve_relative_path = &fileResolve;
    i.get_child_for_display_name = &fileChildDisplay;
    i.enumerate_children = &fileEnumerate;
    i.query_info = &fileQueryInfo;
    i.read_fn = &fileRead;
    i.delete_file = &fileDelete;
    i.move = &fileMove;
    i.monitor_dir = &fileMonitor;
    i.monitor_file = &fileMonitor;
}

fn fileFinalize(obj: [*c]c.GObject) callconv(.c) void {
    const s: *GungnirFile = @ptrCast(@alignCast(obj));
    c.g_free(s.name);
    s.name = null;
    const parent: *c.GObjectClass = @ptrCast(@alignCast(c.g_type_class_peek_parent(c.g_type_class_peek(file_type))));
    if (parent.finalize) |fin| fin(obj);
}

fn fileClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    const k: *c.GObjectClass = @ptrCast(@alignCast(g_class));
    k.finalize = &fileFinalize;
}

fn enumNext(e: [*c]c.GFileEnumerator, cancellable: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) ?*c.GFileInfo {
    _ = cancellable;
    const s: *GungnirEnum = @ptrCast(@alignCast(e));
    const list = s.infos orelse return null;
    if (s.at >= list.*.len) {
        // GIO has no empty of its own: clients enumerate and delete. An ending without
        // complaint would tell them they got everything.
        if (s.partial != 0) {
            s.partial = 0;
            setError(err, c.G_IO_ERROR_FAILED, "not every item could be listed: too many, or a volume is hung");
        }
        return null;
    }
    const info: *c.GFileInfo = @ptrCast(@alignCast(list.*.pdata[s.at]));
    s.at += 1;
    _ = c.g_object_ref(info);
    return info;
}

fn enumClose(e: [*c]c.GFileEnumerator, cancellable: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) c.gboolean {
    _ = e;
    _ = cancellable;
    _ = err;
    return 1;
}

fn enumFinalize(obj: [*c]c.GObject) callconv(.c) void {
    const s: *GungnirEnum = @ptrCast(@alignCast(obj));
    if (s.infos) |l| _ = c.g_ptr_array_free(l, 1);
    s.infos = null;
    const parent: *c.GObjectClass = @ptrCast(@alignCast(c.g_type_class_peek_parent(c.g_type_class_peek(enum_type))));
    if (parent.finalize) |fin| fin(obj);
}

fn enumClassInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    const k: *GungnirEnumClass = @ptrCast(@alignCast(g_class));
    k.parent_class.next_file = &enumNext;
    k.parent_class.close_fn = &enumClose;
    const o: *c.GObjectClass = @ptrCast(@alignCast(g_class));
    o.finalize = &enumFinalize;
}

fn classFinalize(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = g_class;
    _ = class_data;
}

const file_type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirFileClass),
    .class_init = &fileClassInit,
    .class_finalize = &classFinalize,
    .instance_size = @sizeOf(GungnirFile),
};

const enum_type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirEnumClass),
    .class_init = &enumClassInit,
    .class_finalize = &classFinalize,
    .instance_size = @sizeOf(GungnirEnum),
};

const monitor_type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirMonitorClass),
    .class_init = &monitorClassInit,
    .class_finalize = &classFinalize,
    .instance_size = @sizeOf(GungnirMonitor),
};

const stream_type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirStreamClass),
    .class_init = &streamClassInit,
    .class_finalize = &classFinalize,
    .instance_size = @sizeOf(GungnirStream),
};

const file_iface_info = c.GInterfaceInfo{
    .interface_init = &fileIfaceInit,
    .interface_finalize = null,
    .interface_data = null,
};

pub fn register(module: *c.GTypeModule) void {
    file_type = c.g_type_module_register_type(module, c.g_object_get_type(), "GungnirFile", &file_type_info, 0);
    if (file_type != 0) {
        c.g_type_module_add_interface(module, file_type, c.g_file_get_type(), &file_iface_info);
    } else {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register GungnirFile");
    }
    enum_type = c.g_type_module_register_type(module, c.g_file_enumerator_get_type(), "GungnirFileEnumerator", &enum_type_info, 0);
    if (enum_type == 0) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register GungnirFileEnumerator");
    }
    monitor_type = c.g_type_module_register_type(module, c.g_file_monitor_get_type(), "GungnirFileMonitor", &monitor_type_info, 0);
    if (monitor_type == 0) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register GungnirFileMonitor");
    }
    stream_type = c.g_type_module_register_type(module, c.g_file_input_stream_get_type(), "GungnirFileStream", &stream_type_info, 0);
    if (stream_type == 0) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register GungnirFileStream");
    }
}

test "a bad reply never reads past the page" {
    var p: Parser = .{ .rest = &[_]u8{ 200, 0, 1 } };
    try std.testing.expect(p.row() == null);
    var q: Parser = .{ .rest = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    try std.testing.expect(q.row() == null);
}

test "a row parses" {
    const bytes = [_]u8{ 1, 0, 'n', 1, 0, 'o', 1, 0, 't', 0, 0, 0, 0, 2, 5, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0 };
    var p: Parser = .{ .rest = &bytes };
    const r = p.row().?;
    try std.testing.expectEqualStrings("n", r.name);
    try std.testing.expectEqual(@as(u8, 2), r.kind);
    try std.testing.expectEqual(@as(u64, 5), r.size);
    try std.testing.expectEqual(@as(i64, 9), r.mtime);
    try std.testing.expectEqual(@as(usize, 0), p.rest.len);
}

test "the last component of a path" {
    try std.testing.expectEqualStrings("b", lastComponent("/a/b"));
    try std.testing.expectEqualStrings("b", lastComponent("/a/b/"));
    try std.testing.expectEqualStrings("b", lastComponent("b"));
}

test "a target on a hung mount is refused in memory" {
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
    const bad = c.g_file_new_for_path("/hung-m/a") orelse return error.OutOfMemory;
    defer c.g_object_unref(bad);
    var err: [*c]c.GError = null;
    try std.testing.expect(targetBlocked(bad, &err));
    defer c.g_error_free(err);
    const fine = c.g_file_new_for_path("/elsewhere/a") orelse return error.OutOfMemory;
    defer c.g_object_unref(fine);
    try std.testing.expect(!targetBlocked(fine, null));
}

test "busy is waited out, within its bound, and nothing else is" {
    const Stub = struct {
        left: *u32,
        err: rpc.Error,
        fn run(a: @This()) rpc.Error![]const u8 {
            if (a.left.* == 0) return "ok";
            a.left.* -= 1;
            return a.err;
        }
    };
    var n: u32 = 3;
    try std.testing.expectEqualStrings("ok", try whileBusy(Stub{ .left = &n, .err = error.Busy }, 5, 1));
    n = 9;
    try std.testing.expectError(error.Busy, whileBusy(Stub{ .left = &n, .err = error.Busy }, 5, 1));
    try std.testing.expectEqual(@as(u32, 3), n);
    n = 2;
    try std.testing.expectError(error.Timeout, whileBusy(Stub{ .left = &n, .err = error.Timeout }, 5, 1));
    try std.testing.expectEqual(@as(u32, 1), n);
}
