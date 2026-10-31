//! `trash:///` and `recent:///` as GFiles (milestone 9), served by gungnird
//! (`src/daemon-rust/src/vfssvc.rs` is the other half of the protocol).
//!
//! A `GungnirFile` is the root of a scheme or one item in it. Every call opens its own
//! connection, so a long empty or delete never holds the shared metadata link, and every
//! wait is bounded. These are GIO's blocking calls, made on the caller's thread: file
//! managers run them on worker threads. A daemon that is not there gives
//! `G_IO_ERROR_NOT_SUPPORTED`, never a hang.
//!
//! Known limits: no change monitoring (a view of the trash does not refresh by itself),
//! and the folders inside a trashed folder are not browsable through `trash:///`.

const std = @import("std");
const c = @import("c");
const ipc = @import("ipc.zig");
const md = @import("md.zig");

const msg_list: u32 = 40;
const msg_delete: u32 = 41;
const msg_restore: u32 = 42;

const scheme_trash: u8 = 0;
const scheme_recent: u8 = 1;

const st_cancelled: u32 = 14;
const st_os_error: u32 = 15;
const st_would_recurse: u32 = 16;
const st_mount_inside: u32 = 17;
const st_not_empty: u32 = 18;

const kind_file: u8 = 1;
const kind_dir: u8 = 2;
const kind_symlink: u8 = 3;

const connect_timeout_ms = 500;
const list_timeout_ms = 5_000;
/// Longer than the daemon's own bound on one item, so its answer is what the caller sees.
const op_timeout_ms = 65_000;

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
};

const GungnirEnumClass = extern struct {
    parent_class: c.GFileEnumeratorClass,
};

var file_type: c.GType = 0;
var enum_type: c.GType = 0;

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
    if (z == null) return newFile(scheme, null);
    defer c.g_free(z);
    return newFile(scheme, z);
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
    client: md.Client,

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
fn failure(cl: *const md.Client, reply: *ipc.Msg, e: md.Error, err: [*c][*c]c.GError) void {
    switch (e) {
        error.Busy => setError(err, c.G_IO_ERROR_BUSY, "gungnird is busy; try again"),
        error.Timeout => setError(err, c.G_IO_ERROR_TIMED_OUT, "gungnird did not answer in time"),
        error.SuspectMount => setError(err, c.G_IO_ERROR_TIMED_OUT, "a volume is hung or gone (reported by the gungnird mount health monitor)"),
        error.NotFound, error.NoSuchFile => setError(err, c.G_IO_ERROR_NOT_FOUND, "no such item"),
        error.BadRequest => setError(err, c.G_IO_ERROR_INVALID_ARGUMENT, "not a valid item"),
        error.Unsupported => setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "this gungnird has no trash service"),
        error.Protocol => switch (cl.last_status) {
            st_mount_inside => setError(err, c.G_IO_ERROR_BUSY, "contains a mounted filesystem; unmount it and try again"),
            st_not_empty => setError(err, c.G_IO_ERROR_NOT_EMPTY, "some items remain"),
            st_cancelled => setError(err, c.G_IO_ERROR_CANCELLED, "cancelled"),
            st_would_recurse => setError(err, c.G_IO_ERROR_WOULD_RECURSE, "a folder cannot be restored to another filesystem this way"),
            st_os_error => {
                const p = reply.payload();
                const errno: c_int = if (p.len >= 8) std.mem.readInt(i32, p[4..8], .little) else 5;
                setError(err, @intCast(c.g_io_error_from_errno(errno)), c.g_strerror(errno));
            },
            else => setError(err, c.G_IO_ERROR_FAILED, "bad reply from gungnird"),
        },
        else => setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "gungnird is not available"),
    }
}

/// One listed entry, slices of a reply.
const Row = struct {
    name: []const u8,
    orig: []const u8,
    target: []const u8,
    deleted: []const u8,
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
        if (p.rest.len < 17) return null;
        const r: Row = .{
            .name = name,
            .orig = orig,
            .target = target,
            .deleted = deleted,
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
    const name = dupz(r.name);
    defer c.g_free(name);
    c.g_file_info_set_name(info, name);

    // What the user sees: the original name; for a degraded item, the entry's.
    const shown = dupz(blk: {
        if (r.orig.len != 0) break :blk lastComponent(r.orig);
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
        kind_file => c.G_FILE_TYPE_REGULAR,
        kind_dir => c.G_FILE_TYPE_DIRECTORY,
        kind_symlink => c.G_FILE_TYPE_SYMBOLIC_LINK,
        else => c.G_FILE_TYPE_SPECIAL,
    };
    c.g_file_info_set_file_type(info, file_kind);
    c.g_file_info_set_size(info, @intCast(@min(r.size, std.math.maxInt(i64))));
    c.g_file_info_set_attribute_uint64(info, "time::modified", @intCast(@max(r.mtime, 0)));
    c.g_file_info_set_attribute_boolean(info, "access::can-delete", 1);
    setCommon(info);
    if (r.kind == kind_symlink) c.g_file_info_set_is_symlink(info, 1);

    if (r.kind == kind_dir) {
        c.g_file_info_set_content_type(info, "inode/directory");
    } else {
        const guess = c.g_content_type_guess(show_raw, null, 0, null);
        defer c.g_free(guess);
        c.g_file_info_set_content_type(info, guess);
    }
    if (r.target.len != 0) {
        const tz = dupz(r.target);
        defer c.g_free(tz);
        const uri = c.g_filename_to_uri(tz, null, null);
        defer c.g_free(uri);
        if (uri != null) c.g_file_info_set_attribute_string(info, "standard::target-uri", uri);
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
fn fetch(scheme: u8, err: [*c][*c]c.GError) ?*c.GPtrArray {
    var link: Link = undefined;
    if (!link.open(list_timeout_ms, err)) return null;
    defer link.close();
    const out: *c.GPtrArray = c.g_ptr_array_new_with_free_func(&c.g_object_unref) orelse return null;
    var cursor: u32 = 0;
    while (true) {
        var req: [5]u8 = undefined;
        req[0] = scheme;
        std.mem.writeInt(u32, req[1..5], cursor, .little);
        var reply: ipc.Msg = undefined;
        const body = link.client.request(msg_list, &req, &reply) catch |e| {
            failure(&link.client, &reply, e, err);
            _ = c.g_ptr_array_free(out, 1);
            return null;
        };
        if (body.len < 6) {
            setError(err, c.G_IO_ERROR_FAILED, "bad reply from gungnird");
            _ = c.g_ptr_array_free(out, 1);
            return null;
        }
        const next = std.mem.readInt(u32, body[0..4], .little);
        const count = std.mem.readInt(u16, body[4..6], .little);
        var p: Parser = .{ .rest = body[6..] };
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
    c.g_file_info_set_size(info, 0);
    setCommon(info);
    c.g_file_info_set_attribute_boolean(info, "access::can-delete", 0);
    if (scheme == scheme_trash) c.g_file_info_set_attribute_uint32(info, "trash::item-count", count);
    return info;
}

/// One item's info, as a new reference.
fn findInfo(self: *GungnirFile, err: [*c][*c]c.GError) ?*c.GFileInfo {
    const all = fetch(self.scheme, err) orelse return null;
    defer _ = c.g_ptr_array_free(all, 1);
    var i: c.guint = 0;
    while (i < all.*.len) : (i += 1) {
        const info: *c.GFileInfo = @ptrCast(@alignCast(all.*.pdata[i]));
        if (c.g_strcmp0(c.g_file_info_get_name(info), self.name) == 0) {
            _ = c.g_object_ref(info);
            return info;
        }
    }
    setError(err, c.G_IO_ERROR_NOT_FOUND, "no such item");
    return null;
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
    return c.g_strdup(if (s.name != null) s.name else "/");
}

fn fileGetPath(f: ?*c.GFile) callconv(.c) [*c]u8 {
    _ = f;
    return null;
}

fn fileUri(f: ?*c.GFile) callconv(.c) [*c]u8 {
    const s = asSelf(f);
    if (s.name == null) return c.g_strconcat(schemeName(s.scheme), ":///", @as([*c]const u8, null));
    const esc = c.g_uri_escape_string(s.name, null, 1);
    defer c.g_free(esc);
    return c.g_strconcat(schemeName(s.scheme), ":///", esc, @as([*c]const u8, null));
}

fn fileParent(f: ?*c.GFile) callconv(.c) ?*c.GFile {
    const s = asSelf(f);
    return if (s.name != null) newFile(s.scheme, null) else null;
}

fn filePrefixMatches(prefix: ?*c.GFile, f: ?*c.GFile) callconv(.c) c.gboolean {
    if (!isOurs(f)) return 0;
    const p = asSelf(prefix);
    const s = asSelf(f);
    return @intFromBool(p.scheme == s.scheme and p.name == null and s.name != null);
}

fn fileRelative(parent: ?*c.GFile, d: ?*c.GFile) callconv(.c) [*c]u8 {
    if (filePrefixMatches(parent, d) == 0) return null;
    return c.g_strdup(asSelf(d).name);
}

fn fileResolve(f: ?*c.GFile, rel: [*c]const u8) callconv(.c) ?*c.GFile {
    const s = asSelf(f);
    const r = std.mem.trim(u8, std.mem.span(rel), "/");
    if (r.len == 0 or std.mem.eql(u8, r, ".")) return newFile(s.scheme, s.name);
    if (s.name != null) return newFile(s.scheme, s.name); // no browsing inside an item
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
    if (s.name != null) {
        setError(err, c.G_IO_ERROR_NOT_DIRECTORY, "folders inside the trash cannot be browsed");
        return null;
    }
    const infos = fetch(s.scheme, err) orelse return null;
    const raw = c.g_object_new(enum_type, "container", f, @as([*c]const u8, null));
    if (raw == null) {
        _ = c.g_ptr_array_free(infos, 1);
        setError(err, c.G_IO_ERROR_FAILED, "cannot create an enumerator");
        return null;
    }
    const e: *GungnirEnum = @ptrCast(@alignCast(raw));
    e.infos = infos;
    e.at = 0;
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
    const all = fetch(s.scheme, err) orelse return null;
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
    return c.g_vfs_get_file_for_uri(c.g_vfs_get_local(), uri);
}

fn fileRead(f: ?*c.GFile, cancellable: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) [*c]c.GFileInputStream {
    const t = targetFile(asSelf(f), err) orelse return null;
    defer c.g_object_unref(t);
    return c.g_file_read(t, cancellable, err);
}

fn fileDelete(f: ?*c.GFile, cancellable: [*c]c.GCancellable, err: [*c][*c]c.GError) callconv(.c) c.gboolean {
    _ = cancellable;
    const s = asSelf(f);
    if (s.name == null) {
        setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "the root cannot be deleted");
        return 0;
    }
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
    var reply: ipc.Msg = undefined;
    _ = link.client.request(msg_delete, req[0 .. 3 + name.len], &reply) catch |e| {
        failure(&link.client, &reply, e, err);
        return 0;
    };
    return 1;
}

/// Moving an item out of the trash to a local path restores it.
fn fileMove(
    src: ?*c.GFile,
    dest: ?*c.GFile,
    flags: c.GFileCopyFlags,
    cancellable: [*c]c.GCancellable,
    progress: c.GFileProgressCallback,
    progress_data: c.gpointer,
    err: [*c][*c]c.GError,
) callconv(.c) c.gboolean {
    _ = cancellable;
    _ = progress;
    _ = progress_data;
    const s = asSelf(src);
    if (s.scheme != scheme_trash or s.name == null or flags & c.G_FILE_COPY_OVERWRITE != 0) {
        setError(err, c.G_IO_ERROR_NOT_SUPPORTED, "only a move out of the trash, without overwriting");
        return 0;
    }
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
    var reply: ipc.Msg = undefined;
    _ = link.client.request(msg_restore, req[0 .. at + to.len], &reply) catch |e| {
        failure(&link.client, &reply, e, err);
        return 0;
    };
    return 1;
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
    _ = err;
    const s: *GungnirEnum = @ptrCast(@alignCast(e));
    const list = s.infos orelse return null;
    if (s.at >= list.*.len) return null;
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
}

test "a bad reply never reads past the page" {
    var p: Parser = .{ .rest = &[_]u8{ 200, 0, 1 } };
    try std.testing.expect(p.row() == null);
    var q: Parser = .{ .rest = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    try std.testing.expect(q.row() == null);
}

test "a row parses" {
    const bytes = [_]u8{ 1, 0, 'n', 1, 0, 'o', 1, 0, 't', 0, 0, 2, 5, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0 };
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
