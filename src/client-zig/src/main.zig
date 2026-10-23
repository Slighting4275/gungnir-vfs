const std = @import("std");
const c = @import("c"); // translated GIO headers, see build.zig
const ipc = @import("ipc.zig");
const link = @import("link.zig");
/// Metadata client API (milestone 5).
pub const md = @import("md.zig");
/// GIO metadata::* attributes on top of it (milestone 6).
const gmeta = @import("gmeta.zig");
/// Mount health events from the daemon (milestone 7).
const health = @import("health.zig");

/// Root panic handler: log through GLib, then terminate the whole process.
pub const panic = std.debug.FullPanic(gungnirPanic);

/// Upper bound for the logged panic message. Clamping before the narrowing cast
/// makes the cast statically in range: no recursive panic, no negative precision.
const max_panic_msg_len = 4096;

fn gungnirPanic(msg: []const u8, first_trace_addr: ?usize) noreturn {
    _ = first_trace_addr;
    // g_critical() is a variadic C macro that translate-c cannot translate; call g_log directly.
    const len: c_int = @intCast(@min(msg.len, max_panic_msg_len));
    c.g_log(null, c.G_LOG_LEVEL_CRITICAL, "gungnir panic: %.*s", len, msg.ptr);
    std.os.linux.exit_group(1);
}

/// Extension name selected with GIO_USE_VFS=gungnir.
pub const extension_name = "gungnir";
pub const type_name = "GungnirVfs";

/// Below GLocalVfs ("local", 0) and gvfs's GDaemonVfs ("gvfs", 10): installing the
/// module never makes it the default VFS. It is only selected via GIO_USE_VFS=gungnir.
pub const vfs_priority: c.gint = -100;

/// NULL-terminated list of extension points this module implements.
const extension_points = [_][*c]const u8{ c.G_VFS_EXTENSION_POINT_NAME, null };

// ---- GungnirVfs: dynamic GVfs subclass --------------------------------------

// Daemon connection (milestone 3, shared by the metadata hooks since milestone 6): see
// link.zig. The vfuncs below keep delegating files to the local VFS whatever the daemon
// does; only the metadata::* hooks (gmeta.zig) talk to it, each within a short deadline.
pub const connect_timeout_ms = link.connect_timeout_ms;
pub const state_connecting = link.state_connecting;
pub const state_connected = link.state_connected;
pub const state_unavailable = link.state_unavailable;

/// Instance struct. No private state yet.
const GungnirVfs = extern struct {
    parent_instance: c.GVfs,
};

/// Class struct. `parent_class` is the translated `GVfsClass`, an extern struct
/// whose vfunc slots are typed C-ABI function pointers (no *anyopaque vtables).
const GungnirVfsClass = extern struct {
    parent_class: c.GVfsClass,
};

var gungnir_vfs_type: c.GType = 0;

fn isActive(vfs: [*c]c.GVfs) callconv(.c) c.gboolean {
    _ = vfs;
    return 1;
}

// The delegating vfuncs forward to the process-wide GLocalVfs singleton, never to
// g_vfs_get_default() (which is GungnirVfs itself and would recurse).

fn getFileForPath(vfs: [*c]c.GVfs, path: [*c]const u8) callconv(.c) ?*c.GFile {
    _ = vfs;
    return c.g_vfs_get_file_for_path(c.g_vfs_get_local(), path);
}

fn getFileForUri(vfs: [*c]c.GVfs, uri: [*c]const u8) callconv(.c) ?*c.GFile {
    _ = vfs;
    return c.g_vfs_get_file_for_uri(c.g_vfs_get_local(), uri);
}

/// Static class-level scheme list, the same as GLocalVfs's own vfunc. GVfs adds the
/// schemes registered on *this* instance (e.g. "resource") and caches the element
/// pointers, so this must not be g_vfs_get_supported_uri_schemes(local): those strings
/// are owned by the local VFS's scheme table and freed on unregister (use-after-free),
/// and "resource" would be listed twice.
const supported_uri_schemes = [_][*c]const c.gchar{ "file", null };

fn getSupportedUriSchemes(vfs: [*c]c.GVfs) callconv(.c) [*c]const [*c]const c.gchar {
    _ = vfs;
    return &supported_uri_schemes;
}

fn parseName(vfs: [*c]c.GVfs, parse_name: [*c]const u8) callconv(.c) ?*c.GFile {
    _ = vfs;
    return c.g_vfs_parse_name(c.g_vfs_get_local(), parse_name);
}

// The private GVfsClass hooks GLocalFile calls on the default VFS (glocalfileinfo.c,
// glocalfile.c; the same ones gvfs's GDaemonVfs implements). Only called while
// GungnirVfs is the default VFS, i.e. with GIO_USE_VFS=gungnir.

/// Allocator for the hooks' own temporaries (GLib copies whatever it keeps).
const hook_gpa = std.heap.c_allocator;

fn localFileAddInfo(
    vfs: [*c]c.GVfs,
    filename: [*c]const u8,
    device: c.guint64,
    matcher: ?*c.GFileAttributeMatcher,
    info: ?*c.GFileInfo,
    cancellable: [*c]c.GCancellable,
    extra_data: [*c]c.gpointer,
    free_extra_data: [*c]c.GDestroyNotify,
) callconv(.c) void {
    _ = vfs;
    _ = device;
    _ = cancellable;
    _ = extra_data; // per-directory cache slot during enumeration; unused
    _ = free_extra_data;
    gmeta.addInfo(hook_gpa, filename, matcher, info);
}

fn addWritableNamespaces(vfs: [*c]c.GVfs, list: [*c]c.GFileAttributeInfoList) callconv(.c) void {
    _ = vfs;
    gmeta.addWritableNamespaces(list);
}

fn localFileSetAttributes(
    vfs: [*c]c.GVfs,
    filename: [*c]const u8,
    info: ?*c.GFileInfo,
    flags: c.GFileQueryInfoFlags,
    cancellable: [*c]c.GCancellable,
    err: [*c][*c]c.GError,
) callconv(.c) c.gboolean {
    _ = vfs;
    _ = flags; // a symlink is always identified as itself (as gvfs keys it by its path)
    return gmeta.setAttributes(filename, info, cancellable, err);
}

fn localFileRemoved(vfs: [*c]c.GVfs, filename: [*c]const u8) callconv(.c) void {
    _ = vfs;
    gmeta.fileRemoved(filename);
}

fn localFileMoved(vfs: [*c]c.GVfs, source: [*c]const u8, dest: [*c]const u8) callconv(.c) void {
    _ = vfs;
    gmeta.fileMoved(source, dest);
}

const prop_daemon_state: c.guint = 1;
const prop_unhealthy_mounts: c.guint = 2;

fn getProperty(object: [*c]c.GObject, prop_id: c.guint, value: [*c]c.GValue, pspec: [*c]c.GParamSpec) callconv(.c) void {
    _ = object;
    _ = pspec;
    if (prop_id == prop_daemon_state) c.g_value_set_int(value, link.state());
    if (prop_id == prop_unhealthy_mounts) c.g_value_set_int(value, health.unhealthyCount());
}

fn instanceInit(instance: [*c]c.GTypeInstance, g_class: c.gpointer) callconv(.c) void {
    _ = instance;
    _ = g_class;
    link.start();
}

fn classInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    // GObject passes every class_init an untyped class pointer; it is our class struct.
    const klass: *GungnirVfsClass = @ptrCast(@alignCast(g_class));
    const vfs_class: *c.GVfsClass = &klass.parent_class;
    vfs_class.is_active = &isActive;
    vfs_class.get_file_for_path = &getFileForPath;
    vfs_class.get_file_for_uri = &getFileForUri;
    vfs_class.get_supported_uri_schemes = &getSupportedUriSchemes;
    vfs_class.parse_name = &parseName;
    vfs_class.local_file_add_info = &localFileAddInfo;
    vfs_class.add_writable_namespaces = &addWritableNamespaces;
    vfs_class.local_file_set_attributes = &localFileSetAttributes;
    vfs_class.local_file_removed = &localFileRemoved;
    vfs_class.local_file_moved = &localFileMoved;
    const object_class: *c.GObjectClass = &vfs_class.parent_class;
    object_class.get_property = &getProperty;
    c.g_object_class_install_property(object_class, prop_daemon_state, c.g_param_spec_int(
        "daemon-state",
        "Daemon state",
        "0 connecting, 1 connected (ping ok), 2 unavailable (local VFS only)",
        state_connecting,
        state_unavailable,
        state_connecting,
        c.G_PARAM_READABLE | c.G_PARAM_STATIC_STRINGS,
    ));
    c.g_object_class_install_property(object_class, prop_unhealthy_mounts, c.g_param_spec_int(
        "unhealthy-mounts",
        "Unhealthy mounts",
        "Mounts gungnird last reported hung or gone (calls on them fail fast)",
        0,
        health.max_entries,
        0,
        c.G_PARAM_READABLE | c.G_PARAM_STATIC_STRINGS,
    ));
}

fn classFinalize(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = g_class;
    _ = class_data;
}

const type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirVfsClass),
    .class_init = &classInit,
    .class_finalize = &classFinalize,
    .instance_size = @sizeOf(GungnirVfs),
    .instance_init = &instanceInit,
};

comptime {
    // GTypeInfo stores sizes as guint16.
    std.debug.assert(@sizeOf(GungnirVfsClass) <= std.math.maxInt(u16));
    std.debug.assert(@sizeOf(GungnirVfs) <= std.math.maxInt(u16));
}

// ---- GIO module entry points ------------------------------------------------

pub export fn g_io_module_load(module: *c.GIOModule) void {
    // GIOModule is a GTypeModule subclass. Registering through it makes GungnirVfs a
    // dynamic type that GObject re-attaches when the module is unloaded and reloaded.
    const type_module: *c.GTypeModule = @ptrCast(@alignCast(module));
    gungnir_vfs_type = c.g_type_module_register_type(type_module, c.g_vfs_get_type(), type_name, &type_info, 0);
    if (gungnir_vfs_type == 0) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register %s", type_name.ptr);
        return;
    }
    _ = c.g_io_extension_point_implement(c.G_VFS_EXTENSION_POINT_NAME, gungnir_vfs_type, extension_name, vfs_priority);
}

pub export fn g_io_module_unload(module: *c.GIOModule) void {
    _ = module;
    link.shutdown();
}

/// GIO takes ownership of the result and frees it with g_strfreev(),
/// so return a g_strdupv() copy, never the static array itself.
pub export fn g_io_module_query() [*c][*c]u8 {
    return c.g_strdupv(@ptrCast(@constCast(&extension_points)));
}

test "query lists gio-vfs" {
    const eps = g_io_module_query();
    defer c.g_strfreev(eps);
    try std.testing.expectEqualStrings("gio-vfs", std.mem.span(eps[0]));
    try std.testing.expect(eps[1] == null);
}

test "priority stays below local (0) and gvfs (10)" {
    try std.testing.expect(vfs_priority < 0);
}

test {
    _ = ipc;
    _ = md;
    _ = link;
    _ = gmeta;
    _ = health;
}

test "daemon state starts as connecting" {
    try std.testing.expectEqual(state_connecting, link.state());
}

test "allocator-backed structures do not leak" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, "gungnir");
    try std.testing.expectEqual(@as(usize, 7), list.items.len);
}
