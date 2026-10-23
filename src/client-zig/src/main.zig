const std = @import("std");
const c = @import("c"); // translated GIO headers, see build.zig
const ipc = @import("ipc.zig");

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

// ---- daemon connection (milestone 3) ----------------------------------------
// The first GungnirVfs instance starts one "gungnir-connect" GThread that connects to
// gungnird, exchanges hellos, maps the ring pair and round-trips a ping, all bounded by
// connect_timeout_ms. The GIO calling thread never touches the socket, so a missing or
// hung daemon cannot block it; every vfunc keeps delegating to the local VFS meanwhile.

/// Budget for connect + hello + ring setup + first ping, on the connector thread.
pub const connect_timeout_ms: u32 = 500;

/// Values of the read-only GungnirVfs:daemon-state property. Plain integers, not an
/// enum: the enum<->int builtins are being renamed on Zig master.
pub const state_connecting: c_int = 0;
pub const state_connected: c_int = 1;
pub const state_unavailable: c_int = 2;

var daemon_state: c_int = state_connecting;
var connector_started: u32 = 0;
var connector_thread: ?*c.GThread = null;
var daemon_conn: ?ipc.Conn = null;
var socket_path: ipc.SocketPath = .{};

fn setState(state: c_int) void {
    @atomicStore(c_int, &daemon_state, state, .release);
}

fn envValue(name: [*:0]const u8) ?[]const u8 {
    const v = c.g_getenv(name);
    return if (v == null) null else std.mem.span(v);
}

fn connectorMain(data: c.gpointer) callconv(.c) c.gpointer {
    _ = data;
    if (ipc.connectAndPing(&socket_path, connect_timeout_ms)) |conn| {
        daemon_conn = conn; // published by the release store in setState
        setState(state_connected);
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: daemon handshake ok on %s", &socket_path.buf);
    } else |err| {
        setState(state_unavailable);
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: daemon unavailable (%s), using the local VFS", @errorName(err).ptr);
    }
    return null;
}

/// Called from instance_init on the GIO calling thread: reads the environment (cheap,
/// never blocks), then hands everything else to the connector thread. Starts at most once.
fn startConnector() void {
    if (@cmpxchgStrong(u32, &connector_started, 0, 1, .acq_rel, .monotonic) != null) return;
    socket_path = ipc.resolveSocketPath(envValue("GUNGNIR_SOCKET"), envValue("XDG_RUNTIME_DIR"), envValue("HOME")) catch |err| {
        setState(state_unavailable);
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: no daemon socket path (%s)", @errorName(err).ptr);
        return;
    };
    var err: [*c]c.GError = null;
    connector_thread = c.g_thread_try_new("gungnir-connect", &connectorMain, null, &err);
    if (connector_thread == null) {
        setState(state_unavailable);
        if (err != null) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: cannot start connector thread: %s", err.*.message);
            c.g_error_free(err);
        }
    }
}

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

const prop_daemon_state: c.guint = 1;

fn getProperty(object: [*c]c.GObject, prop_id: c.guint, value: [*c]c.GValue, pspec: [*c]c.GParamSpec) callconv(.c) void {
    _ = object;
    _ = pspec;
    if (prop_id == prop_daemon_state) c.g_value_set_int(value, @atomicLoad(c_int, &daemon_state, .acquire));
}

fn instanceInit(instance: [*c]c.GTypeInstance, g_class: c.gpointer) callconv(.c) void {
    _ = instance;
    _ = g_class;
    startConnector();
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
    // Only reached once no GungnirVfs instance is alive. The join is bounded by
    // connect_timeout_ms, and the thread must not outlive the module's code.
    if (connector_thread) |t| _ = c.g_thread_join(t);
    connector_thread = null;
    if (daemon_conn) |*conn| conn.close();
    daemon_conn = null;
    setState(state_connecting);
    @atomicStore(u32, &connector_started, 0, .release);
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
}

test "daemon state starts as connecting" {
    try std.testing.expectEqual(state_connecting, @atomicLoad(c_int, &daemon_state, .acquire));
}

test "allocator-backed structures do not leak" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, "gungnir");
    try std.testing.expectEqual(@as(usize, 7), list.items.len);
}
