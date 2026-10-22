const std = @import("std");
const c = @import("c"); // translated GIO headers, see build.zig

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

/// NULL-terminated list of extension points this module implements.
const extension_points = [_][*c]const u8{ c.G_VFS_EXTENSION_POINT_NAME, null };

pub export fn g_io_module_load(module: *c.GIOModule) void {
    _ = module;
    // TODO: define the Gungnir GVfs subclass (extern struct vtables) and call
    // g_io_extension_point_implement(G_VFS_EXTENSION_POINT_NAME, type, "gungnir", prio).
}

pub export fn g_io_module_unload(module: *c.GIOModule) void {
    _ = module;
}

/// GIO takes ownership of the result and frees it with g_strfreev(),
/// so return a g_strdupv() copy, never the static array itself.
pub export fn g_io_module_query() [*c][*c]u8 {
    return c.g_strdupv(@constCast(@ptrCast(&extension_points)));
}

test "query lists gio-vfs" {
    const eps = g_io_module_query();
    defer c.g_strfreev(eps);
    try std.testing.expectEqualStrings("gio-vfs", std.mem.span(eps[0]));
    try std.testing.expect(eps[1] == null);
}

test "allocator-backed structures do not leak" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, "gungnir");
    try std.testing.expectEqual(@as(usize, 7), list.items.len);
}
