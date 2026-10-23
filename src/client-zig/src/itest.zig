//! Integration test, run as a child process by `zig build itest`:
//!   gungnir-itest <module-dir>            GIO_USE_VFS=gungnir: expect GungnirVfs
//!   gungnir-itest <module-dir> --no-opt-in GIO_USE_VFS unset:  expect GLocalVfs
//! <module-dir> contains only libgiogungnir.so and GIO_EXTRA_MODULES is unset, so no
//! system or user gvfs modules load.
const std = @import("std");
const c = @import("c");

fn fail(what: [*:0]const u8) c_int {
    c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest FAILED: %s", what);
    return 1;
}

/// Query standard::type and expect a directory. Frees everything it creates.
fn isDirectory(file: ?*c.GFile) bool {
    const f = file orelse return false;
    defer c.g_object_unref(f);
    var err: [*c]c.GError = null;
    const info = c.g_file_query_info(f, c.G_FILE_ATTRIBUTE_STANDARD_TYPE, c.G_FILE_QUERY_INFO_NONE, null, &err);
    if (info == null) {
        if (err != null) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: query_info: %s", err.*.message);
            c.g_error_free(err);
        }
        return false;
    }
    defer c.g_object_unref(info);
    return c.g_file_info_get_file_type(info) == c.G_FILE_TYPE_DIRECTORY;
}

pub export fn main(argc: c_int, argv: [*c][*c]u8) c_int {
    if (argc < 2 or argc > 3) return fail("usage: gungnir-itest <module-dir> [--no-opt-in]");
    const opt_in = argc == 2;
    if (!opt_in and !std.mem.eql(u8, std.mem.span(argv[2]), "--no-opt-in")) return fail("unknown flag");

    if (c.g_setenv("GIO_MODULE_DIR", argv[1], 1) == 0) return fail("g_setenv GIO_MODULE_DIR");
    // GIO also scans every dir in GIO_EXTRA_MODULES; an inherited value (Flatpak, Nix,
    // custom sessions) could load gvfs's GDaemonVfs (priority 10) and break --no-opt-in.
    c.g_unsetenv("GIO_EXTRA_MODULES");
    if (opt_in) {
        if (c.g_setenv("GIO_USE_VFS", "gungnir", 1) == 0) return fail("g_setenv GIO_USE_VFS");
    } else {
        c.g_unsetenv("GIO_USE_VFS");
    }

    const vfs = c.g_vfs_get_default();
    if (vfs == null) return fail("g_vfs_get_default returned NULL");
    const name = c.g_type_name_from_instance(@ptrCast(vfs));
    if (name == null) return fail("default VFS has no type name");
    const expected = if (opt_in) "GungnirVfs" else "GLocalVfs";
    if (!std.mem.eql(u8, std.mem.span(name), expected)) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: default VFS is %s, expected %s", name, expected.ptr);
        return fail("wrong default VFS");
    }
    if (c.g_vfs_is_active(vfs) == 0) return fail("default VFS is not active");

    if (!isDirectory(c.g_file_new_for_path("/"))) return fail("g_file_new_for_path(\"/\") is not a directory");
    if (!isDirectory(c.g_file_new_for_uri("file:///"))) return fail("g_file_new_for_uri(\"file:///\") is not a directory");
    if (!isDirectory(c.g_file_parse_name("/"))) return fail("g_file_parse_name(\"/\") is not a directory");

    const schemes = c.g_vfs_get_supported_uri_schemes(vfs);
    if (schemes == null or schemes[0] == null) return fail("no supported URI schemes");
    var has_file = false;
    var i: usize = 0;
    while (schemes[i] != null) : (i += 1) {
        const s = std.mem.span(schemes[i]);
        if (std.mem.eql(u8, s, "file")) has_file = true;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (std.mem.eql(u8, s, std.mem.span(schemes[j]))) return fail("duplicate URI scheme");
        }
    }
    if (!has_file) return fail("\"file\" is not a supported URI scheme");
    return 0;
}
