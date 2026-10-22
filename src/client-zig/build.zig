const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // @cImport is gone on Zig master: translate the GIO headers in the build graph.
    // The one-line umbrella header is generated here, not committed as a .h file.
    const header = b.addWriteFiles().add("gungnir_c.h", "#include <gio/gio.h>\n");
    const translate = b.addTranslateC(.{
        .root_source_file = header,
        .target = target,
        .optimize = optimize,
    });
    translate.linkSystemLibrary("gio-2.0", .{}); // include paths + link flags via pkg-config

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("c", translate.createModule());
    mod.linkSystemLibrary("gio-2.0", .{});

    const lib = b.addLibrary(.{
        .name = "giogungnir", // -> libgiogungnir.so
        .linkage = .dynamic,
        .root_module = mod,
    });
    // No C sources are compiled, so the UBSan runtime is dead weight; bundling it
    // also exports ~34 weak __ubsan_handle_* symbols from a library dlopen()ed into GTK hosts.
    lib.bundle_ubsan_rt = false;
    b.installArtifact(lib);

    const tests = b.addTest(.{ .root_module = mod });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
