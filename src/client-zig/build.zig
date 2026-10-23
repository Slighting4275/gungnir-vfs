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
    const c_mod = translate.createModule();

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("c", c_mod);
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

    const unit_tests = b.addTest(.{ .root_module = mod });
    const run_unit = b.addRunArtifact(unit_tests);

    // Integration test: a child process loads the built .so through GIO from a
    // module dir that contains only this module, with GIO_USE_VFS=gungnir.
    const itest_exe = b.addExecutable(.{
        .name = "gungnir-itest",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/itest.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "c", .module = c_mod }},
        }),
    });
    itest_exe.root_module.linkSystemLibrary("gio-2.0", .{});
    itest_exe.bundle_ubsan_rt = false;
    const module_dir = b.addWriteFiles();
    _ = module_dir.addCopyFile(lib.getEmittedBin(), "libgiogungnir.so");
    const run_itest = b.addRunArtifact(itest_exe);
    run_itest.addDirectoryArg(module_dir.getDirectory());
    run_itest.expectExitCode(0);
    // Without GIO_USE_VFS the module must NOT become the default (priority below "local").
    const run_itest_default = b.addRunArtifact(itest_exe);
    run_itest_default.addDirectoryArg(module_dir.getDirectory());
    run_itest_default.addArg("--no-opt-in");
    run_itest_default.expectExitCode(0);
    const itest = b.step("itest", "Load libgiogungnir.so through GIO and check GungnirVfs");
    itest.dependOn(&run_itest.step);
    itest.dependOn(&run_itest_default.step);

    const test_step = b.step("test", "Run unit and integration tests");
    test_step.dependOn(&run_unit.step);
    test_step.dependOn(itest);
}
