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

    // Sockets and test databases live in the repo's .build/tmp (AGENTS.md §3), each itest
    // run in a fresh private (0700) directory of its own that itest.zig creates there.
    const repo_tmp = b.path("../../.build/tmp");
    // The daemon test starts the real gungnird with the test-hooks feature (hung-mount sets
    // GUNGNIR_TEST_FAKE_HUNG_MOUNT, milestone 7), built by cargo into its own target dir,
    // .build/target-hooks: never over the release gungnird in .build/target.
    const cargo_build = b.addSystemCommand(&.{ "cargo", "build", "--release", "--quiet", "--bin", "gungnird", "--features", "test-hooks", "--target-dir", ".build/target-hooks" });
    cargo_build.setCwd(b.path("../.."));
    cargo_build.has_side_effects = true;
    const gungnird_bin = b.path("../../.build/target-hooks/release/gungnird");

    const itest = b.step("itest", "Load libgiogungnir.so through GIO, check GungnirVfs, the daemon handshake and metadata");
    // opt-in: GIO_USE_VFS=gungnir, nothing at the socket: GungnirVfs with local fallback.
    // no-opt-in: without GIO_USE_VFS the module must NOT become the default VFS.
    // daemon: real gungnird, hello + ring pair + ping. hung: a socket that never answers.
    // metadata: real gungnird, set then get keys through the md.zig client (protocol v2).
    // gio-metadata, gio-cli, daemon-stopped: metadata::* through GIO (milestone 6), in
    // process and with the `gio` tool, and with the daemon stopped and restarted.
    // ui-thread: hooks called from the main loop, daemon answering and SIGSTOPped.
    // hung-mount: gungnird with a fake hung mount; the module learns it from the health
    // events and fails GIO calls under it within 100 ms (milestone 7).
    // file-ops: the GungnirFileOp type against gungnird (milestone 8).
    // volmon: the volume monitor with GIO_USE_VOLUME_MONITOR=gungnir (milestone 10).
    // volmon-off: without it the monitor is never active (D-004, BC-HC-F01); no-opt-in
    // checks the same without GIO_USE_VFS.
    const daemon_modes = [_][]const u8{ "daemon", "metadata", "gio-metadata", "gio-cli", "daemon-stopped", "ui-thread", "hung-mount", "file-ops" };
    for ([_][]const u8{ "opt-in", "no-opt-in", "daemon", "hung", "metadata", "gio-metadata", "gio-cli", "daemon-stopped", "ui-thread", "hung-mount", "file-ops", "volmon", "volmon-off" }) |mode| {
        const run = b.addRunArtifact(itest_exe);
        run.setName(b.fmt("itest {s}", .{mode}));
        run.addDirectoryArg(module_dir.getDirectory());
        run.addArg(mode);
        if (!std.mem.eql(u8, mode, "no-opt-in")) run.addDirectoryArg2(repo_tmp, .{ .make_absolute = true });
        const needs_daemon = for (daemon_modes) |d| {
            if (std.mem.eql(u8, mode, d)) break true;
        } else false;
        if (needs_daemon) {
            run.addFileArg2(gungnird_bin, .{ .make_absolute = true });
            run.step.dependOn(&cargo_build.step);
        }
        run.has_side_effects = true; // talks to sockets: never skip as cached
        run.expectExitCode(0);
        itest.dependOn(&run.step);
    }

    const test_step = b.step("test", "Run unit and integration tests");
    test_step.dependOn(&run_unit.step);
    test_step.dependOn(itest);
}
