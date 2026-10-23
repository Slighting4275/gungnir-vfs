//! Integration test, run as child processes by `zig build itest`:
//!   gungnir-itest <module-dir> opt-in <tmp-dir>              GungnirVfs; no daemon at the socket
//!   gungnir-itest <module-dir> no-opt-in                     GIO_USE_VFS unset: GLocalVfs
//!   gungnir-itest <module-dir> daemon <tmp-dir> <gungnird>   starts gungnird, expects a ping round trip
//!   gungnir-itest <module-dir> hung <tmp-dir>                a socket that never answers
//! <module-dir> contains only libgiogungnir.so and GIO_EXTRA_MODULES is unset, so no
//! system or user gvfs modules load. Sockets and databases go in <tmp-dir> (.build/tmp).
const std = @import("std");
const c = @import("c");
const linux = std.os.linux;

/// The GIO calling thread must get its VFS and answer local file queries in this time,
/// whatever the daemon does.
const max_call_ms = 250;

fn fail(what: [*:0]const u8) c_int {
    c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest FAILED: %s", what);
    return 1;
}

fn nowMs() i64 {
    return @divTrunc(c.g_get_monotonic_time(), 1000);
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

/// Default-VFS checks shared by every mode. Returns null on success, else what failed.
fn checkVfs(expected: []const u8) ?[*:0]const u8 {
    const vfs = c.g_vfs_get_default();
    if (vfs == null) return "g_vfs_get_default returned NULL";
    const name = c.g_type_name_from_instance(@ptrCast(vfs));
    if (name == null) return "default VFS has no type name";
    if (!std.mem.eql(u8, std.mem.span(name), expected)) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: default VFS is %s, expected %s", name, expected.ptr);
        return "wrong default VFS";
    }
    if (c.g_vfs_is_active(vfs) == 0) return "default VFS is not active";

    if (!isDirectory(c.g_file_new_for_path("/"))) return "g_file_new_for_path(\"/\") is not a directory";
    if (!isDirectory(c.g_file_new_for_uri("file:///"))) return "g_file_new_for_uri(\"file:///\") is not a directory";
    if (!isDirectory(c.g_file_parse_name("/"))) return "g_file_parse_name(\"/\") is not a directory";

    const schemes = c.g_vfs_get_supported_uri_schemes(vfs);
    if (schemes == null or schemes[0] == null) return "no supported URI schemes";
    var has_file = false;
    var i: usize = 0;
    while (schemes[i] != null) : (i += 1) {
        const s = std.mem.span(schemes[i]);
        if (std.mem.eql(u8, s, "file")) has_file = true;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (std.mem.eql(u8, s, std.mem.span(schemes[j]))) return "duplicate URI scheme";
        }
    }
    if (!has_file) return "\"file\" is not a supported URI scheme";
    return null;
}

/// GungnirVfs checks, timed: the calling thread must never wait on the daemon.
fn checkGungnirFast() ?[*:0]const u8 {
    const t0 = nowMs();
    if (checkVfs("GungnirVfs")) |what| return what;
    const took = nowMs() - t0;
    if (took > max_call_ms) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: GIO calls took %d ms", @as(c_int, @intCast(@min(took, 1 << 30))));
        return "GIO calling thread was blocked";
    }
    return null;
}

const State = struct { value: c_int, ms: i64 };

/// Poll GungnirVfs:daemon-state until it leaves "connecting" (0) or `timeout_ms` passes.
fn waitDaemonState(timeout_ms: i64) State {
    const vfs = c.g_vfs_get_default();
    const t0 = nowMs();
    while (true) {
        var v: c_int = -1;
        c.g_object_get(@ptrCast(vfs), "daemon-state", &v, @as(?*anyopaque, null));
        const ms = nowMs() - t0;
        if (v != 0 or ms > timeout_ms) return .{ .value = v, .ms = ms };
        c.g_usleep(5 * 1000);
    }
}

fn expectState(want: c_int, timeout_ms: i64, min_ms: i64) ?[*:0]const u8 {
    const st = waitDaemonState(timeout_ms);
    if (st.value != want or st.ms < min_ms) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: daemon-state %d after %d ms, expected %d", st.value, @as(c_int, @intCast(@min(st.ms, 1 << 30))), want);
        return "unexpected daemon-state";
    }
    return null;
}

fn sockAddr(path: [*:0]const u8) ?linux.sockaddr.un {
    const p = std.mem.span(path);
    var addr: linux.sockaddr.un = .{ .path = @splat(0) };
    if (p.len >= addr.path.len) return null;
    @memcpy(addr.path[0..p.len], p);
    return addr;
}

/// A listening socket that never accepts: a hung daemon.
fn listenHung(path: [*:0]const u8) ?linux.fd_t {
    var addr = sockAddr(path) orelse return null;
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: linux.fd_t = @intCast(rc);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS or
        linux.errno(linux.listen(fd, 4)) != .SUCCESS)
    {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

/// True once something accepts connections at `path` (connects, then hangs up at once).
fn canConnect(path: [*:0]const u8) bool {
    var addr = sockAddr(path) orelse return false;
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    return linux.errno(linux.connect(fd, &addr, @sizeOf(linux.sockaddr.un))) == .SUCCESS;
}

fn tmpPath(dir: [*c]u8, what: [*:0]const u8, ext: [*:0]const u8) [*c]u8 {
    return c.g_strdup_printf("%s/itest-%s-%d%s", dir, what, @as(c_int, linux.getpid()), ext);
}

fn removeFile(path: [*c]const u8) void {
    _ = linux.unlink(path);
}

fn runDaemon(tmp_arg: [*c]u8, gungnird: [*c]u8) c_int {
    const tmp_dir = c.g_canonicalize_filename(tmp_arg, null); // drop "..": sun_path is short
    defer c.g_free(tmp_dir);
    const sock = tmpPath(tmp_dir, "daemon", ".sock");
    defer c.g_free(sock);
    const db = tmpPath(tmp_dir, "daemon", ".db");
    defer c.g_free(db);
    const log = tmpPath(tmp_dir, "daemon", ".log");
    defer c.g_free(log);
    if (c.g_setenv("GUNGNIR_SOCKET", sock, 1) == 0) return fail("g_setenv GUNGNIR_SOCKET");

    // The daemon's stderr goes to a log file, kept only if the test fails.
    const log_rc = linux.open(log, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(log_rc) != .SUCCESS) return fail("could not create the daemon log");
    const log_fd: c_int = @intCast(log_rc);
    var argv = [_][*c]u8{ gungnird, db, null };
    var pid: c.GPid = 0;
    var err: [*c]c.GError = null;
    const spawned = c.g_spawn_async_with_fds(null, &argv, null, c.G_SPAWN_DO_NOT_REAP_CHILD, null, null, &pid, -1, log_fd, log_fd, &err);
    _ = linux.close(log_fd);
    if (spawned == 0) {
        if (err != null) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: spawn gungnird: %s", err.*.message);
            c.g_error_free(err);
        }
        return fail("could not start gungnird");
    }
    var rc: c_int = 1;
    defer {
        _ = linux.kill(pid, .TERM);
        var status: i32 = 0;
        _ = linux.waitpid(pid, &status, 0);
        removeFile(sock);
        const lock = c.g_strdup_printf("%s.lock", sock);
        removeFile(lock);
        c.g_free(lock);
        for ([_][*:0]const u8{ "", "-wal", "-shm" }) |ext| {
            const f = c.g_strdup_printf("%s%s", db, ext);
            removeFile(f);
            c.g_free(f);
        }
        if (rc == 0) removeFile(log) else c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: daemon log kept at %s", log);
    }
    // Wait (bounded) until the daemon accepts connections, before the module tries.
    const t0 = nowMs();
    while (!canConnect(sock)) {
        if (nowMs() - t0 > 10_000) return fail("gungnird did not start listening within 10 s");
        c.g_usleep(10 * 1000);
    }
    if (checkGungnirFast()) |what| return fail(what);
    if (expectState(1, 5_000, 0)) |what| return fail(what);
    rc = 0;
    return rc;
}

fn runHung(tmp_arg: [*c]u8) c_int {
    const tmp_dir = c.g_canonicalize_filename(tmp_arg, null);
    defer c.g_free(tmp_dir);
    const sock = tmpPath(tmp_dir, "hung", ".sock");
    defer c.g_free(sock);
    removeFile(sock);
    const fd = listenHung(sock) orelse return fail("could not create the hung listener");
    defer {
        _ = linux.close(fd);
        removeFile(sock);
    }
    if (c.g_setenv("GUNGNIR_SOCKET", sock, 1) == 0) return fail("g_setenv GUNGNIR_SOCKET");
    if (checkGungnirFast()) |what| return fail(what);
    // The connector gives up after its 500 ms budget: not much sooner, never much later.
    if (expectState(2, 3_000, 300)) |what| return fail(what);
    return 0;
}

fn runMissing(tmp_arg: [*c]u8) c_int {
    const tmp_dir = c.g_canonicalize_filename(tmp_arg, null);
    defer c.g_free(tmp_dir);
    const sock = tmpPath(tmp_dir, "missing", ".sock");
    defer c.g_free(sock);
    removeFile(sock);
    if (c.g_setenv("GUNGNIR_SOCKET", sock, 1) == 0) return fail("g_setenv GUNGNIR_SOCKET");
    if (checkGungnirFast()) |what| return fail(what);
    if (expectState(2, 1_000, 0)) |what| return fail(what);
    return 0;
}

pub export fn main(argc: c_int, argv: [*c][*c]u8) c_int {
    if (argc < 3) return fail("usage: gungnir-itest <module-dir> <mode> [args]");
    const mode = std.mem.span(argv[2]);

    if (c.g_setenv("GIO_MODULE_DIR", argv[1], 1) == 0) return fail("g_setenv GIO_MODULE_DIR");
    // GIO also scans every dir in GIO_EXTRA_MODULES; an inherited value (Flatpak, Nix,
    // custom sessions) could load gvfs's GDaemonVfs (priority 10) and break no-opt-in.
    c.g_unsetenv("GIO_EXTRA_MODULES");

    if (std.mem.eql(u8, mode, "no-opt-in")) {
        if (argc != 3) return fail("usage: no-opt-in takes no arguments");
        c.g_unsetenv("GIO_USE_VFS");
        if (checkVfs("GLocalVfs")) |what| return fail(what);
        return 0;
    }
    if (c.g_setenv("GIO_USE_VFS", "gungnir", 1) == 0) return fail("g_setenv GIO_USE_VFS");
    if (std.mem.eql(u8, mode, "opt-in") and argc == 4) return runMissing(argv[3]);
    if (std.mem.eql(u8, mode, "hung") and argc == 4) return runHung(argv[3]);
    if (std.mem.eql(u8, mode, "daemon") and argc == 5) return runDaemon(argv[3], argv[4]);
    return fail("unknown mode or wrong argument count");
}
