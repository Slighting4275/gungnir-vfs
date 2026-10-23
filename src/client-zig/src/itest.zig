//! Integration test, run as child processes by `zig build itest`:
//!   gungnir-itest <module-dir> opt-in <tmp-dir>              GungnirVfs; no daemon at the socket
//!   gungnir-itest <module-dir> no-opt-in                     GIO_USE_VFS unset: GLocalVfs
//!   gungnir-itest <module-dir> daemon <tmp-dir> <gungnird>   starts gungnird, expects a ping round trip
//!   gungnir-itest <module-dir> hung <tmp-dir>                a socket that never answers
//!   gungnir-itest <module-dir> metadata <tmp-dir> <gungnird> starts gungnird, then sets and
//!                                                            gets keys with the md.zig client
//! <module-dir> contains only libgiogungnir.so and GIO_EXTRA_MODULES is unset, so no
//! system or user gvfs modules load. Sockets and databases go in a fresh private (0700)
//! directory per run, created under <tmp-dir> (.build/tmp).
const std = @import("std");
const c = @import("c");
const ipc = @import("ipc.zig");
const md = @import("md.zig");
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

fn tmpPath(dir: [*:0]const u8, file: [*:0]const u8) [*c]u8 {
    return c.g_strdup_printf("%s/%s", dir, file);
}

/// Creates a fresh directory that only we can enter (0700) under `tmp_arg`, whatever the
/// umask: CI runners check the repo out with umask 0000, which leaves .build/tmp 0777, and
/// gungnird (rightly) refuses a socket directory that others can write to. `tmp_arg` must
/// be our own directory; it is made not group- or world-writable, so nobody else can swap
/// the new directory out from under us. Returns a g_malloc'd path (g_free it), or null.
fn privateDir(tmp_arg: [*c]u8, mode: [*:0]const u8) ?[*:0]u8 {
    const base = c.g_canonicalize_filename(tmp_arg, null); // drop "..": sun_path is short
    defer c.g_free(base);
    // Every check and chmod below goes through an fd opened O_NOFOLLOW, never the path, so
    // a symlink (refused) or a directory swapped in after the check cannot redirect them.
    const base_fd = openOwnDir(linux.AT.FDCWD, base) orelse {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: %s is not a directory owned by us (symlinks are refused)", base);
        return null;
    };
    defer _ = linux.close(base_fd.fd);
    if (base_fd.mode & 0o022 != 0 and linux.errno(linux.fchmod(base_fd.fd, base_fd.mode & 0o7755)) != .SUCCESS) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: cannot remove group/world write from %s", base);
        return null;
    }
    var n: c_int = 0;
    while (n < 1000) : (n += 1) {
        const leaf = c.g_strdup_printf("itest-%s-%d-%d", mode, @as(c_int, linux.getpid()), n);
        defer c.g_free(leaf);
        // mkdirat in the directory we checked, never adopt an existing one: a leftover just
        // gets the next name.
        switch (linux.errno(linux.mkdirat(base_fd.fd, leaf, 0o700))) {
            .SUCCESS => {},
            .EXIST => continue,
            else => {
                c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: cannot create %s/%s", base, leaf);
                return null;
            },
        }
        // The umask may have stripped bits from 0700, never added any; fchmod makes it exact.
        const made = openOwnDir(base_fd.fd, leaf);
        const ok = if (made) |d| linux.errno(linux.fchmod(d.fd, 0o700)) == .SUCCESS else false;
        if (made) |d| _ = linux.close(d.fd);
        if (!ok) {
            _ = linux.unlinkat(base_fd.fd, leaf, linux.AT.REMOVEDIR);
            return null;
        }
        return @ptrCast(c.g_strdup_printf("%s/%s", base, leaf));
    }
    return null;
}

const OwnDir = struct { fd: linux.fd_t, mode: u32 };

/// Open `path` (relative to `dirfd`) as a directory without following a symlink in its
/// last component, and check with fstat (the object opened, not whatever the path names
/// now) that it is a directory owned by us.
fn openOwnDir(dirfd: linux.fd_t, path: [*:0]const u8) ?OwnDir {
    const rc = linux.openat(dirfd, path, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: linux.fd_t = @intCast(rc);
    var st: linux.Statx = undefined;
    const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .UID = true };
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, mask, &st)) != .SUCCESS or
        st.mode & 0o170000 != 0o040000 or st.uid != linux.geteuid())
    {
        _ = linux.close(fd);
        return null;
    }
    return .{ .fd = fd, .mode = st.mode };
}

fn removeFile(path: [*c]const u8) void {
    _ = linux.unlink(path);
}

/// What a daemon-backed mode checks once gungnird listens. Null on success.
const DaemonCheck = *const fn (tmp_dir: [*:0]const u8, sock: [*:0]const u8) ?[*:0]const u8;

/// GIO module against the real daemon: daemon-state reaches 1 (hello, rings, ping).
fn checkModuleConnects(tmp_dir: [*:0]const u8, sock: [*:0]const u8) ?[*:0]const u8 {
    _ = tmp_dir;
    _ = sock;
    if (checkGungnirFast()) |what| return what;
    return expectState(1, 5_000, 0);
}

/// The md.zig client against the real daemon: identify a file, set and get a string
/// and a stringv, list, unset; plus the clean errors for a missing file.
fn checkMetadata(tmp_dir: [*:0]const u8, sock: [*:0]const u8) ?[*:0]const u8 {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    const gpa = dbg.allocator();
    const what = metadataRoundTrip(gpa, tmp_dir, sock) catch |err| blk: {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: metadata: %s", @errorName(err).ptr);
        break :blk "metadata round trip failed";
    };
    if (dbg.deinit() == .leak) return "the metadata client leaked memory";
    return what;
}

fn metadataRoundTrip(gpa: std.mem.Allocator, tmp_dir: [*:0]const u8, sock: [*:0]const u8) md.Error!?[*:0]const u8 {
    const sock_path = try ipc.resolveSocketPath(std.mem.span(sock), null, null);
    var conn = try ipc.connectAndPing(&sock_path, 2_000);
    defer conn.close();
    var client: md.Client = .{ .conn = &conn, .timeout_ms = 5_000 };

    const file = tmpPath(tmp_dir, "meta-file");
    defer c.g_free(file);
    const fd_rc = linux.open(file, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(fd_rc) != .SUCCESS) return "could not create the test file";
    _ = linux.close(@intCast(fd_rc));
    defer removeFile(file);

    const id = try client.identify(std.mem.span(file));
    if (id.inode_num == 0 or id.fsUuid().len == 0) return "identify returned an empty identity";
    const again = try client.identify(std.mem.span(file));
    if (!again.eql(&id)) return "identify is not stable";

    if (try client.get(gpa, &id, "custom-icon")) |v| {
        v.deinit(gpa);
        return "a fresh file already has metadata";
    }
    try client.setString(&id, "custom-icon", "file:///icons/spear.png");
    const got = (try client.get(gpa, &id, "custom-icon")) orelse return "set then get returned nothing";
    defer got.deinit(gpa);
    if (got != .string or !std.mem.eql(u8, got.string, "file:///icons/spear.png")) return "get returned another value";

    const emblems = [_][]const u8{ "emblem-important", "", "emblem-\u{2603}" };
    try client.setStringv(&id, "emblems", &emblems);
    const gv = (try client.get(gpa, &id, "emblems")) orelse return "stringv set then get returned nothing";
    defer gv.deinit(gpa);
    if (gv != .stringv or gv.stringv.len != emblems.len) return "stringv came back with another shape";
    for (gv.stringv, emblems) |a, b| if (!std.mem.eql(u8, a, b)) return "stringv came back different";

    const keys = try client.listKeys(gpa, &id);
    defer md.freeKeys(gpa, keys);
    if (keys.len != 2 or !std.mem.eql(u8, keys[0], "custom-icon") or !std.mem.eql(u8, keys[1], "emblems"))
        return "listKeys returned the wrong keys";

    try client.unset(&id, "custom-icon");
    if (try client.get(gpa, &id, "custom-icon")) |v| {
        v.deinit(gpa);
        return "unset key is still there";
    }

    // Clean errors: a missing file, an invalid key (refused before sending); the daemon
    // keeps answering afterwards.
    const missing = tmpPath(tmp_dir, "no-such-file");
    defer c.g_free(missing);
    if (client.identify(std.mem.span(missing))) |_| return "a missing file was identified" else |err| {
        if (err != error.NoSuchFile) return "a missing file gave the wrong error";
    }
    if (client.setString(&id, "bad\xffkey", "v")) |_| return "a non-UTF-8 key was accepted" else |err| {
        if (err != error.BadUtf8) return "a non-UTF-8 key gave the wrong error";
    }
    try client.setString(&id, "after-errors", "ok");
    return null;
}

fn runDaemon(tmp_arg: [*c]u8, gungnird: [*c]u8, mode: [*:0]const u8, check: DaemonCheck) c_int {
    const tmp_dir = privateDir(tmp_arg, mode) orelse return fail("could not create a private test directory");
    defer c.g_free(tmp_dir);
    defer _ = linux.rmdir(tmp_dir); // after the files below; a kept log keeps the dir too
    const sock = tmpPath(tmp_dir, "gungnird.sock");
    defer c.g_free(sock);
    const db = tmpPath(tmp_dir, "metadata.db");
    defer c.g_free(db);
    const log = tmpPath(tmp_dir, "gungnird.log");
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
        removeFile(log); // the cleanup below is not armed yet
        return fail("could not start gungnird");
    }
    var rc: c_int = 1;
    var reaped = false;
    defer {
        if (!reaped) {
            _ = linux.kill(pid, .TERM);
            var status: i32 = 0;
            _ = linux.waitpid(pid, &status, 0);
        }
        removeFile(sock);
        const lock = c.g_strdup_printf("%s.lock", sock);
        removeFile(lock);
        c.g_free(lock);
        for ([_][*:0]const u8{ "", "-wal", "-shm" }) |ext| {
            const f = c.g_strdup_printf("%s%s", db, ext);
            removeFile(f);
            c.g_free(f);
        }
        if (rc == 0) removeFile(log) else {
            // Show the daemon's own error in the test output (CI keeps no files).
            // Only the tail, so a runaway daemon cannot flood the job log.
            var text: [*c]u8 = null;
            var len: c.gsize = 0;
            if (c.g_file_get_contents(log, &text, &len, null) != 0) {
                const cap: c.gsize = 16 * 1024;
                const skip = if (len > cap) len - cap else 0;
                c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: gungnird output%s:\n%s", @as([*:0]const u8, if (skip > 0) " (last 16 KiB)" else ""), text + skip);
                c.g_free(text);
            }
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: daemon log kept at %s", log);
        }
    }
    // Wait (bounded) until the daemon accepts connections, before the module tries.
    const t0 = nowMs();
    while (!canConnect(sock)) {
        var status: i32 = 0;
        if (linux.waitpid(pid, &status, linux.W.NOHANG) == @as(usize, @intCast(pid))) {
            reaped = true;
            return fail("gungnird exited before it started listening");
        }
        if (nowMs() - t0 > 10_000) return fail("gungnird did not start listening within 10 s");
        c.g_usleep(10 * 1000);
    }
    if (check(tmp_dir, sock)) |what| return fail(what);
    rc = 0;
    return rc;
}

fn runHung(tmp_arg: [*c]u8) c_int {
    const tmp_dir = privateDir(tmp_arg, "hung") orelse return fail("could not create a private test directory");
    defer c.g_free(tmp_dir);
    defer _ = linux.rmdir(tmp_dir);
    const sock = tmpPath(tmp_dir, "gungnird.sock");
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
    const tmp_dir = privateDir(tmp_arg, "opt-in") orelse return fail("could not create a private test directory");
    defer c.g_free(tmp_dir);
    defer _ = linux.rmdir(tmp_dir);
    const sock = tmpPath(tmp_dir, "gungnird.sock");
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
    if (std.mem.eql(u8, mode, "daemon") and argc == 5) return runDaemon(argv[3], argv[4], "daemon", &checkModuleConnects);
    if (std.mem.eql(u8, mode, "metadata") and argc == 5) return runDaemon(argv[3], argv[4], "metadata", &checkMetadata);
    return fail("unknown mode or wrong argument count");
}
