//! Integration test, run as child processes by `zig build itest`:
//!   gungnir-itest <module-dir> opt-in <tmp-dir>              GungnirVfs; no daemon at the socket
//!   gungnir-itest <module-dir> no-opt-in                     GIO_USE_VFS unset: GLocalVfs
//!   gungnir-itest <module-dir> daemon <tmp-dir> <gungnird>   starts gungnird, expects a ping round trip
//!   gungnir-itest <module-dir> hung <tmp-dir>                a socket that never answers
//!   gungnir-itest <module-dir> metadata <tmp-dir> <gungnird> starts gungnird, then sets and
//!                                                            gets keys with the md.zig client
//!   gungnir-itest <module-dir> gio-metadata <tmp-dir> <gungnird>  metadata::* through GIO
//!                                                            in this process (milestone 6)
//!   gungnir-itest <module-dir> gio-cli <tmp-dir> <gungnird>  the same with the `gio` tool,
//!                                                            then again with the daemon gone
//!   gungnir-itest <module-dir> daemon-stopped <tmp-dir> <gungnird>  stop gungnird under a
//!                                                            live connection, then restart it
//!   gungnir-itest <module-dir> hung-mount <tmp-dir> <gungnird>  gungnird with a fake hung
//!                                                            mount (test-hooks build): the
//!                                                            module hears of it and fails
//!                                                            fast (milestone 7)
//!   gungnir-itest <module-dir> file-ops <tmp-dir> <gungnird>  GungnirFileOp: copy, move,
//!                                                            delete, fsync, errors, cancel,
//!                                                            hung-mount refusal, no daemon
//!                                                            (milestone 8; test-hooks build)
//!   gungnir-itest <module-dir> volmon-installed <tmp-dir>   the module installed: a copy
//!                                                            indexed with gio-querymodules;
//!                                                            Gungnir mounts with no opt-in,
//!                                                            GIO_USE_VFS only, and
//!                                                            GIO_USE_VOLUME_MONITOR=gungnir
//!                                                            (BC-HC-F01 v2, D-049, D-051)
//! <module-dir> contains only libgiogungnir.so and GIO_EXTRA_MODULES is unset, so no
//! system or user gvfs modules load. Sockets and databases go in a fresh private (0700)
//! directory per run, created under <tmp-dir> (.build/tmp).
const std = @import("std");
const c = @import("c");
const ipc = @import("ipc.zig");
const md = @import("md.zig");
const health = @import("health.zig");
const link = @import("link.zig");
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

/// A daemon-backed run: its private directory, socket, database and log, and the running
/// gungnird (a check may stop and restart it).
const Ctx = struct {
    tmp_dir: [*:0]const u8,
    sock: [*:0]const u8,
    db: [*:0]const u8,
    log: [*:0]const u8,
    gungnird: [*c]u8,
    pid: c.GPid = 0,
    running: bool = false,

    /// Start gungnird (stderr appended to the log) and wait, bounded, until it listens.
    fn startDaemon(ctx: *Ctx) ?[*:0]const u8 {
        const log_rc = linux.open(ctx.log, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, 0o600);
        if (linux.errno(log_rc) != .SUCCESS) return "could not open the daemon log";
        const log_fd: c_int = @intCast(log_rc);
        var argv = [_][*c]u8{ ctx.gungnird, @constCast(ctx.db), null };
        var err: [*c]c.GError = null;
        const spawned = c.g_spawn_async_with_fds(null, &argv, null, c.G_SPAWN_DO_NOT_REAP_CHILD, null, null, &ctx.pid, -1, log_fd, log_fd, &err);
        _ = linux.close(log_fd);
        if (spawned == 0) {
            if (err != null) {
                c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: spawn gungnird: %s", err.*.message);
                c.g_error_free(err);
            }
            return "could not start gungnird";
        }
        ctx.running = true;
        // Wait (bounded) until the daemon accepts connections, before the module tries.
        const t0 = nowMs();
        while (!canConnect(ctx.sock)) {
            var status: i32 = 0;
            if (linux.waitpid(ctx.pid, &status, linux.W.NOHANG) == @as(usize, @intCast(ctx.pid))) {
                ctx.running = false;
                return "gungnird exited before it started listening";
            }
            if (nowMs() - t0 > 10_000) return "gungnird did not start listening within 10 s";
            c.g_usleep(10 * 1000);
        }
        return null;
    }

    fn stopDaemon(ctx: *Ctx) void {
        if (!ctx.running) return;
        _ = linux.kill(ctx.pid, .TERM);
        var status: i32 = 0;
        _ = linux.waitpid(ctx.pid, &status, 0);
        ctx.running = false;
    }
};

/// What a daemon-backed mode checks once gungnird listens. Null on success.
const DaemonCheck = *const fn (ctx: *Ctx) ?[*:0]const u8;

/// GIO module against the real daemon: daemon-state reaches 1 (hello, rings, ping).
fn checkModuleConnects(ctx: *Ctx) ?[*:0]const u8 {
    _ = ctx;
    if (checkGungnirFast()) |what| return what;
    return expectState(1, 5_000, 0);
}

/// The md.zig client against the real daemon: identify a file, set and get a string
/// and a stringv, list, unset; plus the clean errors for a missing file.
fn checkMetadata(ctx: *Ctx) ?[*:0]const u8 {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    const gpa = dbg.allocator();
    const what = metadataRoundTrip(gpa, ctx.tmp_dir, ctx.sock) catch |err| blk: {
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

    var ctx: Ctx = .{ .tmp_dir = tmp_dir, .sock = @ptrCast(sock), .db = @ptrCast(db), .log = @ptrCast(log), .gungnird = gungnird };
    var rc: c_int = 1;
    defer {
        ctx.stopDaemon();
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
    if (ctx.startDaemon()) |what| return fail(what);
    if (check(&ctx)) |what| return fail(what);
    rc = 0;
    return rc;
}

// ---- milestone 6: metadata::* through GIO --------------------------------------

/// Log and free a GError, if any.
fn logError(what: [*:0]const u8, err: [*c]c.GError) void {
    if (err == null) return;
    c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: %s: %s", what, err.*.message);
    c.g_error_free(err);
}

/// query_info on `file`; null (logged) on failure. Fails the timing budget loudly.
fn queryTimed(file: ?*c.GFile, attrs: [*:0]const u8, slow: *bool) ?*c.GFileInfo {
    const t0 = nowMs();
    var err: [*c]c.GError = null;
    const info = c.g_file_query_info(file, attrs, c.G_FILE_QUERY_INFO_NONE, null, &err);
    if (nowMs() - t0 > max_call_ms) slow.* = true;
    if (info == null) logError("query_info", err);
    return info;
}

fn hasMetadata(info: ?*c.GFileInfo) bool {
    return c.g_file_info_has_namespace(info, "metadata") != 0;
}

fn stringAttr(info: ?*c.GFileInfo, name: [*:0]const u8, want: []const u8) bool {
    if (c.g_file_info_get_attribute_type(info, name) != c.G_FILE_ATTRIBUTE_TYPE_STRING) return false;
    return std.mem.eql(u8, std.mem.span(c.g_file_info_get_attribute_string(info, name)), want);
}

fn stringvAttr(info: ?*c.GFileInfo, name: [*:0]const u8, want: []const []const u8) bool {
    if (c.g_file_info_get_attribute_type(info, name) != c.G_FILE_ATTRIBUTE_TYPE_STRINGV) return false;
    const v = c.g_file_info_get_attribute_stringv(info, name);
    if (v == null) return false;
    for (want, 0..) |w, i| {
        if (v[i] == null or !std.mem.eql(u8, std.mem.span(v[i]), w)) return false;
    }
    return v[want.len] == null;
}

fn createFile(path: [*c]const u8) bool {
    const rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

const AsyncQuery = struct { done: bool = false, info: ?*c.GFileInfo = null };

fn asyncQueried(source: [*c]c.GObject, res: ?*c.GAsyncResult, data: c.gpointer) callconv(.c) void {
    const q: *AsyncQuery = @ptrCast(@alignCast(data));
    var err: [*c]c.GError = null;
    q.info = c.g_file_query_info_finish(@ptrCast(source), res, &err);
    if (q.info == null) logError("query_info_finish", err);
    q.done = true;
}

/// Setting, querying (sync, async, enumerated), unsetting, wrong types, writable
/// namespaces, rename and delete of metadata::* through GungnirVfs, in this process.
fn checkGioMetadata(ctx: *Ctx) ?[*:0]const u8 {
    if (checkGungnirFast()) |what| return what;
    if (expectState(1, 5_000, 0)) |what| return what;
    const path = tmpPath(ctx.tmp_dir, "gio-file");
    defer c.g_free(path);
    if (!createFile(path)) return "could not create the test file";
    defer removeFile(path);
    const file = c.g_file_new_for_path(path);
    defer c.g_object_unref(file);
    var slow = false;
    var err: [*c]c.GError = null;

    // string and stringv
    if (c.g_file_set_attribute_string(file, "metadata::custom-icon", "file:///icons/spear.png", c.G_FILE_QUERY_INFO_NONE, null, &err) == 0) {
        logError("set string", err);
        return "g_file_set_attribute_string(metadata::custom-icon) failed";
    }
    var emblems = [_][*c]const u8{ "emblem-important", "", "emblem-\u{2603}", null };
    if (c.g_file_set_attribute(file, "metadata::emblems", c.G_FILE_ATTRIBUTE_TYPE_STRINGV, @ptrCast(&emblems), c.G_FILE_QUERY_INFO_NONE, null, &err) == 0) {
        logError("set stringv", err);
        return "g_file_set_attribute(metadata::emblems, stringv) failed";
    }
    {
        const info = queryTimed(file, "metadata::*", &slow) orelse return "query_info(metadata::*) failed";
        defer c.g_object_unref(info);
        if (!stringAttr(info, "metadata::custom-icon", "file:///icons/spear.png")) return "metadata::custom-icon did not come back";
        if (!stringvAttr(info, "metadata::emblems", &.{ "emblem-important", "", "emblem-\u{2603}" })) return "metadata::emblems did not come back";
    }
    {
        // A specific key: only that one is fetched and returned.
        const info = queryTimed(file, "standard::name,metadata::emblems", &slow) orelse return "query_info(metadata::emblems) failed";
        defer c.g_object_unref(info);
        if (c.g_file_info_has_attribute(info, "metadata::custom-icon") != 0) return "an unrequested metadata key was returned";
        if (!stringvAttr(info, "metadata::emblems", &.{ "emblem-important", "", "emblem-\u{2603}" })) return "a requested metadata key is missing";
    }
    {
        const info = queryTimed(file, "standard::*", &slow) orelse return "query_info(standard::*) failed";
        defer c.g_object_unref(info);
        if (hasMetadata(info)) return "metadata returned without being asked for";
    }

    // set_attributes_from_info: one set, one unset (type INVALID), statuses SET.
    {
        const info = c.g_file_info_new();
        defer c.g_object_unref(info);
        c.g_file_info_set_attribute_string(info, "metadata::note", "spear");
        c.g_file_info_set_attribute(info, "metadata::custom-icon", c.G_FILE_ATTRIBUTE_TYPE_INVALID, null);
        if (c.g_file_set_attributes_from_info(file, info, c.G_FILE_QUERY_INFO_NONE, null, &err) == 0) {
            logError("set_attributes_from_info", err);
            return "g_file_set_attributes_from_info failed";
        }
        if (c.g_file_info_get_attribute_status(info, "metadata::note") != c.G_FILE_ATTRIBUTE_STATUS_SET or
            c.g_file_info_get_attribute_status(info, "metadata::custom-icon") != c.G_FILE_ATTRIBUTE_STATUS_SET)
            return "set_attributes_from_info did not mark the attributes SET";
    }
    {
        const info = queryTimed(file, "metadata::*", &slow) orelse return "query_info after unset failed";
        defer c.g_object_unref(info);
        if (c.g_file_info_has_attribute(info, "metadata::custom-icon") != 0) return "an unset key is still returned";
        if (!stringAttr(info, "metadata::note", "spear")) return "metadata::note did not come back";
    }

    // Only strings and string lists: anything else is a clean INVALID_ARGUMENT.
    if (c.g_file_set_attribute_uint32(file, "metadata::number", 7, c.G_FILE_QUERY_INFO_NONE, null, &err) != 0)
        return "a uint32 metadata value was accepted";
    if (err == null or c.g_error_matches(err, c.g_io_error_quark(), c.G_IO_ERROR_INVALID_ARGUMENT) == 0) {
        logError("set uint32", err);
        return "a uint32 metadata value gave the wrong error";
    }
    c.g_error_free(err);
    err = null;

    // Writable namespaces include metadata.
    {
        const list = c.g_file_query_writable_namespaces(file, null, &err);
        if (list == null) {
            logError("query_writable_namespaces", err);
            return "g_file_query_writable_namespaces failed";
        }
        defer c.g_file_attribute_info_list_unref(list);
        if (c.g_file_attribute_info_list_lookup(list, "metadata") == null) return "metadata is not a writable namespace";
    }

    // query_info_async (runs query_info on a GTask worker thread).
    {
        var q: AsyncQuery = .{};
        c.g_file_query_info_async(file, "metadata::note", c.G_FILE_QUERY_INFO_NONE, c.G_PRIORITY_DEFAULT, null, &asyncQueried, &q);
        const t0 = nowMs();
        while (!q.done and nowMs() - t0 < 5_000) {
            if (c.g_main_context_iteration(null, 0) == 0) c.g_usleep(1000);
        }
        if (!q.done) return "query_info_async did not complete";
        const info = q.info orelse return "query_info_async failed";
        defer c.g_object_unref(info);
        if (!stringAttr(info, "metadata::note", "spear")) return "query_info_async lost the metadata";
    }

    // Enumerating the directory carries the metadata of its children.
    {
        const dir = c.g_file_new_for_path(ctx.tmp_dir);
        defer c.g_object_unref(dir);
        const en = c.g_file_enumerate_children(dir, "standard::name,metadata::*", c.G_FILE_QUERY_INFO_NONE, null, &err);
        if (en == null) {
            logError("enumerate_children", err);
            return "g_file_enumerate_children failed";
        }
        defer c.g_object_unref(en);
        var found = false;
        while (true) {
            const info = c.g_file_enumerator_next_file(en, null, null) orelse break;
            defer c.g_object_unref(info);
            if (std.mem.eql(u8, std.mem.span(c.g_file_info_get_name(info)), "gio-file"))
                found = stringAttr(info, "metadata::note", "spear");
        }
        if (!found) return "the enumerated file has no metadata";
    }

    // GIO calls from many threads at once share the one connection safely.
    if (checkThreads(file)) |what| return what;

    // Rename: the metadata stays with the file (identity), GIO reports the move.
    const moved_path = tmpPath(ctx.tmp_dir, "gio-file-moved");
    defer c.g_free(moved_path);
    const moved = c.g_file_new_for_path(moved_path);
    defer c.g_object_unref(moved);
    if (c.g_file_move(file, moved, c.G_FILE_COPY_NONE, null, null, null, &err) == 0) {
        logError("move", err);
        return "g_file_move failed";
    }
    defer removeFile(moved_path);
    {
        const info = queryTimed(moved, "metadata::*", &slow) orelse return "query_info after move failed";
        defer c.g_object_unref(info);
        if (!stringAttr(info, "metadata::note", "spear")) return "metadata did not follow the rename";
    }

    // Delete: the daemon drops the rows (checked through a separate md.zig connection).
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    const what = checkDeleteDrops(dbg.allocator(), ctx, moved, moved_path) catch |e| blk: {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: delete check: %s", @errorName(e).ptr);
        break :blk "the delete check failed";
    };
    if (dbg.deinit() == .leak) return "the metadata client leaked memory";
    if (what) |w| return w;
    if (slow) return "a metadata query blocked the calling thread too long";
    return null;
}

const thread_count = 6;
const rounds = 25;

const Worker = struct { file: ?*c.GFile, index: usize, failures: u32 = 0, slow: bool = false };

fn workerMain(data: c.gpointer) callconv(.c) c.gpointer {
    const w: *Worker = @ptrCast(@alignCast(data));
    var name_buf: [32]u8 = undefined;
    const name = std.fmt.bufPrintSentinel(&name_buf, "metadata::thread-{d}", .{w.index}, 0) catch {
        w.failures += 1;
        return null;
    };
    for (0..rounds) |i| {
        var val_buf: [16]u8 = undefined;
        const val = std.fmt.bufPrintSentinel(&val_buf, "{d}", .{i}, 0) catch {
            w.failures += 1;
            continue;
        };
        var err: [*c]c.GError = null;
        const t0 = nowMs();
        if (c.g_file_set_attribute_string(w.file, name.ptr, val.ptr, c.G_FILE_QUERY_INFO_NONE, null, &err) == 0) {
            logError("threaded set", err);
            w.failures += 1;
            continue;
        }
        const info = queryTimed(w.file, name.ptr, &w.slow) orelse {
            w.failures += 1;
            continue;
        };
        defer c.g_object_unref(info);
        if (!stringAttr(info, name.ptr, val)) w.failures += 1;
        if (nowMs() - t0 > 2 * max_call_ms) w.slow = true;
    }
    return null;
}

fn checkThreads(file: ?*c.GFile) ?[*:0]const u8 {
    var workers: [thread_count]Worker = undefined;
    var threads: [thread_count]?*c.GThread = @splat(null);
    for (&workers, &threads, 0..) |*w, *t, i| {
        w.* = .{ .file = file, .index = i };
        t.* = c.g_thread_try_new("itest-worker", &workerMain, w, null);
    }
    var started = true;
    for (threads) |t| {
        if (t) |th| _ = c.g_thread_join(th) else started = false;
    }
    if (!started) return "could not start the worker threads";
    for (workers) |w| {
        if (w.failures != 0) return "a threaded metadata set/query failed";
        if (w.slow) return "a threaded metadata call blocked too long";
    }
    // Clean up the keys (unset) so later checks see only their own.
    for (0..thread_count) |i| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrintSentinel(&name_buf, "metadata::thread-{d}", .{i}, 0) catch return "name";
        if (c.g_file_set_attribute(file, name.ptr, c.G_FILE_ATTRIBUTE_TYPE_INVALID, null, c.G_FILE_QUERY_INFO_NONE, null, null) == 0)
            return "unsetting a threaded key failed";
    }
    return null;
}

fn checkDeleteDrops(gpa: std.mem.Allocator, ctx: *Ctx, file: ?*c.GFile, path: [*c]const u8) md.Error!?[*:0]const u8 {
    const sock_path = try ipc.resolveSocketPath(std.mem.span(ctx.sock), null, null);
    var conn = try ipc.connectAndPing(&sock_path, 2_000);
    defer conn.close();
    var client: md.Client = .{ .conn = &conn, .timeout_ms = 5_000 };
    const id = try client.identify(std.mem.span(path));
    const before = (try client.get(gpa, &id, "note")) orelse return "metadata missing before the delete";
    before.deinit(gpa);
    var err: [*c]c.GError = null;
    if (c.g_file_delete(file, null, &err) == 0) {
        logError("delete", err);
        return "g_file_delete failed";
    }
    if (try client.get(gpa, &id, "note")) |v| {
        v.deinit(gpa);
        return "metadata survived g_file_delete";
    }
    return null;
}

/// Runs `gio <args>` (inherits GIO_MODULE_DIR, GIO_USE_VFS, GUNGNIR_SOCKET); returns its
/// exit status and output (g_free both strings), or null if it could not run.
const CliResult = struct { ok: bool, out: [*c]u8, err: [*c]u8, ms: i64 };

fn runGio(args: []const [*c]const u8) ?CliResult {
    const gio = c.g_find_program_in_path("gio");
    if (gio == null) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: the gio tool is not in PATH");
        return null;
    }
    defer c.g_free(gio);
    var argv: [12][*c]u8 = @splat(null);
    if (args.len + 2 > argv.len) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: too many gio arguments");
        return null;
    }
    argv[0] = gio;
    for (args, 1..) |a, i| argv[i] = @constCast(a);
    var r: CliResult = .{ .ok = false, .out = null, .err = null, .ms = 0 };
    var status: c_int = 0;
    var err: [*c]c.GError = null;
    const t0 = nowMs();
    if (c.g_spawn_sync(null, &argv, null, c.G_SPAWN_DEFAULT, null, null, &r.out, &r.err, &status, &err) == 0) {
        logError("spawn gio", err);
        return null;
    }
    r.ms = nowMs() - t0;
    r.ok = c.g_spawn_check_wait_status(status, null) != 0;
    return r;
}

fn freeCli(r: CliResult) void {
    c.g_free(r.out);
    c.g_free(r.err);
}

fn contains(hay: [*c]const u8, needle: []const u8) bool {
    if (hay == null) return false;
    return std.mem.indexOf(u8, std.mem.span(hay), needle) != null;
}

/// gio set / gio info through the module, then the same with the daemon stopped: the
/// query still answers quickly, just without metadata, and set fails cleanly.
fn checkGioCli(ctx: *Ctx) ?[*:0]const u8 {
    const path = tmpPath(ctx.tmp_dir, "cli-file");
    defer c.g_free(path);
    if (!createFile(path)) return "could not create the test file";
    defer removeFile(path);
    const steps = [_]struct { args: []const [*c]const u8 }{
        .{ .args = &.{ "set", path, "metadata::foo", "bar" } },
        .{ .args = &.{ "set", "-t", "stringv", path, "metadata::tags", "a", "b" } },
        .{ .args = &.{ "set", path, "metadata::gone", "x" } },
        .{ .args = &.{ "set", "-t", "unset", path, "metadata::gone" } },
    };
    for (steps) |st| {
        const r = runGio(st.args) orelse return "could not run gio";
        defer freeCli(r);
        if (!r.ok) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: gio set: %s", r.err);
            return "gio set failed";
        }
    }
    {
        const r = runGio(&.{ "info", "-a", "metadata::*", path }) orelse return "could not run gio";
        defer freeCli(r);
        if (!r.ok or !contains(r.out, "metadata::foo: bar") or !contains(r.out, "metadata::tags: [a, b]") or contains(r.out, "metadata::gone")) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: gio info said:\n%s%s", r.out, r.err);
            return "gio info did not show the metadata that gio set stored";
        }
    }
    {
        const r = runGio(&.{ "info", "-w", path }) orelse return "could not run gio";
        defer freeCli(r);
        if (!r.ok or !contains(r.out, "metadata (string")) return "gio info -w does not list metadata as writable";
    }
    ctx.stopDaemon();
    {
        const r = runGio(&.{ "info", "-a", "standard::type,metadata::*", path }) orelse return "could not run gio";
        defer freeCli(r);
        if (!r.ok or contains(r.out, "metadata::") or !contains(r.out, "standard::type")) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: gio info without a daemon said:\n%s%s", r.out, r.err);
            return "gio info without a daemon did not answer without metadata";
        }
        if (r.ms > 1_000) return "gio info without a daemon was slow";
    }
    {
        const r = runGio(&.{ "set", path, "metadata::foo", "baz" }) orelse return "could not run gio";
        defer freeCli(r);
        if (r.ok or !contains(r.err, "not available")) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: gio set without a daemon said:\n%s%s", r.out, r.err);
            return "gio set without a daemon did not fail cleanly";
        }
        if (r.ms > 1_000) return "gio set without a daemon was slow";
    }
    return null;
}

/// Without metadata service (no daemon, or still connecting): a metadata query is fast
/// and carries no metadata, a set fails fast with one of `codes`.
fn checkNoMetadata(tmp_dir: [*:0]const u8, codes: []const c_int) ?[*:0]const u8 {
    const path = tmpPath(tmp_dir, "no-md-file");
    defer c.g_free(path);
    if (!createFile(path)) return "could not create the test file";
    defer removeFile(path);
    const file = c.g_file_new_for_path(path);
    defer c.g_object_unref(file);
    var slow = false;
    {
        const info = queryTimed(file, "standard::type,metadata::*", &slow) orelse return "query_info without metadata service failed";
        defer c.g_object_unref(info);
        if (hasMetadata(info)) return "metadata appeared without a daemon";
        if (c.g_file_info_get_file_type(info) != c.G_FILE_TYPE_REGULAR) return "standard::type is wrong without a daemon";
    }
    if (slow) return "a metadata query without a daemon blocked the calling thread";
    var err: [*c]c.GError = null;
    const t0 = nowMs();
    if (c.g_file_set_attribute_string(file, "metadata::k", "v", c.G_FILE_QUERY_INFO_NONE, null, &err) != 0)
        return "a metadata set succeeded without a daemon";
    const took = nowMs() - t0;
    defer if (err != null) c.g_error_free(err);
    if (took > 400) return "a metadata set without a daemon blocked too long";
    if (err == null or err.*.domain != c.g_io_error_quark()) return "a metadata set without a daemon gave no GIO error";
    for (codes) |code| if (err.*.code == code) return null;
    c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: unexpected error: %s", err.*.message);
    return "a metadata set without a daemon gave an unexpected error code";
}

/// The daemon stops under a live connection: queries answer quickly without metadata,
/// sets fail cleanly; after a restart the module reconnects on its own.
fn checkDaemonStopped(ctx: *Ctx) ?[*:0]const u8 {
    if (checkGungnirFast()) |what| return what;
    if (expectState(1, 5_000, 0)) |what| return what;
    const path = tmpPath(ctx.tmp_dir, "stop-file");
    defer c.g_free(path);
    if (!createFile(path)) return "could not create the test file";
    defer removeFile(path);
    const file = c.g_file_new_for_path(path);
    defer c.g_object_unref(file);
    var err: [*c]c.GError = null;
    if (c.g_file_set_attribute_string(file, "metadata::k", "v", c.G_FILE_QUERY_INFO_NONE, null, &err) == 0) {
        logError("set", err);
        return "set with a live daemon failed";
    }
    ctx.stopDaemon();
    if (checkNoMetadata(ctx.tmp_dir, &.{c.G_IO_ERROR_NOT_SUPPORTED})) |what| return what;
    if (expectState(2, 0, 0)) |what| return what;
    if (checkGungnirFast()) |what| return what;
    if (ctx.startDaemon()) |what| return what;
    // The next metadata call at least reconnect_interval_ms after the loss reconnects.
    const t0 = nowMs();
    while (nowMs() - t0 < 10_000) {
        var slow = false;
        const info = queryTimed(file, "metadata::k", &slow) orelse return "query_info after the restart failed";
        defer c.g_object_unref(info);
        if (slow) return "a query during reconnection blocked the calling thread";
        if (stringAttr(info, "metadata::k", "v")) return null;
        c.g_usleep(100 * 1000);
    }
    return "the module did not reconnect to the restarted daemon";
}

// ---- review: metadata hooks on the UI thread ------------------------------------

/// AGENTS.md §4: no GIO call may pause the client thread for 5 ms or more. The test
/// threshold leaves room for scheduler noise on CI runners; the measured worst is logged.
const ui_slo_ms = 5;
const ui_assert_ms = 25;

const UiRun = struct {
    ctx: *Ctx,
    loop: ?*c.GMainLoop,
    worst_us: i64 = 0,
    worst_what: [*:0]const u8 = "nothing",
    failed: ?[*:0]const u8 = null,
    /// The healthy runs: the first file's metadata must reach the UI thread.
    want_metadata: bool = false,

    fn note(r: *UiRun, what: [*:0]const u8, t0_us: i64) void {
        const took = c.g_get_monotonic_time() - t0_us;
        if (took > r.worst_us) {
            r.worst_us = took;
            r.worst_what = what;
        }
    }
};

fn uiIdle(data: c.gpointer) callconv(.c) c.gboolean {
    const r: *UiRun = @ptrCast(@alignCast(data));
    r.failed = uiCalls(r);
    c.g_main_loop_quit(r.loop);
    return 0;
}

/// Run `uiCalls` from an idle callback, i.e. on the thread that dispatches the default
/// main context, exactly like a GTK signal handler or idle in an application.
fn runOnUiThread(r: *UiRun) ?[*:0]const u8 {
    r.loop = c.g_main_loop_new(null, 0);
    defer c.g_main_loop_unref(r.loop);
    _ = c.g_idle_add(&uiIdle, r);
    c.g_main_loop_run(r.loop);
    return r.failed;
}

const ui_files = 40;

const no_metadata_msg: [*:0]const u8 = "the UI thread got no metadata from a healthy daemon";
/// UI-thread runs of a stage that expects metadata. One reply slower than ui_budget_ms
/// (scheduling on a loaded machine) is a timeout by design, and the quiet period after
/// it hides metadata from the UI thread for ui_quiet_ms: retry the stage after that
/// period rather than fail; a daemon that never answers in time still fails.
const ui_metadata_attempts = 5;
const healthy_blocked_msg: [*:0]const u8 = "a metadata hook blocked the UI thread with a healthy daemon";

/// Every attempt is held to the UI-block assert when `blocked` is given: the retry
/// forgives lost metadata only, never a blocked UI thread (F10b).
fn runOnUiThreadWantingMetadata(ctx: *Ctx, out: *UiRun, blocked: ?[*:0]const u8) ?[*:0]const u8 {
    var attempt: u32 = 1;
    while (true) : (attempt += 1) {
        out.* = .{ .ctx = ctx, .loop = null, .want_metadata = true };
        const result = runOnUiThread(out);
        c.g_log(null, c.G_LOG_LEVEL_MESSAGE, "gungnir itest: ui-thread, attempt %u: worst %s %ld us", attempt, out.worst_what, @as(c_long, @intCast(out.worst_us)));
        if (blocked) |msg| if (out.worst_us > ui_assert_ms * 1000) return msg;
        const what = result orelse return null;
        if (what != no_metadata_msg or attempt == ui_metadata_attempts) return what;
        c.g_log(null, c.G_LOG_LEVEL_MESSAGE, "gungnir itest: ui-thread, no metadata on attempt %u (a slow reply started the quiet period), retrying", attempt);
        c.g_usleep((link.ui_quiet_ms + 200) * 1000);
    }
}

fn uiCalls(r: *UiRun) ?[*:0]const u8 {
    const dir = c.g_file_new_for_path(r.ctx.tmp_dir);
    defer c.g_object_unref(dir);
    const one = tmpPath(r.ctx.tmp_dir, "ui-0");
    defer c.g_free(one);
    const file = c.g_file_new_for_path(one);
    defer c.g_object_unref(file);
    var err: [*c]c.GError = null;
    for (0..10) |_| {
        const t0 = c.g_get_monotonic_time();
        const info = c.g_file_query_info(file, "standard::name,metadata::*", c.G_FILE_QUERY_INFO_NONE, null, &err);
        r.note("query_info(metadata::*)", t0);
        if (info == null) {
            logError("ui query", err);
            return "query_info failed on the UI thread";
        }
        defer c.g_object_unref(info);
        if (r.want_metadata and !stringAttr(info, "metadata::k", "v") and !stringAttr(info, "metadata::k", "v2"))
            return no_metadata_msg;
    }
    {
        const en = c.g_file_enumerate_children(dir, "standard::name,metadata::*", c.G_FILE_QUERY_INFO_NONE, null, &err) orelse {
            logError("ui enumerate", err);
            return "enumerate_children failed on the UI thread";
        };
        defer c.g_object_unref(en);
        while (true) {
            const t0 = c.g_get_monotonic_time();
            const info = c.g_file_enumerator_next_file(en, null, null);
            r.note("enumerator_next_file(metadata::*)", t0);
            c.g_object_unref(info orelse break);
        }
    }
    for (0..3) |_| {
        const t0 = c.g_get_monotonic_time();
        const ok = c.g_file_set_attribute_string(file, "metadata::k", "v2", c.G_FILE_QUERY_INFO_NONE, null, &err);
        r.note("set_attribute_string(metadata::k)", t0);
        if (ok == 0) {
            c.g_error_free(err);
            err = null;
        }
    }
    const gone = tmpPath(r.ctx.tmp_dir, "ui-1");
    defer c.g_free(gone);
    const gone_file = c.g_file_new_for_path(gone);
    defer c.g_object_unref(gone_file);
    const t0 = c.g_get_monotonic_time();
    const deleted = c.g_file_delete(gone_file, null, &err);
    r.note("delete (local_file_removed)", t0);
    if (deleted == 0) {
        logError("ui delete", err);
        return "delete failed on the UI thread";
    }
    return null;
}

/// The daemon is alive but not answering (SIGSTOP: as when it is stuck on a hung mount,
/// a locked database or a debugger). Metadata hooks called from the UI thread must still
/// return within the client-thread SLO, and metadata comes back once it answers again.
fn checkUiThread(ctx: *Ctx) ?[*:0]const u8 {
    if (checkGungnirFast()) |what| return what;
    if (expectState(1, 5_000, 0)) |what| return what;
    var paths: [ui_files][*c]u8 = undefined;
    for (&paths, 0..) |*p, i| {
        var name: [16]u8 = undefined;
        const n = std.fmt.bufPrintSentinel(&name, "ui-{d}", .{i}, 0) catch return "name";
        p.* = tmpPath(ctx.tmp_dir, n.ptr);
        if (!createFile(p.*)) return "could not create a test file";
    }
    defer for (paths) |p| {
        removeFile(p);
        c.g_free(p);
    };
    const file = c.g_file_new_for_path(paths[0]);
    defer c.g_object_unref(file);
    var err: [*c]c.GError = null;
    if (c.g_file_set_attribute_string(file, "metadata::k", "v", c.G_FILE_QUERY_INFO_NONE, null, &err) == 0) {
        logError("set", err);
        return "set with a live daemon failed";
    }
    // Healthy daemon: the UI thread gets the metadata, within the SLO.
    var healthy: UiRun = undefined;
    if (runOnUiThreadWantingMetadata(ctx, &healthy, healthy_blocked_msg)) |what| return what;
    c.g_log(null, c.G_LOG_LEVEL_MESSAGE, "gungnir itest: ui-thread, daemon answering: worst %s %ld us", healthy.worst_what, @as(c_long, @intCast(healthy.worst_us)));
    if (healthy.worst_us > ui_assert_ms * 1000) return healthy_blocked_msg;
    if (!createFile(paths[1])) return "could not re-create the test file";

    _ = linux.kill(ctx.pid, .STOP);
    var stopped: UiRun = .{ .ctx = ctx, .loop = null };
    const what = runOnUiThread(&stopped);
    c.g_log(null, c.G_LOG_LEVEL_MESSAGE, "gungnir itest: ui-thread, daemon stopped: worst %s %ld us (SLO %d ms)", stopped.worst_what, @as(c_long, @intCast(stopped.worst_us)), @as(c_int, ui_slo_ms));
    _ = linux.kill(ctx.pid, .CONT);
    if (what) |w| return w;
    if (stopped.worst_us > ui_assert_ms * 1000) return "a metadata hook blocked the UI thread while the daemon did not answer";

    // Answering again: metadata comes back (from a worker thread at once, and on the UI
    // thread after the back-off), without a restart.
    const t0 = nowMs();
    while (nowMs() - t0 < 10_000) {
        var slow = false;
        const info = queryTimed(file, "metadata::k", &slow) orelse return "query_info after SIGCONT failed";
        defer c.g_object_unref(info);
        if (stringAttr(info, "metadata::k", "v") or stringAttr(info, "metadata::k", "v2")) break;
        c.g_usleep(100 * 1000);
    } else return "metadata did not come back after the daemon answered again";
    // And on the UI thread, at the latest after its quiet period.
    if (!createFile(paths[1])) return "could not re-create the test file";
    c.g_usleep(1200 * 1000);
    var again: UiRun = undefined;
    if (runOnUiThreadWantingMetadata(ctx, &again, null)) |w| return w;
    c.g_log(null, c.G_LOG_LEVEL_MESSAGE, "gungnir itest: ui-thread, answering again: worst %s %ld us", again.worst_what, @as(c_long, @intCast(again.worst_us)));
    return null;
}

// ---- milestone 7: hang-proof mounts ---------------------------------------------

/// Calls under a hung mount must return within this, on the calling thread.
const max_hung_call_ms = 100;

fn unhealthyMounts() c_int {
    var v: c_int = -1;
    c.g_object_get(@ptrCast(c.g_vfs_get_default()), "unhealthy-mounts", &v, @as(?*anyopaque, null));
    return v;
}

/// gungnird (a test-hooks build) treats <tmp>/fake-hung as a mount whose probes never
/// return. The module must learn that from the pushed health events alone (no call is
/// made until then), then answer every GIO call under it within max_hung_call_ms without
/// asking the daemon; other paths keep their metadata; and the daemon itself refuses
/// identity requests for the mount at once (a second connection, no health cache).
const UiHung = struct {
    hung: ?*c.GFile,
    ok: ?*c.GFile,
    loop: ?*c.GMainLoop = null,
    worst_us: i64 = 0,
    failed: ?[*:0]const u8 = null,

    fn note(u: *UiHung, t0_us: i64) void {
        u.worst_us = @max(u.worst_us, c.g_get_monotonic_time() - t0_us);
    }
};

fn uiHungIdle(data: c.gpointer) callconv(.c) c.gboolean {
    const u: *UiHung = @ptrCast(@alignCast(data));
    u.failed = uiHungCalls(u);
    c.g_main_loop_quit(u.loop);
    return 0;
}

fn uiHungCalls(u: *UiHung) ?[*:0]const u8 {
    var err: [*c]c.GError = null;
    for (0..5) |_| {
        var t0 = c.g_get_monotonic_time();
        const info = c.g_file_query_info(u.hung, "standard::name,metadata::*", c.G_FILE_QUERY_INFO_NONE, null, &err);
        u.note(t0);
        const i = info orelse {
            logError("ui query under the hung mount", err);
            return "query_info under the hung mount failed on the UI thread";
        };
        defer c.g_object_unref(i);
        if (hasMetadata(i)) return "metadata came back for a hung mount on the UI thread";
        t0 = c.g_get_monotonic_time();
        const set = c.g_file_set_attribute_string(u.hung, "metadata::k", "v", c.G_FILE_QUERY_INFO_NONE, null, &err);
        u.note(t0);
        if (set != 0) return "a set under the hung mount succeeded on the UI thread";
        defer {
            c.g_error_free(err);
            err = null;
        }
        if (!contains(err.*.message, "health monitor")) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: UI-thread set said: %s", err.*.message);
            return "a set under the hung mount on the UI thread was not failed from the health cache";
        }
    }
    // No quiet period was started: the file next to it still gets its metadata here.
    const t0 = c.g_get_monotonic_time();
    const info = c.g_file_query_info(u.ok, "metadata::k", c.G_FILE_QUERY_INFO_NONE, null, &err);
    u.note(t0);
    const i = info orelse {
        logError("ui query next to the hung mount", err);
        return "query_info next to the hung mount failed on the UI thread";
    };
    defer c.g_object_unref(i);
    if (!stringAttr(i, "metadata::k", "v")) return "the UI thread lost the metadata next to the hung mount";
    return null;
}

fn checkHungMount(ctx: *Ctx) ?[*:0]const u8 {
    const dir = tmpPath(ctx.tmp_dir, "fake-hung");
    defer c.g_free(dir);
    if (linux.errno(linux.mkdirat(linux.AT.FDCWD, dir, 0o700)) != .SUCCESS) return "could not create the fake mount dir";
    defer _ = linux.rmdir(dir);
    const path = tmpPath(dir, "f");
    defer c.g_free(path);
    if (!createFile(path)) return "could not create the file under the fake mount";
    defer removeFile(path);
    const ok_path = tmpPath(ctx.tmp_dir, "ok-file");
    defer c.g_free(ok_path);
    if (!createFile(ok_path)) return "could not create the control file";
    defer removeFile(ok_path);
    // Restart the daemon with the hook (nothing has talked to it yet).
    if (c.g_setenv("GUNGNIR_TEST_FAKE_HUNG_MOUNT", dir, 1) == 0) return "g_setenv GUNGNIR_TEST_FAKE_HUNG_MOUNT";
    ctx.stopDaemon();
    if (ctx.startDaemon()) |what| return what;
    c.g_unsetenv("GUNGNIR_TEST_FAKE_HUNG_MOUNT");

    if (checkGungnirFast()) |what| return what;
    if (expectState(1, 5_000, 0)) |what| return what;
    // The probe deadline is 1 s; the event reaches the idle module through its event
    // thread. No GIO call is made meanwhile.
    const t0 = nowMs();
    while (unhealthyMounts() < 1) {
        if (nowMs() - t0 > 5_000) return "no mount-health event reached the module";
        c.g_usleep(10 * 1000);
    }
    if (unhealthyMounts() != 1) return "the module counts the wrong number of hung mounts";

    const file = c.g_file_new_for_path(path);
    defer c.g_object_unref(file);
    var err: [*c]c.GError = null;
    {
        const t = nowMs();
        const info = c.g_file_query_info(file, "standard::*,metadata::*", c.G_FILE_QUERY_INFO_NONE, null, &err);
        if (nowMs() - t > max_hung_call_ms) return "query_info under a hung mount was slow";
        if (info == null) {
            logError("query_info", err);
            return "query_info under a hung mount failed";
        }
        defer c.g_object_unref(info);
        if (hasMetadata(info)) return "metadata came back for a hung mount";
        if (c.g_file_info_get_file_type(info) != c.G_FILE_TYPE_REGULAR) return "standard::type is wrong under the hung mount";
    }
    {
        const t = nowMs();
        if (c.g_file_set_attribute_string(file, "metadata::k", "v", c.G_FILE_QUERY_INFO_NONE, null, &err) != 0)
            return "a metadata set on a hung mount succeeded";
        if (nowMs() - t > max_hung_call_ms) return "a metadata set on a hung mount was slow";
        defer c.g_error_free(err);
        if (c.g_error_matches(err, c.g_io_error_quark(), c.G_IO_ERROR_TIMED_OUT) == 0) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: set said: %s", err.*.message);
            return "a metadata set on a hung mount gave the wrong error";
        }
        // Failed by the module's own cache, not by a round trip to the resolver.
        if (!contains(err.*.message, "health monitor")) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: set said: %s", err.*.message);
            return "a metadata set on a hung mount was not failed from the health cache";
        }
    }
    err = null;
    {
        const dfile = c.g_file_new_for_path(dir);
        defer c.g_object_unref(dfile);
        const t = nowMs();
        const en = c.g_file_enumerate_children(dfile, "standard::name,metadata::*", c.G_FILE_QUERY_INFO_NONE, null, &err);
        if (en == null) {
            logError("enumerate_children", err);
            return "enumerating the hung mount failed";
        }
        defer c.g_object_unref(en);
        var n: usize = 0;
        while (c.g_file_enumerator_next_file(en, null, null)) |info| {
            defer c.g_object_unref(info);
            if (hasMetadata(info)) return "an enumerated child of a hung mount has metadata";
            n += 1;
        }
        if (n != 1) return "enumerating the hung mount saw the wrong children";
        if (nowMs() - t > max_hung_call_ms) return "enumerating the hung mount was slow";
    }
    {
        var q: AsyncQuery = .{};
        const t = nowMs();
        c.g_file_query_info_async(file, "metadata::k", c.G_FILE_QUERY_INFO_NONE, c.G_PRIORITY_DEFAULT, null, &asyncQueried, &q);
        while (!q.done and nowMs() - t < 5_000) {
            if (c.g_main_context_iteration(null, 0) == 0) c.g_usleep(1000);
        }
        if (!q.done) return "query_info_async under a hung mount did not complete";
        if (nowMs() - t > max_hung_call_ms) return "query_info_async under a hung mount was slow";
        const info = q.info orelse return "query_info_async under a hung mount failed";
        defer c.g_object_unref(info);
        if (hasMetadata(info)) return "query_info_async returned metadata for a hung mount";
    }

    // Everything else still has its metadata.
    const ok = c.g_file_new_for_path(ok_path);
    defer c.g_object_unref(ok);
    if (c.g_file_set_attribute_string(ok, "metadata::k", "v", c.G_FILE_QUERY_INFO_NONE, null, &err) == 0) {
        logError("set", err);
        return "a metadata set next to the hung mount failed";
    }
    {
        var slow = false;
        const info = queryTimed(ok, "metadata::k", &slow) orelse return "query_info next to the hung mount failed";
        defer c.g_object_unref(info);
        if (!stringAttr(info, "metadata::k", "v")) return "metadata next to the hung mount did not come back";
        if (slow) return "a query next to the hung mount was slow";
    }
    // On the UI thread (milestone 6 review: 3 ms budget, quiet period after a timeout):
    // the health cache answers before any of that, within the SLO, and failing a call
    // under the hung mount never starts the quiet period for the paths next to it.
    {
        var u: UiHung = .{ .hung = file, .ok = ok };
        u.loop = c.g_main_loop_new(null, 0);
        defer c.g_main_loop_unref(u.loop);
        _ = c.g_idle_add(&uiHungIdle, &u);
        c.g_main_loop_run(u.loop);
        c.g_log(null, c.G_LOG_LEVEL_MESSAGE, "gungnir itest: hung-mount on the UI thread: worst %ld us (SLO %d ms)", @as(c_long, @intCast(u.worst_us)), @as(c_int, ui_slo_ms));
        if (u.failed) |w| return w;
        if (u.worst_us > ui_assert_ms * 1000) return "a call under the hung mount blocked the UI thread";
    }

    // The daemon's own view, over a second connection without the module's cache.
    const sock_path = ipc.resolveSocketPath(std.mem.span(ctx.sock), null, null) catch return "bad socket path";
    var conn = ipc.connectAndPing(&sock_path, 2_000) catch return "second connection failed";
    defer conn.close();
    var cl: md.Client = .{ .conn = &conn, .timeout_ms = 2_000 };
    {
        const t = nowMs();
        if (cl.identify(std.mem.span(path))) |_| return "the daemon identified a file on a hung mount" else |e| {
            if (e != error.SuspectMount) {
                c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: identify: %s", @errorName(e).ptr);
                return "identify on a hung mount gave the wrong error";
            }
        }
        if (nowMs() - t > max_hung_call_ms) return "identify on a hung mount was slow";
    }
    const info = health.queryPath(&cl, std.mem.span(path)) catch return "health query by path failed";
    if (info.state != health.hung or !std.mem.eql(u8, info.mountPoint(), std.mem.span(dir))) return "the daemon does not report the fake mount hung";
    const by_id = health.queryId(&cl, info.mnt_id) catch return "health query by id failed";
    if (by_id.state != health.hung) return "health query by id disagrees";
    const root = health.queryPath(&cl, "/") catch return "health query of / failed";
    if (root.state != health.healthy) return "/ is not healthy";
    if (health.queryId(&cl, 0xdead_beef_dead)) |_| return "an unknown mount id was found" else |e| {
        if (e != error.NotFound) return "an unknown mount id gave the wrong error";
    }
    if (checkGungnirFast()) |what| return what;
    return null;
}

// ---- milestone 8: GungnirFileOp ------------------------------------------------

/// "start" must return within this; it only spawns the op thread.
const max_start_ms = 50;

const OpRun = struct {
    finished: bool = false,
    code: c_int = 0, // 0: success, else the G_IO_ERROR code
    message: [256]u8 = @splat(0),
    progress: u32 = 0,
    last_cur: i64 = 0,
    last_total: i64 = 0,
    start_ms: i64 = 0,
    done_ms: i64 = 0,
    order_ok: bool = true,
};

fn onOpProgress(obj: c.gpointer, cur: i64, total: i64, data: c.gpointer) callconv(.c) void {
    _ = obj;
    const r: *OpRun = @ptrCast(@alignCast(data));
    if (r.finished) r.order_ok = false;
    r.progress += 1;
    r.last_cur = cur;
    r.last_total = total;
}

fn onOpFinished(obj: c.gpointer, err: ?*c.GError, data: c.gpointer) callconv(.c) void {
    _ = obj;
    const r: *OpRun = @ptrCast(@alignCast(data));
    if (r.finished) r.order_ok = false;
    r.finished = true;
    r.done_ms = nowMs();
    if (err) |e| {
        r.code = e.code;
        const m = std.mem.span(e.message);
        const n = @min(m.len, r.message.len - 1);
        @memcpy(r.message[0..n], m[0..n]);
    }
}

fn newOp(op: c_int, src: [*c]const u8, dest: [*c]const u8, flags: c_uint) ?*c.GObject {
    const t = c.g_type_from_name("GungnirFileOp");
    if (t == 0) return null;
    const obj = if (dest != null)
        c.g_object_new(t, "operation", op, "source", src, "destination", dest, "flags", flags, @as(?*anyopaque, null))
    else
        c.g_object_new(t, "operation", op, "source", src, "flags", flags, @as(?*anyopaque, null));
    return @ptrCast(@alignCast(obj));
}

/// Start `obj` and run the main context until "finished" (bounded). `cancel_after_ms`
/// cancels the GCancellable that long after the start (negative: never).
fn runOpObj(obj: *c.GObject, r: *OpRun, cancel_after_ms: i64) ?[*:0]const u8 {
    _ = c.g_signal_connect_data(obj, "progress", @ptrCast(&onOpProgress), r, null, 0);
    _ = c.g_signal_connect_data(obj, "finished", @ptrCast(&onOpFinished), r, null, 0);
    const cancellable = c.g_cancellable_new();
    defer c.g_object_unref(cancellable);
    var ok: c.gboolean = 0;
    r.start_ms = nowMs();
    c.g_signal_emit_by_name(obj, "start", cancellable, &ok);
    if (nowMs() - r.start_ms > max_start_ms) return "GungnirFileOp start blocked the caller";
    if (ok == 0) return "GungnirFileOp start returned FALSE";
    var again: c.gboolean = 1;
    c.g_signal_emit_by_name(obj, "start", cancellable, &again);
    if (again != 0) return "a second start was accepted";
    var cancelled = false;
    while (!r.finished) {
        if (nowMs() - r.start_ms > 30_000) return "GungnirFileOp did not finish within 30 s";
        if (!cancelled and cancel_after_ms >= 0 and nowMs() - r.start_ms >= cancel_after_ms) {
            c.g_cancellable_cancel(cancellable);
            cancelled = true;
        }
        if (c.g_main_context_iteration(null, 0) == 0) c.g_usleep(1000);
    }
    if (!r.order_ok) return "GungnirFileOp signals out of order (progress after finished, or two finished)";
    return null;
}

fn runOp(op: c_int, src: [*c]const u8, dest: [*c]const u8, flags: c_uint, r: *OpRun) ?[*:0]const u8 {
    const obj = newOp(op, src, dest, flags) orelse return "GungnirFileOp is not registered";
    defer c.g_object_unref(obj);
    return runOpObj(obj, r, -1);
}

fn expectOp(op: c_int, src: [*c]const u8, dest: [*c]const u8, flags: c_uint, want: c_int, what: [*:0]const u8) ?[*:0]const u8 {
    var r: OpRun = .{};
    if (runOp(op, src, dest, flags, &r)) |w| return w;
    if (r.code != want) {
        c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: %s: code %d (want %d): %s", what, r.code, want, @as([*:0]const u8, @ptrCast(&r.message)));
        return what;
    }
    return null;
}

fn writeFile(path: [*c]const u8, data: []const u8) bool {
    return c.g_file_set_contents(path, data.ptr, @intCast(data.len), null) != 0;
}

fn fileExists(path: [*c]const u8) bool {
    return c.g_file_test(path, c.G_FILE_TEST_EXISTS) != 0 or c.g_file_test(path, c.G_FILE_TEST_IS_SYMLINK) != 0;
}

/// No `.gungnir-*.tmp` left behind in `dir`.
fn noTempFiles(dir: [*c]const u8) bool {
    const d = c.g_dir_open(dir, 0, null) orelse return false;
    defer c.g_dir_close(d);
    while (c.g_dir_read_name(d)) |name| {
        const n = std.mem.span(name);
        if (std.mem.startsWith(u8, n, ".gungnir-")) return false;
    }
    return true;
}

fn statOf(path: [*c]const u8) ?linux.Statx {
    var st: linux.Statx = undefined;
    const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .MTIME = true, .SIZE = true };
    if (linux.errno(linux.statx(linux.AT.FDCWD, path, linux.AT.SYMLINK_NOFOLLOW, mask, &st)) != .SUCCESS) return null;
    return st;
}

/// GungnirFileOp against the real daemon (a test-hooks build), then slowed down for
/// cancellation, with a fake hung mount for the refusal, and with no daemon at all.
fn checkFileOps(ctx: *Ctx) ?[*:0]const u8 {
    if (checkGungnirFast()) |what| return what;
    if (expectState(1, 5_000, 0)) |what| return what;
    const dir = tmpPath(ctx.tmp_dir, "ops");
    defer c.g_free(dir);
    if (linux.errno(linux.mkdirat(linux.AT.FDCWD, dir, 0o700)) != .SUCCESS) return "could not create the ops dir";
    defer {
        // Whatever a failed check left behind: the test dir is private and ours.
        const argv = [_][*c]const u8{ "rm", "-rf", "--", dir, null };
        _ = c.g_spawn_sync(null, @ptrCast(@constCast(&argv)), null, c.G_SPAWN_SEARCH_PATH, null, null, null, null, null, null);
    }
    const a = tmpPath(dir, "a");
    defer c.g_free(a);
    const b = tmpPath(dir, "b");
    defer c.g_free(b);
    const m = tmpPath(dir, "m");
    defer c.g_free(m);

    // Copy with all metadata: content, mode, mtime and metadata::* follow; progress seen.
    {
        const size = 4 << 20;
        const data = std.heap.c_allocator.alloc(u8, size) catch return "out of memory";
        defer std.heap.c_allocator.free(data);
        for (data, 0..) |*x, i| x.* = @truncate((i *% 2654435761) >> 13);
        if (!writeFile(a, data)) return "could not write the source";
        if (linux.errno(linux.chmod(a, 0o640)) != .SUCCESS) return "chmod";
        const ts = [2]linux.timespec{ .{ .sec = 1_000_000_000, .nsec = 123_456_789 }, .{ .sec = 1_000_000_000, .nsec = 123_456_789 } };
        if (linux.errno(linux.utimensat(linux.AT.FDCWD, a, &ts, 0)) != .SUCCESS) return "utimensat";
        const fa = c.g_file_new_for_path(a);
        defer c.g_object_unref(fa);
        var err: [*c]c.GError = null;
        if (c.g_file_set_attribute_string(fa, "metadata::k", "copied", c.G_FILE_QUERY_INFO_NONE, null, &err) == 0) {
            logError("set", err);
            return "metadata set on the source failed";
        }
        var r: OpRun = .{};
        if (runOp(1, a, b, c.G_FILE_COPY_ALL_METADATA, &r)) |w| return w;
        if (r.code != 0) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: copy: %s", @as([*:0]const u8, @ptrCast(&r.message)));
            return "copy failed";
        }
        if (r.progress == 0 or r.last_total != size) return "copy reported no (or wrong) progress";
        var got: [*c]u8 = null;
        var len: c.gsize = 0;
        if (c.g_file_get_contents(b, &got, &len, null) == 0) return "could not read the copy";
        defer c.g_free(got);
        if (len != size or !std.mem.eql(u8, got[0..len], data)) return "the copy's content differs";
        const st = statOf(b) orelse return "stat of the copy";
        if (st.mode & 0o7777 != 0o640) return "the copy's mode differs";
        if (st.mtime.sec != 1_000_000_000 or st.mtime.nsec != 123_456_789) return "the copy's mtime differs";
        if (!noTempFiles(dir)) return "copy left a temp file";
        const fb = c.g_file_new_for_path(b);
        defer c.g_object_unref(fb);
        var slow = false;
        const info = queryTimed(fb, "metadata::k", &slow) orelse return "query of the copy failed";
        defer c.g_object_unref(info);
        if (!stringAttr(info, "metadata::k", "copied")) return "metadata did not follow the copy (ALL_METADATA)";
    }
    // Copy without ALL_METADATA: no metadata rows; existing destination: EXISTS; OVERWRITE.
    {
        const c2 = tmpPath(dir, "c2");
        defer c.g_free(c2);
        if (expectOp(1, a, c2, 0, 0, "plain copy")) |w| return w;
        const f = c.g_file_new_for_path(c2);
        defer c.g_object_unref(f);
        var slow = false;
        const info = queryTimed(f, "metadata::k", &slow) orelse return "query of the plain copy failed";
        defer c.g_object_unref(info);
        if (hasMetadata(info)) return "metadata followed a copy without ALL_METADATA";
        if (expectOp(1, a, c2, 0, c.G_IO_ERROR_EXISTS, "copy onto an existing file")) |w| return w;
        if (expectOp(1, b, c2, c.G_FILE_COPY_OVERWRITE, 0, "copy with OVERWRITE")) |w| return w;
        if (expectOp(3, c2, null, 0, 0, "delete")) |w| return w;
        if (fileExists(c2)) return "delete left the file";
    }
    // Move: the file and its metadata.
    {
        if (expectOp(2, b, m, 0, 0, "move")) |w| return w;
        if (fileExists(b) or !fileExists(m)) return "move did not move";
        const f = c.g_file_new_for_path(m);
        defer c.g_object_unref(f);
        var slow = false;
        const info = queryTimed(f, "metadata::k", &slow) orelse return "query after move failed";
        defer c.g_object_unref(info);
        if (!stringAttr(info, "metadata::k", "copied")) return "metadata did not follow the move";
    }
    // Errors.
    {
        const none = tmpPath(dir, "none");
        defer c.g_free(none);
        if (expectOp(1, none, b, 0, c.G_IO_ERROR_NOT_FOUND, "copy of a missing file")) |w| return w;
        if (expectOp(3, none, null, 0, c.G_IO_ERROR_NOT_FOUND, "delete of a missing file")) |w| return w;
        const sub = tmpPath(dir, "sub");
        defer c.g_free(sub);
        if (linux.errno(linux.mkdirat(linux.AT.FDCWD, sub, 0o700)) != .SUCCESS) return "mkdir sub";
        const inner = tmpPath(sub, "x");
        defer c.g_free(inner);
        if (!writeFile(inner, "x")) return "write sub/x";
        if (expectOp(1, sub, b, 0, c.G_IO_ERROR_WOULD_RECURSE, "copy of a directory")) |w| return w;
        if (expectOp(3, sub, null, 0, c.G_IO_ERROR_NOT_EMPTY, "delete of a non-empty dir")) |w| return w;
        if (expectOp(1, "relative", b, 0, c.G_IO_ERROR_INVALID_ARGUMENT, "relative path")) |w| return w;
        if (expectOp(1, a, b, c.G_FILE_COPY_BACKUP, c.G_IO_ERROR_NOT_SUPPORTED, "BACKUP flag")) |w| return w;
        if (expectOp(5, m, null, 0, 0, "fsync")) |w| return w;
        if (expectOp(4, sub, null, 0, 0, "delete tree")) |w| return w;
        if (fileExists(sub)) return "delete-tree left the directory";
    }
    // Already-cancelled: CANCELLED without a round trip.
    {
        const obj = newOp(1, a, b, 0) orelse return "GungnirFileOp is not registered";
        defer c.g_object_unref(obj);
        var r: OpRun = .{};
        if (runOpObj(obj, &r, 0)) |w| return w;
        if (r.code != c.G_IO_ERROR_CANCELLED and r.code != 0) return "a cancel at once gave the wrong result";
        if (r.code == 0) _ = linux.unlink(b);
    }

    // Mid-operation cancellation: every step of the daemon takes 300 ms now.
    if (c.g_setenv("GUNGNIR_TEST_SLOW_OPS_MS", "300", 1) == 0) return "g_setenv GUNGNIR_TEST_SLOW_OPS_MS";
    ctx.stopDaemon();
    if (ctx.startDaemon()) |what| return what;
    c.g_unsetenv("GUNGNIR_TEST_SLOW_OPS_MS");
    {
        const obj = newOp(1, a, b, 0) orelse return "GungnirFileOp is not registered";
        defer c.g_object_unref(obj);
        var r: OpRun = .{};
        if (runOpObj(obj, &r, 150)) |w| return w;
        if (r.code != c.G_IO_ERROR_CANCELLED) {
            c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir itest: cancel: code %d: %s", r.code, @as([*:0]const u8, @ptrCast(&r.message)));
            return "a cancelled copy did not report CANCELLED";
        }
        if (r.done_ms - r.start_ms > 2_000) return "cancellation took too long";
        if (fileExists(b)) return "a cancelled copy left its destination";
        // The daemon removes its temp file as the op unwinds.
        const t0 = nowMs();
        while (!noTempFiles(dir)) {
            if (nowMs() - t0 > 2_000) return "a cancelled copy left a temp file";
            c.g_usleep(10 * 1000);
        }
    }

    // A hung mount: refused by the module's health cache within max_hung_call_ms.
    {
        const hung = tmpPath(ctx.tmp_dir, "fake-hung");
        defer c.g_free(hung);
        if (linux.errno(linux.mkdirat(linux.AT.FDCWD, hung, 0o700)) != .SUCCESS) return "could not create the fake mount dir";
        defer _ = linux.rmdir(hung);
        const hf = tmpPath(hung, "f");
        defer c.g_free(hf);
        if (c.g_setenv("GUNGNIR_TEST_FAKE_HUNG_MOUNT", hung, 1) == 0) return "g_setenv GUNGNIR_TEST_FAKE_HUNG_MOUNT";
        ctx.stopDaemon();
        if (ctx.startDaemon()) |what| return what;
        c.g_unsetenv("GUNGNIR_TEST_FAKE_HUNG_MOUNT");
        // Reconnect and learn the mount's state from the pushed events.
        const t0 = nowMs();
        while (unhealthyMounts() < 1) {
            if (nowMs() - t0 > 10_000) return "no mount-health event reached the module";
            // A metadata call drives the module's reconnect.
            const f = c.g_file_new_for_path(m);
            defer c.g_object_unref(f);
            const info = c.g_file_query_info(f, "metadata::k", c.G_FILE_QUERY_INFO_NONE, null, null);
            if (info != null) c.g_object_unref(info);
            c.g_usleep(20 * 1000);
        }
        var r: OpRun = .{};
        if (runOp(1, m, hf, 0, &r)) |w| return w;
        if (r.code != c.G_IO_ERROR_TIMED_OUT) return "a copy into a hung mount was not refused with TIMED_OUT";
        if (r.done_ms - r.start_ms > max_hung_call_ms) return "a copy into a hung mount was not refused fast";
        if (!contains(@ptrCast(&r.message), "health monitor")) return "the refusal did not come from the health cache";
    }

    // No daemon: NOT_SUPPORTED, quickly.
    ctx.stopDaemon();
    {
        var r: OpRun = .{};
        if (runOp(5, m, null, 0, &r)) |w| return w;
        if (r.code != c.G_IO_ERROR_NOT_SUPPORTED) return "an op without a daemon gave the wrong error";
        if (r.done_ms - r.start_ms > 1_000) return "an op without a daemon took too long";
    }
    if (checkGungnirFast()) |what| return what;
    return null;
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
    // Then metadata calls answer at once: no metadata, and a set fails cleanly. (While
    // still connecting they wait at most their own budget: the gmeta/link unit tests.)
    if (checkNoMetadata(tmp_dir, &.{c.G_IO_ERROR_NOT_SUPPORTED})) |what| return fail(what);
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
    if (checkNoMetadata(tmp_dir, &.{c.G_IO_ERROR_NOT_SUPPORTED})) |what| return fail(what);
    return 0;
}

/// Mounts plus volumes of `vm` that are Gungnir objects (GungnirMount, GungnirVolume).
fn gungnirObjects(vm: *c.GVolumeMonitor) usize {
    var n: usize = 0;
    for ([_][*c]c.GList{ c.g_volume_monitor_get_mounts(vm), c.g_volume_monitor_get_volumes(vm) }) |list| {
        defer c.g_list_free_full(list, @ptrCast(&c.g_object_unref));
        var curr: ?*c.GList = list;
        while (curr) |node| : (curr = node.*.next) {
            const name = c.g_type_name_from_instance(@ptrCast(@alignCast(node.*.data)));
            if (name != null and std.mem.startsWith(u8, std.mem.span(name), "Gungnir")) n += 1;
        }
    }
    return n;
}

/// D-004 / BC-HC-F01: without GIO_USE_VOLUME_MONITOR=gungnir the module's volume monitor
/// is never active: registered only on the native extension point at -100 (never on the
/// one GUnionVolumeMonitor adds to every process), unsupported, and g_volume_monitor_get()
/// shows no Gungnir mount or volume. Call after the modules are loaded.
fn checkVolmonOff() ?[*:0]const u8 {
    if (c.g_getenv("GIO_USE_VOLUME_MONITOR") != null) return "GIO_USE_VOLUME_MONITOR is set";
    const union_ep = c.g_io_extension_point_lookup(c.G_VOLUME_MONITOR_EXTENSION_POINT_NAME);
    if (union_ep != null and c.g_io_extension_point_get_extension_by_name(union_ep, "gungnir") != null)
        return "the volume monitor is registered on the union (every process) extension point";
    const native_ep = c.g_io_extension_point_lookup(c.G_NATIVE_VOLUME_MONITOR_EXTENSION_POINT_NAME);
    const ext = c.g_io_extension_point_get_extension_by_name(native_ep, "gungnir") orelse
        return "the volume monitor is not registered on the native extension point";
    if (c.g_io_extension_get_priority(ext) != -100) return "the native volume monitor priority is not -100";
    const klass: *c.GVolumeMonitorClass = @ptrCast(@alignCast(c.g_io_extension_ref_class(ext)));
    defer c.g_type_class_unref(klass);
    if (klass.is_supported.?() != 0) return "the volume monitor says it is supported without the opt-in";
    const vm = c.g_volume_monitor_get();
    defer c.g_object_unref(vm);
    if (gungnirObjects(vm) != 0) return "g_volume_monitor_get() lists Gungnir mounts or volumes without the opt-in";
    return null;
}

/// volmon-off: the VFS opted in (GIO_USE_VFS=gungnir), the volume monitor not.
fn runVolmonOff(tmp_arg: [*c]u8) c_int {
    _ = tmp_arg;
    if (checkGungnirFast()) |what| return fail(what);
    if (checkVolmonOff()) |what| return fail(what);
    return 0;
}

/// volmon: GIO_USE_VOLUME_MONITOR=gungnir makes it the native monitor of
/// g_volume_monitor_get(), and the type works on its own.
fn runVolmon(tmp_arg: [*c]u8) c_int {
    _ = tmp_arg;
    if (c.g_setenv("GIO_USE_VOLUME_MONITOR", "gungnir", 1) == 0) return fail("g_setenv GIO_USE_VOLUME_MONITOR");
    if (checkGungnirFast()) |what| return fail(what);
    {
        const native_ep = c.g_io_extension_point_lookup(c.G_NATIVE_VOLUME_MONITOR_EXTENSION_POINT_NAME);
        const ext = c.g_io_extension_point_get_extension_by_name(native_ep, "gungnir") orelse
            return fail("the volume monitor is not registered on the native extension point");
        const klass: *c.GVolumeMonitorClass = @ptrCast(@alignCast(c.g_io_extension_ref_class(ext)));
        defer c.g_type_class_unref(klass);
        if (klass.is_supported.?() == 0) return fail("the volume monitor is unsupported with GIO_USE_VOLUME_MONITOR=gungnir");
        const dvm = c.g_volume_monitor_get();
        defer c.g_object_unref(dvm);
        if (gungnirObjects(dvm) == 0) return fail("g_volume_monitor_get() lists no Gungnir mount with GIO_USE_VOLUME_MONITOR=gungnir");
    }
    const vm_type = c.g_type_from_name("GungnirVolumeMonitor");
    if (vm_type == 0) return fail("GungnirVolumeMonitor type is not registered");
    const vm_obj = c.g_object_new(vm_type, @as(?*const u8, null));
    if (vm_obj == null) return fail("could not instantiate GungnirVolumeMonitor");
    const vm: *c.GVolumeMonitor = @ptrCast(@alignCast(vm_obj));
    defer c.g_object_unref(vm);

    const mounts = c.g_volume_monitor_get_mounts(vm);
    if (mounts == null) return fail("g_volume_monitor_get_mounts returned NULL");
    defer c.g_list_free_full(mounts, @ptrCast(&c.g_object_unref));

    var found_root = false;
    var curr: ?*c.GList = mounts;
    while (curr) |node| : (curr = node.*.next) {
        const m: *c.GMount = @ptrCast(@alignCast(node.*.data));
        const root = c.g_mount_get_root(m);
        if (root) |r| {
            defer c.g_object_unref(r);
            const path = c.g_file_get_path(r);
            if (path) |p| {
                defer c.g_free(p);
                if (std.mem.eql(u8, std.mem.span(p), "/")) found_root = true;
            }
        }
    }
    if (!found_root) return fail("root mount / not found in GungnirVolumeMonitor mounts");

    const vols = c.g_volume_monitor_get_volumes(vm);
    if (vols == null) return fail("g_volume_monitor_get_volumes returned NULL");
    defer c.g_list_free_full(vols, @ptrCast(&c.g_object_unref));

    return 0;
}

/// The line gio-querymodules must write for the module: every extension point it
/// implements, so an installed module is loaded for the volume monitor too.
const cache_line = "libgiogungnir.so: gio-vfs,gio-native-volume-monitor";

/// Path of gio-querymodules: PATH (Arch), else pkg-config's gio_querymodules (Debian keeps
/// it in a libexec dir). g_free the result.
fn findQueryModules() ?[*:0]u8 {
    if (c.g_find_program_in_path("gio-querymodules")) |p| return @ptrCast(p);
    var out: [*c]u8 = null;
    var status: c_int = 0;
    var argv = [_][*c]u8{ @constCast("pkg-config"), @constCast("--variable=gio_querymodules"), @constCast("gio-2.0"), null };
    if (c.g_spawn_sync(null, &argv, null, c.G_SPAWN_SEARCH_PATH | c.G_SPAWN_STDERR_TO_DEV_NULL, null, null, &out, null, &status, null) == 0) return null;
    defer c.g_free(out);
    if (c.g_spawn_check_wait_status(status, null) == 0 or out == null) return null;
    const p = std.mem.trim(u8, std.mem.span(out), " \t\r\n");
    if (p.len == 0) return null;
    const dup: [*:0]u8 = @ptrCast(c.g_strndup(p.ptr, p.len));
    if (c.g_file_test(dup, c.G_FILE_TEST_IS_EXECUTABLE) == 0) {
        c.g_free(dup);
        return null;
    }
    return dup;
}

const Count = struct { gungnir: c_long, all: c_long, direct: c_long, distinct: c_long, registered: c_long, linked: c_long, ref: c_long, refeq: c_long, giolines: c_long, gioroots: c_long };
const count_keys = [_][]const u8{ "gungnir", "all", "direct", "distinct", "registered", "linked", "ref", "refeq", "giolines", "gioroots" };

/// Runs `self <dir> volmon-count <variant>` and parses its COUNT line.
fn countIn(self: [*c]u8, dir: [*:0]const u8, variant: [*:0]const u8) ?Count {
    var argv = [_][*c]u8{ self, @constCast(dir), @constCast("volmon-count"), @constCast(variant), null };
    var out: [*c]u8 = null;
    var status: c_int = 0;
    var err: [*c]c.GError = null;
    if (c.g_spawn_sync(null, &argv, null, c.G_SPAWN_DEFAULT, null, null, &out, null, &status, &err) == 0) {
        logError("spawn volmon-count", err);
        return null;
    }
    defer c.g_free(out);
    if (c.g_spawn_check_wait_status(status, null) == 0 or out == null) return null;
    const text = std.mem.span(out);
    const at = std.mem.indexOf(u8, text, "COUNT ") orelse return null;
    const line_end = std.mem.indexOfScalarPos(u8, text, at, '\n') orelse text.len;
    var vals: [count_keys.len]c_long = undefined;
    var it = std.mem.tokenizeScalar(u8, text[at + "COUNT ".len .. line_end], ' ');
    for (count_keys, &vals) |k, *v| {
        const tok = it.next() orelse return null;
        if (tok.len <= k.len or !std.mem.startsWith(u8, tok, k) or tok[k.len] != '=') return null;
        v.* = std.fmt.parseInt(c_long, tok[k.len + 1 ..], 10) catch return null;
    }
    const r: Count = .{ .gungnir = vals[0], .all = vals[1], .direct = vals[2], .distinct = vals[3], .registered = vals[4], .linked = vals[5], .ref = vals[6], .refeq = vals[7], .giolines = vals[8], .gioroots = vals[9] };
    std.debug.print("gungnir itest volmon-installed: {s}: {s}\n", .{ variant, text[at + "COUNT ".len .. line_end] });
    return r;
}

/// The reference set for the Gungnir monitor (D-062): the file URIs of the mount points
/// of /proc/self/mountinfo that the module's documented filter accepts (volmon.zig
/// isStorageFs), parsed and filtered here independently of the module. Each mount
/// point once.
fn referenceRoots(out: *c.GHashTable) bool {
    var raw: [*c]u8 = null;
    var len: c.gsize = 0;
    if (c.g_file_get_contents("/proc/self/mountinfo", &raw, &len, null) == 0) return false;
    defer c.g_free(raw);
    const ignored = [_][]const u8{ "proc", "sysfs", "devpts", "cgroup", "cgroup2", "pstore", "bpf", "autofs", "hugetlbfs", "mqueue", "debugfs", "tracefs", "securityfs", "configfs", "fusectl", "devtmpfs", "binfmt_misc", "efivarfs", "nsfs", "rpc_pipefs" };
    var lines = std.mem.splitScalar(u8, raw[0..len], '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        var i: usize = 0;
        var mp_raw: []const u8 = "";
        while (i < 5) : (i += 1) mp_raw = f.next() orelse break;
        if (i < 5) continue;
        const fstype = while (f.next()) |t| {
            if (std.mem.eql(u8, t, "-")) break f.next() orelse continue;
        } else continue;
        var buf: [1024]u8 = undefined;
        var n: usize = 0;
        var k: usize = 0;
        while (k < mp_raw.len and n < buf.len - 1) : (n += 1) {
            if (mp_raw[k] == '\\' and k + 3 < mp_raw.len) {
                if (std.fmt.parseInt(u8, mp_raw[k + 1 .. k + 4], 8)) |b| {
                    buf[n] = b;
                    k += 4;
                    continue;
                } else |_| {}
            }
            buf[n] = mp_raw[k];
            k += 1;
        }
        buf[n] = 0;
        const mp = buf[0..n];
        const skip = for (ignored) |ig| {
            if (std.mem.eql(u8, fstype, ig)) break true;
        } else if (std.mem.eql(u8, fstype, "tmpfs"))
            !(std.mem.eql(u8, mp, "/tmp") or std.mem.startsWith(u8, mp, "/media") or std.mem.startsWith(u8, mp, "/run/media") or std.mem.startsWith(u8, mp, "/mnt"))
        else
            std.mem.startsWith(u8, mp, "/var/lib/docker");
        if (skip) continue;
        const uri = c.g_filename_to_uri(@ptrCast(&buf), null, null) orelse continue;
        _ = c.g_hash_table_add(out, uri);
    }
    return true;
}

/// Every Gungnir mount of `vm` has a volume whose mount is that same mount (DIB-F016);
/// returns how many do.
fn linkedMounts(vm: *c.GVolumeMonitor) c_long {
    var n: c_long = 0;
    const list = c.g_volume_monitor_get_mounts(vm);
    defer c.g_list_free_full(list, @ptrCast(&c.g_object_unref));
    var curr: ?*c.GList = list;
    while (curr) |node| : (curr = node.*.next) {
        const m: *c.GMount = @ptrCast(@alignCast(node.*.data));
        const name = c.g_type_name_from_instance(@ptrCast(@alignCast(m)));
        if (name == null or !std.mem.startsWith(u8, std.mem.span(name), "Gungnir")) continue;
        const v = c.g_mount_get_volume(m) orelse continue;
        defer c.g_object_unref(v);
        const back = c.g_volume_get_mount(v) orelse continue;
        defer c.g_object_unref(back);
        if (back == m) n += 1;
    }
    return n;
}

/// `gio mount -l` in this environment: how many mount lines it prints, and how many
/// distinct roots they name (each root once: lines == roots).
fn gioMountList(lines_out: *c_long, roots_out: *c_long) bool {
    const r = runGio(&.{ "mount", "-l" }) orelse return false;
    defer freeCli(r);
    if (!r.ok or r.out == null) return false;
    const seen = c.g_hash_table_new_full(c.g_str_hash, c.g_str_equal, c.g_free, null);
    defer c.g_hash_table_destroy(seen);
    var lines: c_long = 0;
    var it = std.mem.splitScalar(u8, std.mem.span(r.out), '\n');
    while (it.next()) |line| {
        const t = std.mem.trimStart(u8, line, " ");
        if (!std.mem.startsWith(u8, t, "Mount(")) continue;
        const at = std.mem.indexOf(u8, t, " -> ") orelse continue;
        lines += 1;
        const uri = t[at + 4 ..];
        _ = c.g_hash_table_add(seen, c.g_strndup(uri.ptr, uri.len));
    }
    lines_out.* = lines;
    roots_out.* = @intCast(c.g_hash_table_size(seen));
    return true;
}

/// Child of volmon-installed: GIO_MODULE_DIR is the indexed copy; `variant` is none
/// (no GIO_* opt-in), vfs (GIO_USE_VFS=gungnir only) or volmon
/// (GIO_USE_VOLUME_MONITOR=gungnir only). Prints the Gungnir mounts of
/// g_volume_monitor_get(), all its mounts, the mounts of a GungnirVolumeMonitor made
/// directly (one per mount point it accepts), their distinct mount roots, and whether the
/// module's types are registered (the module was loaded).
fn runVolmonCount(variant: []const u8) c_int {
    c.g_unsetenv("GIO_USE_VFS");
    if (std.mem.eql(u8, variant, "vfs")) {
        if (c.g_setenv("GIO_USE_VFS", "gungnir", 1) == 0) return fail("g_setenv GIO_USE_VFS");
    } else if (std.mem.eql(u8, variant, "volmon")) {
        if (c.g_setenv("GIO_USE_VOLUME_MONITOR", "gungnir", 1) == 0) return fail("g_setenv GIO_USE_VOLUME_MONITOR");
    } else if (!std.mem.eql(u8, variant, "none")) return fail("volmon-count: unknown variant");
    // As an application does: the default VFS first, then the volume monitor.
    _ = c.g_vfs_get_default();
    const vm = c.g_volume_monitor_get();
    defer c.g_object_unref(vm);
    var mounts_gungnir: c_long = 0;
    var mounts_all: c_long = 0;
    {
        const list = c.g_volume_monitor_get_mounts(vm);
        defer c.g_list_free_full(list, @ptrCast(&c.g_object_unref));
        var curr: ?*c.GList = list;
        while (curr) |node| : (curr = node.*.next) {
            mounts_all += 1;
            const name = c.g_type_name_from_instance(@ptrCast(@alignCast(node.*.data)));
            if (name != null and std.mem.startsWith(u8, std.mem.span(name), "Gungnir")) mounts_gungnir += 1;
        }
    }
    const linked = linkedMounts(vm);
    var direct: c_long = 0;
    var distinct: c_long = 0;
    var ref: c_long = -1;
    var refeq: c_long = 0;
    const vm_type = c.g_type_from_name("GungnirVolumeMonitor");
    if (vm_type != 0) {
        const obj = c.g_object_new(vm_type, @as(?*const u8, null)) orelse return fail("could not instantiate GungnirVolumeMonitor");
        defer c.g_object_unref(obj);
        const list = c.g_volume_monitor_get_mounts(@ptrCast(@alignCast(obj)));
        defer c.g_list_free_full(list, @ptrCast(&c.g_object_unref));
        const seen = c.g_hash_table_new_full(c.g_str_hash, c.g_str_equal, c.g_free, null);
        defer c.g_hash_table_destroy(seen);
        var curr: ?*c.GList = list;
        while (curr) |node| : (curr = node.*.next) {
            direct += 1;
            const root = c.g_mount_get_root(@ptrCast(@alignCast(node.*.data))) orelse continue;
            defer c.g_object_unref(root);
            _ = c.g_hash_table_add(seen, c.g_file_get_uri(root));
        }
        distinct = @intCast(c.g_hash_table_size(seen));
        const want = c.g_hash_table_new_full(c.g_str_hash, c.g_str_equal, c.g_free, null);
        defer c.g_hash_table_destroy(want);
        if (referenceRoots(want.?)) {
            ref = @intCast(c.g_hash_table_size(want));
            var iter: c.GHashTableIter = undefined;
            c.g_hash_table_iter_init(&iter, want);
            var key: c.gpointer = null;
            refeq = @intFromBool(ref == distinct);
            while (c.g_hash_table_iter_next(&iter, &key, null) != 0) {
                if (c.g_hash_table_contains(seen, key) == 0) {
                    refeq = 0;
                    c.g_print("missing from the Gungnir monitor: %s\n", @as([*c]const u8, @ptrCast(key)));
                }
            }
        }
    }
    var giolines: c_long = -1;
    var gioroots: c_long = -1;
    if (!gioMountList(&giolines, &gioroots)) c.g_print("gio mount -l failed\n");
    c.g_print("COUNT gungnir=%ld all=%ld direct=%ld distinct=%ld registered=%ld linked=%ld ref=%ld refeq=%ld giolines=%ld gioroots=%ld\n", mounts_gungnir, mounts_all, direct, distinct, @as(c_long, @intFromBool(vm_type != 0)), linked, ref, refeq, giolines, gioroots);
    return 0;
}

/// volmon-installed (BC-HC-F01 v2, D-049, D-051): the module as a package installs it, in
/// a module dir indexed by gio-querymodules, so GIO loads it through giomodule.cache, not
/// by scanning the dir. With no env and with GIO_USE_VFS=gungnir only, no Gungnir mount
/// appears; with GIO_USE_VOLUME_MONITOR=gungnir the default monitor lists exactly one
/// mount per mount point the Gungnir monitor accepts (N > 0, no duplicates), N is the
/// independently filtered /proc/self/mountinfo set, every mount's volume points back at
/// it, and `gio mount -l` names each root once (D-062, DIB-F016).
fn runVolmonInstalled(self: [*c]u8, module_dir: [*c]u8, tmp_arg: [*c]u8) c_int {
    const dir = privateDir(tmp_arg, "volmon-installed") orelse return fail("cannot create a private directory");
    defer c.g_free(dir);
    const src = tmpPath(@ptrCast(module_dir), "libgiogungnir.so");
    defer c.g_free(src);
    const dst = tmpPath(dir, "libgiogungnir.so");
    defer c.g_free(dst);
    const cache = tmpPath(dir, "giomodule.cache");
    defer c.g_free(cache);
    defer {
        removeFile(dst);
        removeFile(cache);
        _ = linux.rmdir(dir);
    }
    {
        var data: [*c]u8 = null;
        var len: c.gsize = 0;
        if (c.g_file_get_contents(src, &data, &len, null) == 0) return fail("cannot read the built module");
        defer c.g_free(data);
        if (c.g_file_set_contents(dst, data, @intCast(len), null) == 0) return fail("cannot copy the module");
    }
    {
        const qm = findQueryModules() orelse return fail("gio-querymodules not found (PATH, pkg-config gio_querymodules)");
        defer c.g_free(qm);
        var argv = [_][*c]u8{ qm, dir, null };
        var status: c_int = 0;
        if (c.g_spawn_sync(null, &argv, null, c.G_SPAWN_DEFAULT, null, null, null, null, &status, null) == 0 or
            c.g_spawn_check_wait_status(status, null) == 0) return fail("gio-querymodules failed");
    }
    {
        var data: [*c]u8 = null;
        if (c.g_file_get_contents(cache, &data, null, null) == 0) return fail("gio-querymodules wrote no giomodule.cache");
        defer c.g_free(data);
        std.debug.print("gungnir itest volmon-installed: giomodule.cache: {s}", .{data});
        const text = std.mem.trimEnd(u8, std.mem.span(data), "\n");
        if (!std.mem.eql(u8, text, cache_line)) return fail("giomodule.cache does not map the module to gio-vfs and gio-native-volume-monitor");
    }
    const none = countIn(self, dir, "none") orelse return fail("volmon-count none failed");
    const vfs = countIn(self, dir, "vfs") orelse return fail("volmon-count vfs failed");
    const vol = countIn(self, dir, "volmon") orelse return fail("volmon-count volmon failed");
    if (none.gungnir != 0) return fail("installed module, no env: g_volume_monitor_get() lists Gungnir mounts");
    if (vfs.gungnir != 0) return fail("installed module, GIO_USE_VFS=gungnir only: g_volume_monitor_get() lists Gungnir mounts");
    if (vol.registered != 1) return fail("installed module, GIO_USE_VOLUME_MONITOR=gungnir: the module was not loaded");
    if (vol.direct <= 0) return fail("the Gungnir monitor accepts no mount point at all");
    if (vol.distinct != vol.direct) return fail("the Gungnir monitor lists a mount point twice");
    if (vol.gungnir != vol.direct) return fail("installed module, GIO_USE_VOLUME_MONITOR=gungnir: Gungnir mounts != mount points");
    if (vol.all != vol.gungnir) return fail("installed module, GIO_USE_VOLUME_MONITOR=gungnir: other monitors' mounts too");
    // D-062: the count is the filtered mountinfo set, each root once, not a fixed number.
    if (vol.ref <= 0) return fail("could not build the mountinfo reference set");
    if (vol.refeq != 1 or vol.direct != vol.ref) return fail("the Gungnir mounts are not exactly the filtered /proc/self/mountinfo set");
    // DIB-F016: every mount has its volume, and that volume's mount is the same mount.
    if (vol.linked != vol.gungnir) return fail("a Gungnir mount has no volume, or its volume's mount is another object");
    if (vol.giolines < 0) return fail("gio mount -l failed");
    if (vol.giolines != vol.gioroots) return fail("gio mount -l lists a mount root more than once");
    if (vol.gioroots != vol.ref) return fail("gio mount -l does not list exactly the filtered mountinfo set");
    return 0;
}

pub export fn main(argc: c_int, argv: [*c][*c]u8) c_int {
    if (argc < 3) return fail("usage: gungnir-itest <module-dir> <mode> [args]");
    const mode = std.mem.span(argv[2]);

    if (c.g_setenv("GIO_MODULE_DIR", argv[1], 1) == 0) return fail("g_setenv GIO_MODULE_DIR");
    // A volmon-installed child gets its indexed dir as argv[1], so this is the right dir.
    // GIO also scans every dir in GIO_EXTRA_MODULES; an inherited value (Flatpak, Nix,
    // custom sessions) could load gvfs's GDaemonVfs (priority 10) and break no-opt-in.
    c.g_unsetenv("GIO_EXTRA_MODULES");
    // Only the volmon mode opts in to the volume monitor; an inherited value must not.
    c.g_unsetenv("GIO_USE_VOLUME_MONITOR");

    if (std.mem.eql(u8, mode, "volmon-count") and argc == 4) return runVolmonCount(std.mem.span(argv[3]));
    if (std.mem.eql(u8, mode, "volmon-installed") and argc == 4) {
        c.g_unsetenv("GIO_USE_VFS");
        return runVolmonInstalled(argv[0], argv[1], argv[3]);
    }
    if (std.mem.eql(u8, mode, "no-opt-in")) {
        if (argc != 3) return fail("usage: no-opt-in takes no arguments");
        c.g_unsetenv("GIO_USE_VFS");
        if (checkVfs("GLocalVfs")) |what| return fail(what);
        c.g_unsetenv("GIO_USE_VOLUME_MONITOR");
        if (checkVolmonOff()) |what| return fail(what);
        return 0;
    }
    if (c.g_setenv("GIO_USE_VFS", "gungnir", 1) == 0) return fail("g_setenv GIO_USE_VFS");
    if (std.mem.eql(u8, mode, "opt-in") and argc == 4) return runMissing(argv[3]);
    if (std.mem.eql(u8, mode, "hung") and argc == 4) return runHung(argv[3]);
    if (std.mem.eql(u8, mode, "daemon") and argc == 5) return runDaemon(argv[3], argv[4], "daemon", &checkModuleConnects);
    if (std.mem.eql(u8, mode, "metadata") and argc == 5) return runDaemon(argv[3], argv[4], "metadata", &checkMetadata);
    if (std.mem.eql(u8, mode, "gio-metadata") and argc == 5) return runDaemon(argv[3], argv[4], "gio-metadata", &checkGioMetadata);
    if (std.mem.eql(u8, mode, "gio-cli") and argc == 5) return runDaemon(argv[3], argv[4], "gio-cli", &checkGioCli);
    if (std.mem.eql(u8, mode, "daemon-stopped") and argc == 5) return runDaemon(argv[3], argv[4], "daemon-stopped", &checkDaemonStopped);
    if (std.mem.eql(u8, mode, "ui-thread") and argc == 5) return runDaemon(argv[3], argv[4], "ui-thread", &checkUiThread);
    if (std.mem.eql(u8, mode, "hung-mount") and argc == 5) return runDaemon(argv[3], argv[4], "hung-mount", &checkHungMount);
    if (std.mem.eql(u8, mode, "file-ops") and argc == 5) return runDaemon(argv[3], argv[4], "file-ops", &checkFileOps);
    if (std.mem.eql(u8, mode, "volmon") and argc == 4) return runVolmon(argv[3]);
    if (std.mem.eql(u8, mode, "volmon-off") and argc == 4) return runVolmonOff(argv[3]);
    return fail("unknown mode or wrong argument count");
}
