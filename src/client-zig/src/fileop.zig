//! Asynchronous file operations through gungnird (milestone 8): the `GungnirFileOp`
//! GObject.
//!
//! Why a Gungnir-specific object and not GFile hooks: GIO gives a GVfs no say in how a
//! local file is copied, moved or deleted. GLocalFile's GFileIface (glocalfile.c) is
//! fixed by GLib: `g_file_copy` uses `iface->copy` (NULL for GLocalFile, so
//! `file_copy_fallback` in gfile.c, which reads and writes on the calling thread), `move`
//! is `g_local_file_move`, `delete_file`/`trash` are GLocalFile's own. The only private
//! GVfsClass slots GLocalFile calls are the metadata ones (`local_file_add_info`,
//! `local_file_set_attributes`, `local_file_removed`, `local_file_moved`, used since
//! milestone 6). Overriding copy/move would mean returning our own GFile type for every
//! `file://` path, which breaks `G_IS_LOCAL_FILE` checks inside GLib (copy fast paths,
//! monitors, portals) and in applications: hacking GIO internals. So the engine is
//! exposed as its own type instead, registered by the module (no new exported symbol):
//!
//!     GType t = g_type_from_name ("GungnirFileOp");   // after g_vfs_get_default ()
//!     GObject *op = g_object_new (t, "operation", 1, "source", "/a", "destination", "/b",
//!                                 "flags", G_FILE_COPY_ALL_METADATA, NULL);
//!     g_signal_connect (op, "progress", G_CALLBACK (on_progress), data); // gint64, gint64
//!     g_signal_connect (op, "finished", G_CALLBACK (on_finished), data); // GError* or NULL
//!     gboolean ok; g_signal_emit_by_name (op, "start", cancellable, &ok);
//!
//! Properties (construct-only): `operation` (1 copy, 2 move, 3 delete, 4 delete-tree, 5
//! fsync), `source`, `destination` (copy and move), `flags` (GFileCopyFlags; BACKUP is
//! not supported), `timeout-ms` (0: gungnird's default). "start" (an action signal)
//! returns TRUE once; then "finished" is emitted exactly once, and "progress" (current,
//! total bytes; coalesced) any number of times before it, all on the thread-default main
//! context of the thread that emitted "start". Errors are G_IO_ERROR codes (an errno from
//! the daemon via g_io_error_from_errno; a move with NO_FALLBACK_FOR_MOVE across
//! filesystems gives NOT_SUPPORTED, as GIO's own move does; no daemon: NOT_SUPPORTED).
//!
//! Never blocking: "start" only checks its arguments, reads the environment and starts a
//! "gungnir-op" GThread; that thread opens its own connection to gungnird (bounded by
//! connect_timeout_ms), sends the op and waits for its events in 50 ms slices, checking
//! the GCancellable (cancel is forwarded to the daemon, and reported at the latest
//! cancel_wait_ms later), the daemon's liveness and its deadlines (reply_timeout_ms for
//! the start's answer, the op's own timeout plus a grace, and stall_ms without any
//! event). Paths the mount health cache (milestone 7) reports hung are refused at once
//! with G_IO_ERROR_TIMED_OUT, without a connection. The first op pins the module
//! (a class reference that is never dropped), so a finishing op thread can never run
//! code from an unloaded library.
const std = @import("std");
const c = @import("c");
const ipc = @import("ipc.zig");
const rpc = @import("rpc.zig");
const health = @import("health.zig");
const proto = @import("proto.zig");
const gioerr = @import("gioerr.zig");
const linux = std.os.linux;

pub const type_name = "GungnirFileOp";

pub const msg_start = proto.msg_op_start;
pub const msg_cancel = proto.msg_op_cancel;
pub const msg_progress = proto.msg_op_progress;
pub const msg_done = proto.msg_op_done;

pub const op_copy: c_int = 1;
pub const op_move: c_int = 2;
pub const op_delete: c_int = 3;
pub const op_delete_tree: c_int = 4;
pub const op_fsync: c_int = 5;

pub const st_cancelled = proto.st_cancelled;
pub const st_os_error = proto.st_os_error;
pub const st_would_recurse = proto.st_would_recurse;

/// GFileCopyFlags the daemon understands (BACKUP excluded).
const known_flags: c_uint = 1 | 4 | 8 | 16 | 32 | 64;
const flag_backup: c_uint = 2;
const flag_no_fallback_for_move: c_uint = 16;

pub const connect_timeout_ms: u32 = 500;
pub const reply_timeout_ms: u64 = 1000;
pub const slice_ms: u64 = 50;
pub const cancel_wait_ms: u64 = 2000;
/// Longer than the daemon's own stall limit (30 s) plus its grace: the daemon answers
/// first; this only catches a daemon that stopped talking.
pub const stall_ms: u64 = 45_000;
/// Added to the op's timeout for the client-side deadline.
pub const grace_ms: u64 = 2000;
/// gungnird's default op deadline (timeout-ms 0).
pub const default_timeout_ms: u64 = 3_600_000;
/// Op threads alive at once; beyond, ops finish with G_IO_ERROR_BUSY.
pub const max_live_ops: u32 = 16;
/// Request seqs used on an op's own connection (clear of the handshake ping).
const start_seq: u64 = 1 << 40;

// ---- protocol (mirrors src/daemon-rust/src/ops.rs) ---------------------------------

/// `op u8 | flags u32 | timeout_ms u32 | src path16 | dest path16`. Null if too long.
pub fn encodeStart(buf: *[ipc.payload_max]u8, op: u8, flags: u32, timeout_ms: u32, src: []const u8, dest: []const u8) ?[]const u8 {
    const total = 1 + 4 + 4 + 2 + src.len + 2 + dest.len;
    if (total > buf.len or src.len > std.math.maxInt(u16) or dest.len > std.math.maxInt(u16)) return null;
    buf[0] = op;
    std.mem.writeInt(u32, buf[1..5], flags, .little);
    std.mem.writeInt(u32, buf[5..9], timeout_ms, .little);
    var i: usize = 9;
    for ([_][]const u8{ src, dest }) |p| {
        std.mem.writeInt(u16, buf[i..][0..2], @intCast(p.len), .little);
        i += 2;
        @memcpy(buf[i..][0..p.len], p);
        i += p.len;
    }
    return buf[0..i];
}

pub const Progress = struct { id: u64, done: u64, total: u64, files: u64 };

pub fn parseProgress(p: []const u8) ?Progress {
    if (p.len != 32) return null;
    return .{
        .id = std.mem.readInt(u64, p[0..8], .little),
        .done = std.mem.readInt(u64, p[8..16], .little),
        .total = std.mem.readInt(u64, p[16..24], .little),
        .files = std.mem.readInt(u64, p[24..32], .little),
    };
}

pub const Done = struct { id: u64, status: u32, errno: i32, bytes: u64, files: u64 };

pub fn parseDone(p: []const u8) ?Done {
    if (p.len != 32) return null;
    return .{
        .id = std.mem.readInt(u64, p[0..8], .little),
        .status = std.mem.readInt(u32, p[8..12], .little),
        .errno = std.mem.readInt(i32, p[12..16], .little),
        .bytes = std.mem.readInt(u64, p[16..24], .little),
        .files = std.mem.readInt(u64, p[24..32], .little),
    };
}

/// The GIOErrorEnum code for a daemon status (and errno), for `op` with `flags`.
pub fn ioErrorCode(status: u32, errno: i32, op: c_int, flags: c_uint) c_int {
    // g_file_move's own contract: NO_FALLBACK_FOR_MOVE across devices is NOT_SUPPORTED.
    if (status == st_os_error and op == op_move and errno == @backingInt(linux.E.XDEV) and flags & flag_no_fallback_for_move != 0)
        return c.G_IO_ERROR_NOT_SUPPORTED;
    return gioerr.ofStatus(status, errno);
}

fn statusError(d: Done, op: c_int, flags: c_uint) *c.GError {
    const code = ioErrorCode(d.status, d.errno, op, flags);
    return switch (d.status) {
        st_os_error => c.g_error_new(c.g_io_error_quark(), code, "gungnird: %s", c.g_strerror(d.errno)),
        st_cancelled => c.g_error_new_literal(c.g_io_error_quark(), code, "Operation was cancelled"),
        proto.st_timeout => c.g_error_new_literal(c.g_io_error_quark(), code, "gungnird: the operation timed out"),
        proto.st_suspect_mount => c.g_error_new_literal(c.g_io_error_quark(), code, "gungnird: the file's mount is hung or gone (mount health monitor)"),
        proto.st_busy => c.g_error_new_literal(c.g_io_error_quark(), code, "gungnird is busy"),
        st_would_recurse => c.g_error_new_literal(c.g_io_error_quark(), code, "Can't recursively copy directory"),
        proto.st_unsupported => c.g_error_new_literal(c.g_io_error_quark(), code, "this gungnird does not support file operations"),
        else => c.g_error_new(c.g_io_error_quark(), code, "gungnird: operation failed (status %u)", d.status),
    };
}

fn ioError(code: c_int, msg: [*:0]const u8) *c.GError {
    return c.g_error_new_literal(c.g_io_error_quark(), code, msg);
}

// ---- the GObject -------------------------------------------------------------------

const Priv = struct {
    operation: c_int = op_copy,
    source: ?[*:0]u8 = null,
    destination: ?[*:0]u8 = null,
    flags: c_uint = 0,
    timeout_ms: c_uint = 0,
    started: bool = false,
    ctx: ?*c.GMainContext = null,
    cancellable: ?*c.GCancellable = null,
    sock: ipc.SocketPath = .{},
    have_sock: bool = false,
    // Written by the op thread, read by the main-context callbacks.
    cur: u64 = 0,
    total: u64 = 0,
    progress_pending: u32 = 0,
    finished: u32 = 0,
    result: ?*c.GError = null,
    counted: bool = false,
};

const GungnirFileOp = extern struct {
    parent_instance: c.GObject,
    priv: ?*Priv,
};

const GungnirFileOpClass = extern struct {
    parent_class: c.GObjectClass,
    /// Class handler of the "start" action signal.
    start: ?*const fn (op: *GungnirFileOp, cancellable: ?*c.GCancellable) callconv(.c) c.gboolean,
};

var file_op_type: c.GType = 0;
var parent_class: ?*c.GObjectClass = null;
var sig_progress: c.guint = 0;
var sig_finished: c.guint = 0;
var live_ops: u32 = 0;
var pinned: u32 = 0;

const prop_operation: c.guint = 1;
const prop_source: c.guint = 2;
const prop_destination: c.guint = 3;
const prop_flags: c.guint = 4;
const prop_timeout: c.guint = 5;

fn privOf(obj: [*c]c.GObject) ?*Priv {
    // GObject passes every vfunc a GObject*; it is our instance.
    const self: *GungnirFileOp = @ptrCast(@alignCast(obj));
    return self.priv;
}

fn setProperty(obj: [*c]c.GObject, id: c.guint, value: [*c]const c.GValue, pspec: [*c]c.GParamSpec) callconv(.c) void {
    _ = pspec;
    const p = privOf(obj) orelse return;
    switch (id) {
        prop_operation => p.operation = c.g_value_get_int(value),
        prop_source => {
            c.g_free(p.source);
            p.source = @ptrCast(c.g_value_dup_string(value));
        },
        prop_destination => {
            c.g_free(p.destination);
            p.destination = @ptrCast(c.g_value_dup_string(value));
        },
        prop_flags => p.flags = c.g_value_get_uint(value),
        prop_timeout => p.timeout_ms = c.g_value_get_uint(value),
        else => {},
    }
}

fn getProperty(obj: [*c]c.GObject, id: c.guint, value: [*c]c.GValue, pspec: [*c]c.GParamSpec) callconv(.c) void {
    _ = pspec;
    const p = privOf(obj) orelse return;
    switch (id) {
        prop_operation => c.g_value_set_int(value, p.operation),
        prop_source => c.g_value_set_string(value, p.source),
        prop_destination => c.g_value_set_string(value, p.destination),
        prop_flags => c.g_value_set_uint(value, p.flags),
        prop_timeout => c.g_value_set_uint(value, p.timeout_ms),
        else => {},
    }
}

fn instanceInit(instance: [*c]c.GTypeInstance, g_class: c.gpointer) callconv(.c) void {
    _ = g_class;
    const self: *GungnirFileOp = @ptrCast(@alignCast(instance));
    const p = std.heap.c_allocator.create(Priv) catch {
        self.priv = null;
        return;
    };
    p.* = .{};
    self.priv = p;
}

fn finalize(obj: [*c]c.GObject) callconv(.c) void {
    const self: *GungnirFileOp = @ptrCast(@alignCast(obj));
    if (self.priv) |p| {
        c.g_free(p.source);
        c.g_free(p.destination);
        if (p.result) |e| c.g_error_free(e);
        if (p.cancellable) |cn| c.g_object_unref(cn);
        if (p.ctx) |ctx| c.g_main_context_unref(ctx);
        std.heap.c_allocator.destroy(p);
        self.priv = null;
    }
    if (parent_class) |pc| if (pc.finalize) |f| f(obj);
}

fn classInit(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = class_data;
    const klass: *GungnirFileOpClass = @ptrCast(@alignCast(g_class));
    parent_class = @ptrCast(@alignCast(c.g_type_class_peek_parent(g_class)));
    klass.start = &startImpl;
    const oc: *c.GObjectClass = &klass.parent_class;
    oc.set_property = &setProperty;
    oc.get_property = &getProperty;
    oc.finalize = &finalize;
    const rw_once = c.G_PARAM_READWRITE | c.G_PARAM_CONSTRUCT_ONLY | c.G_PARAM_STATIC_STRINGS;
    c.g_object_class_install_property(oc, prop_operation, c.g_param_spec_int("operation", "Operation", "1 copy, 2 move, 3 delete, 4 delete-tree, 5 fsync", op_copy, op_fsync, op_copy, rw_once));
    c.g_object_class_install_property(oc, prop_source, c.g_param_spec_string("source", "Source", "Absolute local path", null, rw_once));
    c.g_object_class_install_property(oc, prop_destination, c.g_param_spec_string("destination", "Destination", "Absolute local path (copy and move)", null, rw_once));
    c.g_object_class_install_property(oc, prop_flags, c.g_param_spec_uint("flags", "Flags", "GFileCopyFlags", 0, std.math.maxInt(c.guint), 0, rw_once));
    c.g_object_class_install_property(oc, prop_timeout, c.g_param_spec_uint("timeout-ms", "Timeout", "Deadline of the whole operation in ms (0: the daemon's default)", 0, std.math.maxInt(c.guint), 0, rw_once));
    const t = c.G_TYPE_FROM_CLASS(g_class);
    sig_progress = c.g_signal_new("progress", t, c.G_SIGNAL_RUN_LAST, 0, null, null, null, c.G_TYPE_NONE, 2, @as(c.GType, c.G_TYPE_INT64), @as(c.GType, c.G_TYPE_INT64));
    sig_finished = c.g_signal_new("finished", t, c.G_SIGNAL_RUN_LAST, 0, null, null, null, c.G_TYPE_NONE, 1, @as(c.GType, c.g_error_get_type()));
    _ = c.g_signal_new("start", t, c.G_SIGNAL_RUN_LAST | c.G_SIGNAL_ACTION, @offsetOf(GungnirFileOpClass, "start"), null, null, null, c.G_TYPE_BOOLEAN, 1, @as(c.GType, c.g_cancellable_get_type()));
}

fn classFinalize(g_class: c.gpointer, class_data: c.gpointer) callconv(.c) void {
    _ = g_class;
    _ = class_data;
}

const type_info = c.GTypeInfo{
    .class_size = @sizeOf(GungnirFileOpClass),
    .class_init = &classInit,
    .class_finalize = &classFinalize,
    .instance_size = @sizeOf(GungnirFileOp),
    .instance_init = &instanceInit,
};

comptime {
    std.debug.assert(@sizeOf(GungnirFileOpClass) <= std.math.maxInt(u16));
    std.debug.assert(@sizeOf(GungnirFileOp) <= std.math.maxInt(u16));
}

/// Called from g_io_module_load: a dynamic type, like GungnirVfs.
pub fn register(module: *c.GTypeModule) void {
    file_op_type = c.g_type_module_register_type(module, c.g_object_get_type(), type_name, &type_info, 0);
    if (file_op_type == 0) c.g_log(null, c.G_LOG_LEVEL_WARNING, "gungnir: failed to register %s", type_name.ptr);
}

// ---- main-context callbacks ----------------------------------------------------------

fn attachIdle(ctx: ?*c.GMainContext, func: c.GSourceFunc, data: c.gpointer) void {
    const src = c.g_idle_source_new();
    c.g_source_set_priority(src, c.G_PRIORITY_DEFAULT);
    c.g_source_set_callback(src, func, data, null);
    _ = c.g_source_attach(src, ctx);
    c.g_source_unref(src);
}

fn emitProgress(self: *GungnirFileOp, p: *Priv) void {
    const cur = @atomicLoad(u64, &p.cur, .acquire);
    const total = @atomicLoad(u64, &p.total, .acquire);
    c.g_signal_emit(self, sig_progress, 0, @as(i64, @intCast(@min(cur, std.math.maxInt(i64)))), @as(i64, @intCast(@min(total, std.math.maxInt(i64)))));
}

fn progressIdle(data: c.gpointer) callconv(.c) c.gboolean {
    const self: *GungnirFileOp = @ptrCast(@alignCast(data));
    defer c.g_object_unref(self);
    const p = self.priv orelse return c.G_SOURCE_REMOVE;
    // Cleared first: an update after this point schedules a new callback.
    if (@atomicRmw(u32, &p.progress_pending, .Xchg, 0, .acq_rel) == 0) return c.G_SOURCE_REMOVE;
    if (@atomicLoad(u32, &p.finished, .acquire) != 0) return c.G_SOURCE_REMOVE;
    emitProgress(self, p);
    return c.G_SOURCE_REMOVE;
}

fn finishIdle(data: c.gpointer) callconv(.c) c.gboolean {
    const self: *GungnirFileOp = @ptrCast(@alignCast(data));
    defer c.g_object_unref(self); // the reference the op held while running
    const p = self.priv orelse return c.G_SOURCE_REMOVE;
    if (@atomicRmw(u32, &p.progress_pending, .Xchg, 0, .acq_rel) != 0) emitProgress(self, p);
    @atomicStore(u32, &p.finished, 1, .release);
    if (p.counted) {
        _ = @atomicRmw(u32, &live_ops, .Sub, 1, .acq_rel);
        p.counted = false;
    }
    const err = p.result;
    p.result = null;
    c.g_signal_emit(self, sig_finished, 0, err);
    if (err) |e| c.g_error_free(e);
    if (p.cancellable) |cn| c.g_object_unref(cn);
    p.cancellable = null;
    return c.G_SOURCE_REMOVE;
}

/// Hand the result to the caller's context (takes over the op's reference).
fn complete(self: *GungnirFileOp, p: *Priv, err: ?*c.GError) void {
    p.result = err;
    attachIdle(p.ctx, &finishIdle, self);
}

fn noteProgress(self: *GungnirFileOp, p: *Priv, pr: Progress) void {
    @atomicStore(u64, &p.cur, pr.done, .release);
    @atomicStore(u64, &p.total, pr.total, .release);
    if (@atomicRmw(u32, &p.progress_pending, .Xchg, 1, .acq_rel) == 0) {
        _ = c.g_object_ref(self);
        attachIdle(p.ctx, &progressIdle, self);
    }
}

// ---- start -------------------------------------------------------------------------

fn envValue(name: [*:0]const u8) ?[]const u8 {
    const v = c.g_getenv(name);
    return if (v == null) null else std.mem.span(v);
}

fn validPath(p: ?[*:0]u8) ?[]const u8 {
    const s = std.mem.span(p orelse return null);
    if (s.len == 0 or s[0] != '/') return null;
    return s;
}

/// The "start" class handler, on the caller's thread: cheap checks only, then a thread.
fn startImpl(self: *GungnirFileOp, cancellable: ?*c.GCancellable) callconv(.c) c.gboolean {
    const p = self.priv orelse return 0;
    if (p.started) return 0;
    p.started = true;
    if (@atomicRmw(u32, &pinned, .Xchg, 1, .acq_rel) == 0) {
        // Never released: keeps this library loaded while op threads may still run.
        _ = c.g_type_class_ref(file_op_type);
    }
    p.ctx = c.g_main_context_ref_thread_default();
    if (cancellable) |cn| p.cancellable = @ptrCast(@alignCast(c.g_object_ref(cn)));
    _ = c.g_object_ref(self); // held by the op until "finished" is emitted

    const needs_dest = p.operation == op_copy or p.operation == op_move;
    if (validPath(p.source) == null or (needs_dest and validPath(p.destination) == null) or
        (!needs_dest and p.destination != null) or p.operation < op_copy or p.operation > op_fsync)
    {
        complete(self, p, ioError(c.G_IO_ERROR_INVALID_ARGUMENT, "GungnirFileOp: needs an operation and absolute paths (a destination only for copy and move)"));
        return 1;
    }
    if (p.flags & flag_backup != 0 or p.flags & ~(known_flags | flag_backup) != 0) {
        complete(self, p, ioError(c.G_IO_ERROR_NOT_SUPPORTED, "GungnirFileOp: unsupported GFileCopyFlags (BACKUP)"));
        return 1;
    }
    if (p.cancellable != null and c.g_cancellable_is_cancelled(p.cancellable) != 0) {
        complete(self, p, ioError(c.G_IO_ERROR_CANCELLED, "Operation was cancelled"));
        return 1;
    }
    // Lexical lookup in the health cache: never touches the path.
    if (health.blocks(validPath(p.source).?) or (needs_dest and health.blocks(validPath(p.destination).?))) {
        complete(self, p, ioError(c.G_IO_ERROR_TIMED_OUT, "the file's mount is hung or gone (reported by the gungnird mount health monitor)"));
        return 1;
    }
    if (ipc.resolveSocketPath(envValue("GUNGNIR_SOCKET"), envValue("XDG_RUNTIME_DIR"), envValue("HOME"))) |sp| {
        p.sock = sp;
        p.have_sock = true;
    } else |_| {}
    if (@atomicRmw(u32, &live_ops, .Add, 1, .acq_rel) >= max_live_ops) {
        _ = @atomicRmw(u32, &live_ops, .Sub, 1, .acq_rel);
        complete(self, p, ioError(c.G_IO_ERROR_BUSY, "too many gungnird file operations at once"));
        return 1;
    }
    p.counted = true;
    var err: [*c]c.GError = null;
    const th = c.g_thread_try_new("gungnir-op", &opMain, self, &err);
    if (th == null) {
        if (err != null) c.g_error_free(err);
        complete(self, p, ioError(c.G_IO_ERROR_FAILED, "cannot start a gungnir-op thread"));
        return 1;
    }
    c.g_thread_unref(th); // detached: it reports through the main context
    return 1;
}

// ---- the op thread -------------------------------------------------------------------

fn opMain(data: c.gpointer) callconv(.c) c.gpointer {
    const self: *GungnirFileOp = @ptrCast(@alignCast(data));
    const p = self.priv orelse return null;
    complete(self, p, run(self, p));
    return null;
}

fn cancelled(p: *Priv) bool {
    return p.cancellable != null and c.g_cancellable_is_cancelled(p.cancellable) != 0;
}

/// Talk to the daemon until the op is done. Every wait is bounded.
fn run(self: *GungnirFileOp, p: *Priv) ?*c.GError {
    if (!p.have_sock) return ioError(c.G_IO_ERROR_NOT_SUPPORTED, "gungnird is not available (no socket path)");
    var conn = ipc.connectAndPing(&p.sock, connect_timeout_ms) catch
        return ioError(c.G_IO_ERROR_NOT_SUPPORTED, "gungnird is not available");
    defer conn.close();
    var buf: [ipc.payload_max]u8 = undefined;
    const src = validPath(p.source) orelse return ioError(c.G_IO_ERROR_INVALID_ARGUMENT, "bad source");
    const dest: []const u8 = if (p.destination) |d| std.mem.span(d) else "";
    const payload = encodeStart(&buf, @intCast(p.operation), p.flags, p.timeout_ms, src, dest) orelse
        return ioError(c.G_IO_ERROR_FILENAME_TOO_LONG, "paths too long for one request");
    conn.shm.push(ipc.ring_c2d, msg_start, start_seq, payload) catch
        return ioError(c.G_IO_ERROR_BUSY, "gungnird is busy");

    const t0 = rpc.nowNs();
    const ms = std.time.ns_per_ms;
    const timeout: u64 = if (p.timeout_ms != 0) p.timeout_ms else default_timeout_ms;
    const overall = t0 + (timeout + grace_ms) * ms;
    var reply_deadline: u64 = t0 + reply_timeout_ms * ms;
    var last_event = t0;
    var op_id: ?u64 = null;
    var cancel_sent = false;
    var cancel_deadline: u64 = 0;
    var msg: ipc.Msg = undefined;
    while (true) {
        if (!cancel_sent and cancelled(p)) {
            cancel_sent = true;
            cancel_deadline = rpc.nowNs() + cancel_wait_ms * ms;
            if (op_id) |id| {
                var idb: [8]u8 = undefined;
                std.mem.writeInt(u64, &idb, id, .little);
                conn.shm.push(ipc.ring_c2d, msg_cancel, start_seq + 1, &idb) catch {};
            }
        }
        const now = rpc.nowNs();
        if (cancel_sent and now >= cancel_deadline) return ioError(c.G_IO_ERROR_CANCELLED, "Operation was cancelled");
        if (op_id == null and now >= reply_deadline) return ioError(c.G_IO_ERROR_TIMED_OUT, "gungnird did not accept the operation in time");
        if (now >= overall) return ioError(c.G_IO_ERROR_TIMED_OUT, "gungnird: the operation timed out");
        if (now - last_event >= stall_ms * ms) return ioError(c.G_IO_ERROR_TIMED_OUT, "gungnird stopped reporting progress");
        const slice_end = now + slice_ms * ms;
        conn.shm.waitReadable(ipc.ring_d2c, slice_end) catch |e| switch (e) {
            error.Timeout => {
                if (!conn.alive()) return ioError(c.G_IO_ERROR_FAILED, "gungnird went away during the operation");
                continue;
            },
            else => return ioError(c.G_IO_ERROR_FAILED, "corrupt reply ring from gungnird"),
        };
        while (true) {
            const got = conn.shm.pop(ipc.ring_d2c) catch return ioError(c.G_IO_ERROR_FAILED, "corrupt reply ring from gungnird");
            if (got == null) break;
            msg = got.?;
            last_event = rpc.nowNs();
            const body = msg.payload();
            if (msg.kind == proto.msg_reply and msg.seq == start_seq) {
                if (body.len < 4) return ioError(c.G_IO_ERROR_FAILED, "short reply from gungnird");
                const st = std.mem.readInt(u32, body[0..4], .little);
                if (st != proto.st_ok) return statusError(.{ .id = 0, .status = st, .errno = 0, .bytes = 0, .files = 0 }, p.operation, p.flags);
                if (body.len != 12) return ioError(c.G_IO_ERROR_FAILED, "bad reply from gungnird");
                const id = std.mem.readInt(u64, body[4..12], .little);
                op_id = id;
                reply_deadline = std.math.maxInt(u64);
                if (cancel_sent) {
                    var idb: [8]u8 = undefined;
                    std.mem.writeInt(u64, &idb, id, .little);
                    conn.shm.push(ipc.ring_c2d, msg_cancel, start_seq + 1, &idb) catch {};
                }
            } else if (msg.kind == msg_progress) {
                const pr = parseProgress(body) orelse continue;
                if (op_id == null or pr.id != op_id.?) continue;
                noteProgress(self, p, pr);
            } else if (msg.kind == msg_done and msg.seq == start_seq) {
                const d = parseDone(body) orelse return ioError(c.G_IO_ERROR_FAILED, "bad done event from gungnird");
                if (d.status == proto.st_ok) return null;
                return statusError(d, p.operation, p.flags);
            }
            // Anything else (the cancel's reply) is not ours to act on.
        }
    }
}

// ---- tests ---------------------------------------------------------------------------

const testing = std.testing;

test "start payload layout matches the daemon's" {
    var buf: [ipc.payload_max]u8 = undefined;
    const p = encodeStart(&buf, 1, 8, 1234, "/a", "/bc").?;
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 8, 0, 0, 0, 0xd2, 0x04, 0, 0, 2, 0, '/', 'a', 3, 0, '/', 'b', 'c' }, p);
    const huge: [4080]u8 = @splat('/');
    try testing.expect(encodeStart(&buf, 1, 0, 0, &huge, "/x") == null);
}

test "progress and done payloads parse, and only at their exact size" {
    var b: [32]u8 = undefined;
    for ([_]u64{ 7, 5, 9, 2 }, 0..) |v, i| std.mem.writeInt(u64, b[i * 8 ..][0..8], v, .little);
    const pr = parseProgress(&b).?;
    try testing.expectEqual(@as(u64, 7), pr.id);
    try testing.expectEqual(@as(u64, 9), pr.total);
    try testing.expect(parseProgress(b[0..31]) == null);
    std.mem.writeInt(u32, b[8..12], st_os_error, .little);
    std.mem.writeInt(i32, b[12..16], 17, .little);
    const d = parseDone(&b).?;
    try testing.expectEqual(st_os_error, d.status);
    try testing.expectEqual(@as(i32, 17), d.errno);
    try testing.expect(parseDone(b[0..30]) == null);
}

test "statuses map to GIO error codes" {
    const E = linux.E;
    try testing.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_FOUND), ioErrorCode(st_os_error, @backingInt(E.NOENT), op_copy, 0));
    try testing.expectEqual(@as(c_int, c.G_IO_ERROR_EXISTS), ioErrorCode(st_os_error, @backingInt(E.EXIST), op_copy, 0));
    try testing.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_SUPPORTED), ioErrorCode(st_os_error, @backingInt(E.XDEV), op_move, flag_no_fallback_for_move));
    try testing.expectEqual(@as(c_int, c.G_IO_ERROR_CANCELLED), ioErrorCode(st_cancelled, 0, op_copy, 0));
    try testing.expectEqual(@as(c_int, c.G_IO_ERROR_TIMED_OUT), ioErrorCode(proto.st_suspect_mount, 0, op_copy, 0));
    try testing.expectEqual(@as(c_int, c.G_IO_ERROR_WOULD_RECURSE), ioErrorCode(st_would_recurse, 0, op_copy, 0));
    try testing.expectEqual(@as(c_int, c.G_IO_ERROR_NOT_SUPPORTED), ioErrorCode(proto.st_unsupported, 0, op_copy, 0));
    try testing.expectEqual(@as(c_int, c.G_IO_ERROR_FAILED), ioErrorCode(99, 0, op_copy, 0));
}

test "random progress and done payloads never trip a safety check" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0303);
    const r = prng.random();
    var buf: [64]u8 = undefined;
    for (0..100_000) |_| {
        const n = r.uintLessThan(usize, buf.len);
        r.bytes(buf[0..n]);
        _ = parseProgress(buf[0..n]);
        _ = parseDone(buf[0..n]);
    }
}
