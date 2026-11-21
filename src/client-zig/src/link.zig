//! The process's one daemon connection (milestones 3 and 6).
//!
//! The first GungnirVfs instance starts one "gungnir-connect" GThread that connects to
//! gungnird, exchanges hellos, maps the ring pair and round-trips a ping, all bounded by
//! connect_timeout_ms. The GIO calling thread never touches the socket during that.
//!
//! GIO calls from any thread then share the connection through `acquire`/`release`: one
//! request at a time (the ring pair is one SPSC queue per direction), with a lock that is
//! only ever waited for up to the caller's deadline. A caller that finds the daemon still
//! connecting waits for it at most until its deadline too. A connection that turns out
//! dead (daemon stopped, corrupt ring) is closed and the state goes back to unavailable;
//! the next metadata call at least `reconnect_interval_ms` later starts a fresh connector
//! thread, so a restarted daemon is picked up again without blocking anyone.
//!
//! The UI thread (the one dispatching the default main context: GTK signal handlers,
//! idles, and the synchronous GIO calls made from them) gets ui_budget_ms per hook, not
//! the hook's own budget (AGENTS.md: < 5 ms client-thread blocking). After a request
//! timed out it skips the daemon entirely for ui_quiet_ms, and it never queues behind a
//! worker thread that has held the connection longer than a UI call ever could: a stuck
//! daemon (SIGSTOP, ring thread waiting out a hung mount) costs one bounded probe per
//! ui_quiet_ms instead of a full budget per file. Worker threads keep their full budget;
//! any answered request ends the quiet period at once.
//!
//! Mount health (milestone 7): after the ping the connector subscribes to health events
//! (within subscribe_timeout_ms; an M6 daemon answers "unsupported" and the link works
//! as before). Events ride the reply ring. A request meets them while it waits for its
//! reply (rpc.Client.on_event) and `release` drains what is left; while the link is idle
//! one "gungnir-health" GThread waits on the ring's head futex (bounded) and drains them
//! under the lock. It only reads shared memory: it never touches a file path.
const std = @import("std");
const c = @import("c");
const ipc = @import("ipc.zig");
const rpc = @import("rpc.zig");
const proto = @import("proto.zig");
const health = @import("health.zig");
const linux = std.os.linux;

/// Budget for connect + hello + ring setup + first ping, on the connector thread.
pub const connect_timeout_ms: u32 = 500;
/// Least time between two connection attempts after the daemon was found unavailable.
pub const reconnect_interval_ms: u64 = 2000;
/// Whole budget of a hook on the UI thread, lock and connection waits included.
pub const ui_budget_ms: u64 = 3;
/// After a timed-out request, UI-thread hooks do not wait for the daemon for this long.
pub const ui_quiet_ms: u64 = 1000;

/// When a hook must be done (absolute CLOCK_MONOTONIC ns), and whether it runs on the
/// UI thread. Made by `budget`.
pub const Budget = struct { deadline: u64, ui: bool };
/// Budget of the health subscription, after the handshake, on the connector thread.
pub const subscribe_timeout_ms: u32 = 200;
/// Longest wait of the event thread before it re-checks for shutdown and liveness.
pub const event_wait_ms: u64 = 2000;
/// Request seqs of the connector's subscription (clear of the requests' 1 << 32 range).
const subscribe_seq: u64 = 1 << 31;

/// Values of the read-only GungnirVfs:daemon-state property. Plain integers, not an
/// enum: the enum<->int builtins are being renamed on Zig master.
pub const state_connecting: c_int = 0;
pub const state_connected: c_int = 1;
pub const state_unavailable: c_int = 2;

pub const AcquireError = error{
    /// No daemon (none listening, refused, died): metadata is not available.
    Unavailable,
    /// Another thread holds the connection past our deadline.
    Busy,
    /// Still connecting at our deadline.
    Timeout,
};

/// Also the futex word callers wait on while the state is "connecting".
var daemon_state: c_int = state_connecting;
var connector_started: u32 = 0;
var connector_thread: ?*c.GThread = null;
var socket_path: ipc.SocketPath = .{};
var have_path = false;
/// Written by the connector thread only while the state is "connecting", published by
/// the release store of "connected"; adopted by `acquire` under `lock`.
var pending_conn: ?ipc.Conn = null;

// Guarded by `lock` (a zero-initialised static GMutex needs no g_mutex_init).
var lock: c.GMutex = std.mem.zeroes(c.GMutex);
var conn: ipc.Conn = undefined;
var have_conn = false;
var next_seq: u64 = 1 << 32;
var last_attempt_ns: u64 = 0;
var client: rpc.Client = undefined;
// Atomics, not under `lock`: read by UI-thread callers before (or instead of) locking.
/// UI-thread hooks fail at once (error.Busy) before this time.
var quiet_until_ns: u64 = 0;
/// When the current holder took `lock`; 0 while it is free.
var held_since_ns: u64 = 0;

/// True on the thread that currently dispatches the default main context, where a GTK
/// application runs its UI. (A plain thread that never runs a main loop is not one.)
pub fn onUiThread() bool {
    return c.g_main_context_is_owner(c.g_main_context_default()) != 0;
}

/// The budget of a hook whose own budget is `ms`, cut to ui_budget_ms on the UI thread.
pub fn budget(ms: u64) Budget {
    const ui = onUiThread();
    const use = if (ui) @min(ms, ui_budget_ms) else ms;
    return .{ .deadline = rpc.nowNs() + use * std.time.ns_per_ms, .ui = ui };
}

/// 1 while the current connection is subscribed to health events (set by the connector
/// before it publishes "connected", cleared under `lock` when the connection closes).
var health_subscribed: u32 = 0;
var events_thread: ?*c.GThread = null;
var events_stop: u32 = 0;
/// Address of the head word the event thread waits on (0: none), for wake-ups.
var events_head: usize = 0;

pub fn state() c_int {
    return @atomicLoad(c_int, &daemon_state, .acquire);
}

fn setState(s: c_int) void {
    @atomicStore(c_int, &daemon_state, s, .release);
    _ = linux.futex_3arg(@ptrCast(&daemon_state), .{ .cmd = .WAKE, .private = true }, std.math.maxInt(i32));
}

fn envValue(name: [*:0]const u8) ?[]const u8 {
    const v = c.g_getenv(name);
    return if (v == null) null else std.mem.span(v);
}

fn connectorMain(data: c.gpointer) callconv(.c) c.gpointer {
    _ = data;
    if (ipc.connectAndPing(&socket_path, connect_timeout_ms)) |connected| {
        var cn = connected;
        // Still exclusively ours: subscribe before anyone else can use the rings.
        var sub: rpc.Client = .{ .conn = &cn, .seq = subscribe_seq, .timeout_ms = subscribe_timeout_ms };
        const subscribed = if (health.subscribe(&sub)) |_| true else |err| blk: {
            if (isFatal(err)) {
                cn.close();
                setState(state_unavailable);
                c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: daemon lost during the health subscription (%s)", @errorName(err).ptr);
                return null;
            }
            c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: no mount health events (%s)", @errorName(err).ptr);
            break :blk false;
        };
        @atomicStore(u32, &health_subscribed, @intFromBool(subscribed), .release);
        pending_conn = cn; // published by the release store in setState
        setState(state_connected);
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: daemon handshake ok on %s", &socket_path.buf);
    } else |err| {
        setState(state_unavailable);
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: daemon unavailable (%s), using the local VFS", @errorName(err).ptr);
    }
    return null;
}

/// Start a connector thread; the state must already be "connecting".
fn spawnConnector() void {
    last_attempt_ns = rpc.nowNs();
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

/// Called from instance_init on the GIO calling thread: reads the environment (cheap,
/// never blocks), then hands everything else to the connector thread. Starts at most once.
pub fn start() void {
    if (@cmpxchgStrong(u32, &connector_started, 0, 1, .acq_rel, .monotonic) != null) return;
    socket_path = ipc.resolveSocketPath(envValue("GUNGNIR_SOCKET"), envValue("XDG_RUNTIME_DIR"), envValue("HOME")) catch |err| {
        setState(state_unavailable);
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: no daemon socket path (%s)", @errorName(err).ptr);
        return;
    };
    have_path = true;
    c.g_mutex_lock(&lock);
    defer c.g_mutex_unlock(&lock);
    spawnConnector();
    @atomicStore(u32, &events_stop, 0, .release);
    var err: [*c]c.GError = null;
    events_thread = c.g_thread_try_new("gungnir-health", &eventsMain, null, &err);
    if (events_thread == null and err != null) {
        // Not fatal: events are still read by every request.
        c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: cannot start the health event thread: %s", err.*.message);
        c.g_error_free(err);
    }
}

/// Wait (futex, bounded by `deadline`) while the connector is still working.
fn waitSettled(deadline: u64) AcquireError!void {
    while (true) {
        if (state() != state_connecting) return;
        const now = rpc.nowNs();
        if (now >= deadline) return error.Timeout;
        const left = deadline - now;
        const ts: linux.timespec = .{ .sec = @intCast(left / std.time.ns_per_s), .nsec = @intCast(left % std.time.ns_per_s) };
        // SUCCESS, AGAIN (state changed), INTR and TIMEDOUT all lead to the re-check above.
        _ = linux.futex_4arg(@ptrCast(&daemon_state), .{ .cmd = .WAIT, .private = true }, @bitCast(state_connecting), &ts);
    }
}

/// Take the lock, giving up at the deadline. GMutex has no timed lock: try, then nap.
/// The UI thread gives up at once on a holder that has had it for over ui_budget_ms (a
/// worker waiting for a slow daemon: its request cannot end within our budget anyway).
fn lockUntil(b: Budget) AcquireError!void {
    while (c.g_mutex_trylock(&lock) == 0) {
        const now = rpc.nowNs();
        if (now >= b.deadline) return error.Busy;
        if (b.ui) {
            const since = @atomicLoad(u64, &held_since_ns, .monotonic);
            if (since != 0 and now -% since > ui_budget_ms * std.time.ns_per_ms) return error.Busy;
        }
        c.g_usleep(100);
    }
    @atomicStore(u64, &held_since_ns, @max(rpc.nowNs(), 1), .monotonic);
}

fn unlock() void {
    @atomicStore(u64, &held_since_ns, 0, .monotonic);
    c.g_mutex_unlock(&lock);
}

/// Under `lock`, state "unavailable": start a new attempt if the last one is old enough.
/// Joining the previous connector thread does not wait: it has set its final state.
fn maybeReconnect() void {
    if (!have_path or state() != state_unavailable) return;
    if (rpc.nowNs() -% last_attempt_ns < reconnect_interval_ms * std.time.ns_per_ms) return;
    if (connector_thread) |t| _ = c.g_thread_join(t);
    connector_thread = null;
    setState(state_connecting);
    spawnConnector();
}

/// The shared metadata client, exclusively ours until `release`. Every request through it
/// ends by `b.deadline`, including the waits in here.
pub fn acquire(b: Budget) AcquireError!*rpc.Client {
    if (b.ui and rpc.nowNs() < @atomicLoad(u64, &quiet_until_ns, .monotonic)) return error.Busy;
    try waitSettled(b.deadline);
    try lockUntil(b);
    if (state() != state_connected) {
        maybeReconnect();
        unlock();
        return error.Unavailable;
    }
    if (!adoptLocked()) {
        unlock();
        return error.Unavailable;
    }
    client = .{ .conn = &conn, .seq = next_seq, .timeout_ms = std.math.maxInt(u32), .deadline_ns = b.deadline, .on_event = &health.onEvent };
    return &client;
}

/// Under `lock`: take over the connector's connection if it has published one.
fn adoptLocked() bool {
    if (have_conn) return true;
    if (state() != state_connected) return false;
    conn = pending_conn orelse return false;
    pending_conn = null;
    have_conn = true;
    return true;
}

/// Under `lock`: apply the health events waiting on the reply ring; anything else there
/// is a late reply to a timed-out request and is dropped, as rpc.Client does.
fn drainLocked() void {
    var n: u32 = 0;
    while (n < ipc.slot_count) : (n += 1) {
        const m = (conn.shm.pop(ipc.ring_d2c) catch return) orelse return;
        if (m.kind == proto.msg_health_event) health.onEvent(m.payload());
    }
}

fn wakeShared(addr: usize) void {
    if (addr == 0) return;
    _ = linux.futex_3arg(@ptrFromInt(addr), .{ .cmd = .WAKE, .private = false }, std.math.maxInt(i32));
}

/// Under `lock`: close the connection (the daemon is gone or the rings are out of step).
fn closeLocked() void {
    // Wake the event thread off this ring before it is unmapped.
    wakeShared(@atomicLoad(usize, &events_head, .acquire));
    conn.close();
    have_conn = false;
    @atomicStore(u32, &health_subscribed, 0, .release);
    health.reset(); // nothing is known to be hung any more
    last_attempt_ns = rpc.nowNs();
    setState(state_unavailable);
    c.g_log(null, c.G_LOG_LEVEL_DEBUG, "gungnir: daemon connection lost");
}

/// Wait (futex) while daemon_state is still `seen`, at most `ms`.
fn waitStateChange(seen: c_int, ms: u64) void {
    const ts: linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = linux.futex_4arg(@ptrCast(&daemon_state), .{ .cmd = .WAIT, .private = true }, @bitCast(seen), &ts);
}

/// The "gungnir-health" thread: keeps the health table current while no request is
/// reading the ring. Every wait is bounded (event_wait_ms); it holds `lock` only to
/// drain the ring (memory copies, no syscall on any path).
fn eventsMain(data: c.gpointer) callconv(.c) c.gpointer {
    _ = data;
    while (@atomicLoad(u32, &events_stop, .acquire) == 0) {
        const st = state();
        if (st != state_connected or @atomicLoad(u32, &health_subscribed, .acquire) == 0) {
            waitStateChange(st, event_wait_ms);
            continue;
        }
        // A request holds the link: it reads the events itself (and release drains).
        if (c.g_mutex_trylock(&lock) == 0) {
            c.g_usleep(5 * 1000);
            continue;
        }
        // Held like any caller's (see lockUntil), so a UI-thread caller can tell it is short.
        @atomicStore(u64, &held_since_ns, @max(rpc.nowNs(), 1), .monotonic);
        if (!adoptLocked()) {
            unlock();
            waitStateChange(st, 10);
            continue;
        }
        if (!conn.alive()) {
            closeLocked();
            unlock();
            continue;
        }
        drainLocked();
        const head_p = conn.shm.headWord(ipc.ring_d2c);
        const head = @atomicLoad(u32, head_p, .acquire);
        @atomicStore(usize, &events_head, @intFromPtr(head_p), .release);
        unlock();
        // Until the daemon pushes (it wakes every waiter), shutdown, or a close (both wake
        // it too). The mapping may go away meanwhile: then the kernel just returns.
        const ts: linux.timespec = .{ .sec = @intCast(event_wait_ms / 1000), .nsec = @intCast((event_wait_ms % 1000) * std.time.ns_per_ms) };
        _ = linux.futex_4arg(head_p, .{ .cmd = .WAIT, .private = false }, head, &ts);
    }
    return null;
}

/// Errors after which the connection cannot be trusted any more (the daemon is gone or
/// the rings are out of step); a timeout or busy answer is not one of them.
pub fn isFatal(err: anyerror) bool {
    return switch (err) {
        error.DaemonAbsent, error.Protocol, error.RingCorrupt, error.Io, error.BadShm => true,
        else => false,
    };
}

/// Give the client back with the error its last request ended in, if any: a fatal one
/// (see isFatal) closes the connection, a timeout starts the UI quiet period, success
/// ends it.
pub fn release(cl: *rpc.Client, err: ?anyerror) void {
    next_seq = cl.seq;
    if (err) |e| {
        if (e == error.Timeout) @atomicStore(u64, &quiet_until_ns, rpc.nowNs() + ui_quiet_ms * std.time.ns_per_ms, .monotonic);
    } else @atomicStore(u64, &quiet_until_ns, 0, .monotonic);
    const fatal = if (err) |e| isFatal(e) else false;
    if (fatal and have_conn) {
        closeLocked();
    } else if (have_conn) {
        drainLocked(); // events that came in behind our reply
    }
    unlock();
}

/// Module unload: only reached once no GungnirVfs instance is alive. The join is bounded
/// by connect_timeout_ms, and the thread must not outlive the module's code.
pub fn shutdown() void {
    if (events_thread) |t| {
        @atomicStore(u32, &events_stop, 1, .release);
        _ = linux.futex_3arg(@ptrCast(&daemon_state), .{ .cmd = .WAKE, .private = true }, std.math.maxInt(i32));
        wakeShared(@atomicLoad(usize, &events_head, .acquire));
        _ = c.g_thread_join(t); // bounded by event_wait_ms
    }
    events_thread = null;
    @atomicStore(usize, &events_head, 0, .release);
    @atomicStore(u32, &health_subscribed, 0, .release);
    health.reset();
    if (connector_thread) |t| _ = c.g_thread_join(t);
    connector_thread = null;
    if (pending_conn) |*p| p.close();
    pending_conn = null;
    if (have_conn) conn.close();
    have_conn = false;
    have_path = false;
    next_seq = 1 << 32;
    @atomicStore(u64, &quiet_until_ns, 0, .monotonic);
    @atomicStore(c_int, &daemon_state, state_connecting, .release);
    @atomicStore(u32, &connector_started, 0, .release);
}

test "state starts as connecting and an unsettled wait is bounded" {
    try std.testing.expectEqual(state_connecting, state());
    const t0 = rpc.nowNs();
    try std.testing.expectError(error.Timeout, acquire(.{ .deadline = t0 + 20 * std.time.ns_per_ms, .ui = false }));
    try std.testing.expect(rpc.nowNs() - t0 < 500 * std.time.ns_per_ms);
}

test "fatal errors are the transport ones" {
    try std.testing.expect(isFatal(error.DaemonAbsent));
    try std.testing.expect(isFatal(error.RingCorrupt));
    try std.testing.expect(!isFatal(error.Timeout));
    try std.testing.expect(!isFatal(error.Busy));
    try std.testing.expect(!isFatal(error.NotFound));
}

test "the UI thread gets the short budget, other threads their own" {
    try std.testing.expect(!onUiThread());
    const t0 = rpc.nowNs();
    const w = budget(200);
    try std.testing.expect(!w.ui and w.deadline >= t0 + 200 * std.time.ns_per_ms);
    const ctx = c.g_main_context_default();
    try std.testing.expect(c.g_main_context_acquire(ctx) != 0);
    defer c.g_main_context_release(ctx);
    try std.testing.expect(onUiThread());
    const u = budget(200);
    try std.testing.expect(u.ui and u.deadline <= rpc.nowNs() + ui_budget_ms * std.time.ns_per_ms);
}

test "a UI-thread caller never waits during the quiet period or behind a long holder" {
    // Quiet period: refused before any wait (even while still connecting).
    @atomicStore(u64, &quiet_until_ns, rpc.nowNs() + std.time.ns_per_s, .monotonic);
    defer @atomicStore(u64, &quiet_until_ns, 0, .monotonic);
    var t0 = rpc.nowNs();
    try std.testing.expectError(error.Busy, acquire(.{ .deadline = t0 + std.time.ns_per_s, .ui = true }));
    try std.testing.expect(rpc.nowNs() - t0 < std.time.ns_per_ms);
    // A worker has held the lock for longer than a UI call may take.
    c.g_mutex_lock(&lock);
    @atomicStore(u64, &held_since_ns, rpc.nowNs() - 10 * std.time.ns_per_ms, .monotonic);
    defer unlock();
    t0 = rpc.nowNs();
    try std.testing.expectError(error.Busy, lockUntil(.{ .deadline = t0 + std.time.ns_per_s, .ui = true }));
    try std.testing.expect(rpc.nowNs() - t0 < std.time.ns_per_ms);
    // A worker caller still waits for its own deadline.
    t0 = rpc.nowNs();
    try std.testing.expectError(error.Busy, lockUntil(.{ .deadline = t0 + 20 * std.time.ns_per_ms, .ui = false }));
    try std.testing.expect(rpc.nowNs() - t0 >= 20 * std.time.ns_per_ms);
}
