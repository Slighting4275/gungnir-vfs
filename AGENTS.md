# PROJECT ARCHITECTURE & IMPLEMENTATION INVARIANTS

Project: Gungnir (gungnir-vfs). Daemon: gungnird. GIO module: libgiogungnir.so. Design principle: like Odin's spear, the I/O pipeline never hesitates, never stops mid-flight, and never misses: no call may block on broken mounts or metadata locks.

## 1. MANDATORY SYSTEMS LANGUAGE SPLIT
Autonomous agents must strictly adhere to this two-language architecture:

### A. CLIENT INTERFACE / GIO SHIM (`src/client-zig`)
- **Language / Toolchain:** **Zig master (nightly)**, auto-updated every night. Target output is `libgiogungnir.so`.
  - Run `zig version` before writing any Zig code, and code against that installed std, not against memory of older Zig releases (0.15 and earlier APIs are frequently wrong here).
  - If a nightly update breaks the build, read the installed std source to fix it: `zig env` prints `.std_dir` (e.g. `grep -rn 'pub fn addTranslateC' "$(zig env | sed -n 's/.*\.std_dir = "\(.*\)",/\1/p')"`). Never guess API names.
  - `build.zig.zon` `minimum_zig_version` records the last nightly the project was verified on; bump it after fixing a nightly break.
- **Required Module Entry Points:**
  Must export standard GIO extension module symbols:
  - `pub export fn g_io_module_load(module: *c.GIOModule) void`
  - `pub export fn g_io_module_unload(module: *c.GIOModule) void`
  - `pub export fn g_io_module_query() [*c][*c]u8` (returns a `g_strdupv` copy of a NULL-terminated array; GIO frees it with `g_strfreev`, so never return static memory)
  - Must register the extension under `G_VFS_EXTENSION_POINT_NAME` (`"gio-vfs"`).
- **C Linkage & VTable Definitions:**
  - Link `libc` and `libgio-2.0` (mandatory; host GTK processes already link glibc).
  - Consume GLib/GIO headers exclusively through the build graph: `b.addTranslateC` on a header generated in `build.zig` (`#include <gio/gio.h>`), imported as module `c` (`const c = @import("c");`). `@cImport` no longer exists on Zig master.
  - Variadic C macros (e.g. `g_critical`, `g_warning`) cannot be translated; call the underlying function (`c.g_log`) directly.
  - Implement GObject virtual tables (`GVfsClass`, `GFileIface`) as Zig `extern struct` types containing typed function pointers matching C ABI prototypes. Untyped `*anyopaque` or `void*` casts for vtables are forbidden.
- **Panic Prevention & C-ABI Safety:**
  - Zig's root panic handler (`pub const panic = std.debug.FullPanic(fn)` on the current master; re-check in the installed std after updates) is `noreturn` and cannot resume execution. Code paths handling external input must NEVER trigger panics.
  - Ban `@panic`, `unreachable`, and implicit slicing/arithmetic assertions on untrusted paths. Use explicit error-returning forms (`std.math.add`, bounds-checked slicing with error returns).
  - Root panic handler must safely format Zig's string slice using a precision specifier, call GLib logging, and terminate via `exit_group`. Clamp the length with `@min` BEFORE narrowing: a bare `@intCast(msg.len)` re-enters the panic handler in safe builds (losing the original message) and is UB in `ReleaseFast`/`ReleaseSmall`, where a negative `%.*s` precision makes `g_log` read past the slice:
    ```zig
    const max_panic_msg_len = 4096;
    c.g_log(null, c.G_LOG_LEVEL_CRITICAL, "gungnir panic: %.*s", @as(c_int, @intCast(@min(msg.len, max_panic_msg_len))), msg.ptr);
    std.os.linux.exit_group(1);
    ```
  - Every exported C boundary must wrap internal Zig logic in `catch` blocks and populate `GError**` using `c.g_set_error()`.
- **Memory & Allocation Scope:**
  - Pure Zig structures must explicitly take an allocator (`std.mem.Allocator`). No hidden heap allocations inside Zig code.
  - GLib internal allocations (such as `g_object_new`, `g_set_error`, or `g_strdupv`) are exempt from the Zig allocator requirement.
- **Kernel Syscalls & Non-Blocking Worker Fallback:**
  - Primary path: Direct asynchronous kernel `io_uring` queues where supported.
  - Mandatory fallback: If `io_uring_setup` fails (`EPERM`, `EACCES`, `ENOSYS`), fall back to POSIX `getdents64` and `statx(2)`.
  - Concurrency invariant: Synchronous POSIX fallback operations (`statx`, `getdents64`) block the calling thread. They MUST NEVER execute on the GTK main thread. Schedule them onto GLib worker threads via `GTask` (`g_task_run_in_thread`) so the host UI loop never stalls.

### B. BACKGROUND DAEMON & STORAGE WORKERS (`src/daemon-rust`)
- **Language:** Strictly **Rust** stable (binary `gungnird`, edition 2024).
- **Async Reactor:** Use raw `io-uring` or `monoio` (thread-per-core io_uring). Banned: `tokio-uring`.
- **IPC & Shared Memory:**
  - Low-latency data transfers must use shared-memory ring buffers (`memfd_create` + futexes) managed via `AF_UNIX` control sockets.
  - Futex operations MUST be process-shared (`FUTEX_WAIT` and `FUTEX_WAKE` without `FUTEX_PRIVATE_FLAG`).
- **Metadata Storage (SQLite in WAL Mode):**
  - Default database path: `$HOME/.cache/gungnir/metadata.db` (overridable by the first CLI argument).
  - Required PRAGMAs:
    `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;`
  - Table schema:
    ```sql
    CREATE TABLE metadata (
      fs_uuid    TEXT    NOT NULL,
      subvol_id  INTEGER NOT NULL,
      inode_num  INTEGER NOT NULL,
      generation INTEGER NOT NULL,
      key        TEXT    NOT NULL,
      btime_sec  INTEGER NOT NULL DEFAULT 0,
      btime_nsec INTEGER NOT NULL DEFAULT 0,
      value      BLOB,
      PRIMARY KEY (fs_uuid, subvol_id, inode_num, generation, key)
    ) WITHOUT ROWID;
    ```
  - Unlink/delete path:
    - Deleted files are removed with `DELETE FROM metadata WHERE fs_uuid = ? AND subvol_id = ? AND inode_num = ?`, batched in a single transaction per event burst.
    - Do NOT add a separate index on `(fs_uuid, subvol_id, inode_num)`: the PRIMARY KEY prefix already serves deletes, and an extra index adds a write to every insert.
  - Inode Tracking & Collision Defense:
    - `generation`: Query via `ioctl(fd, FS_IOC_GETVERSION, &generation)`. If unsupported by the filesystem, set `generation = 0`. NEVER use `stx_ctime` as a key or fallback; `ctime` changes on chmod, rename, hard link, and xattr writes, causing key churn and metadata loss.
    - `btime` (staleness check, not part of the key): Record `stx_btime` when `stx_mask & STATX_BTIME` is set; otherwise store `0`. On lookup, if both the stored and current `btime` are non-zero and differ, treat the row as stale (recycled inode) and delete it.
    - `subvol_id`: Query via `statx` (`STATX_SUBVOL`, Linux 6.10+) or `BTRFS_IOC_INO_LOOKUP`; default to `0` on filesystems without subvolumes.
    - `fs_uuid` retrieval, in order:
      1. `ioctl(fd, FS_IOC_GETFSUUID, &fsuuid)` (Linux 6.8+).
      2. Parse `/proc/self/mountinfo` for the mount's `major:minor` and source device, then resolve the UUID via the matching symlink in `/dev/disk/by-uuid/`.
      3. Synthetic ID for UUID-less filesystems, formatted `synth-<first 32 hex chars of BLAKE3>` (each input length-prefixed, see `synth_fs_id`). Read `f_type` via `statfs(2)` (`statvfs` has no `f_type`). Hash inputs by filesystem class:
         - Volatile (`tmpfs`, `ramfs`): `f_type || mount_point || boot_id`, where `boot_id` is read from `/proc/sys/kernel/random/boot_id`. Contents are wiped each boot, so IDs must not survive a reboot.
         - Network (`nfs`, `nfs4`, `cifs`, `smb3`): `f_type || mount_source` (e.g. `server:/export`), so an export keeps its ID regardless of mount point.
         - Everything else (FUSE and others): `f_type || mount_source || mount_point`.
      - Hash with the `blake3` crate ONLY. Never use Rust's `DefaultHasher`/SipHash: its output is not guaranteed stable across Rust versions and would silently orphan every synthetic ID after a toolchain upgrade.
- **Error Propagation:**
  - Set `panic = "abort"` in release profiles.
  - All disk, network, and IPC boundaries must return typed `Result<T, E>`. No `unwrap`/`expect` outside tests.

## 2. STRICTLY PROHIBITED IMPLEMENTATIONS
- BANNED: C++ (any standard; never link `libstdc++`).
- BANNED: Hand-written `.c` or `.h` implementation files (headers generated inside `build.zig` for translate-c are allowed).
- BANNED: Go (runtime GC and green-thread scheduler violate GIO shared-library constraints).
- BANNED: D-Bus as a bulk data transfer plane. D-Bus is permitted only for initial activation.
- BANNED: `tokio-uring`.
- BANNED: `DefaultHasher` / SipHash for any persisted identifier.
- BANNED: `@cImport` (removed on Zig master; use `b.addTranslateC`).

## 3. HOST ENVIRONMENT CONSTRAINTS (Arch Linux host)
- Hardened mount rule: `/tmp` is mounted `noexec`. Never build, link, or execute binaries from `/tmp`.
- All temporary sockets, test roots, and build artifacts MUST reside in `./.build/` or `$HOME/.cache/gungnir/`.
- Safe command execution: Never emit destructive commands (`git reset --hard`, `git clean -fdx`, or commands closing active terminal sessions).
- Compilation failure circuit breaker: If an analyzer or compiler fails twice with the same diagnostic, stop and output the exact error trace.
- No personal names, emails, or other personal details in code, metadata (`authors` fields), or commits.

## 4. CONCRETE VERIFICATION TARGETS & SLOs
Before declaring any task complete, agents must verify the following:

1. **Zig Test Suite** (from `src/client-zig`):
   - `zig build` and `zig build test --summary all` must pass on the installed nightly, with zero memory leaks under `std.testing.allocator`.
2. **Rust Test Suite** (from the repo root):
   - `cargo test --release` must exit code 0.
   - `RUSTFLAGS="-D warnings" cargo check --release` and `cargo clippy --release -- -D warnings` must exit code 0.
3. **Batch Removal & Event Throughput Benchmark:**
   - An automated test burst of **50,000 file deletion/update events** must satisfy:
     - Total burst completion time: **< 1.5 seconds** wall-clock time.
     - Per-operation p99 latency: **< 1.0 millisecond**.
     - Maximum client-thread blocking pause: **< 5.0 milliseconds** on any single GIO slice.
     - Peak resident set size (RSS): **< 40 MiB**.
