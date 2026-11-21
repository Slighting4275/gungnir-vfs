# PROJECT ARCHITECTURE & IMPLEMENTATION INVARIANTS

Project: Gungnir (gungnir-vfs). Daemon: gungnird. GIO module: libgiogungnir.so. Design principle: like Odin's spear, the I/O pipeline never hesitates, never stops mid-flight, and never misses: no call may block on broken mounts or metadata locks.

## 1. MANDATORY SYSTEMS LANGUAGE SPLIT
Autonomous agents must strictly adhere to this two-language architecture:

### A. CLIENT INTERFACE / GIO SHIM (`src/client-zig`)
- **Language / Toolchain:** **Zig master (nightly)**, auto-updated every night. Target output is `libgiogungnir.so`.
  - Run `zig version` before writing any Zig code, and code against that installed std, not against memory of older Zig releases (0.15 and earlier APIs are frequently wrong here).
  - Whether this morning's nightly still builds the module: `~/.cache/gungnir/zig-nightly.log` (written at 06:00 by the user timer `gungnir-zig-nightly`, `tools/zig-nightly-check`); read it first when a Zig build fails before you changed anything.
  - If a nightly update breaks the build, read the installed std source to fix it: `zig env` prints `.std_dir` (e.g. `grep -rn 'pub fn addTranslateC' "$(zig env | sed -n 's/.*\.std_dir = "\(.*\)",/\1/p')"`). Never guess API names.
  - `build.zig.zon` `minimum_zig_version` records the OLDEST nightly the project is verified on: the ziglang.org master that CI downloads (it can lag the newest nightly by weeks). Zig does not enforce the field, so CI compares `zig version` against it. Raise it only when the code starts to need a newer std API, never just because a newer nightly also works.
- **Required Module Entry Points:**
  Must export standard GIO extension module symbols:
  - `pub export fn g_io_module_load(module: *c.GIOModule) void`
  - `pub export fn g_io_module_unload(module: *c.GIOModule) void`
  - `pub export fn g_io_module_query() [*c][*c]u8` (returns a `g_strdupv` copy of a NULL-terminated array; GIO frees it with `g_strfreev`, so never return static memory)
  - Must register the extension under `G_VFS_EXTENSION_POINT_NAME` (`"gio-vfs"`).
  - Export ONLY these three symbols. Check with `nm -D --defined-only .build/zig-out/lib/libgiogungnir.so`; keep `bundle_ubsan_rt = false` on every artifact.
- **GungnirVfs Type & VFS Selection (opt-in only):**
  - `g_io_module_load` registers `GungnirVfs` (subclass of `GVfs`) with `g_type_module_register_type`, passing the `GIOModule` as the `GTypeModule`, so it is a dynamic type that survives module unload/reload. Never use `g_type_register_static` in the module.
  - It then calls `g_io_extension_point_implement(G_VFS_EXTENSION_POINT_NAME, type, "gungnir", -100)`.
  - Priority MUST stay below GLib's `local` (0) and gvfs's `gvfs` (10) (verified in GLib 2.84.4 and 2.90.1). GIO picks the highest-priority active VFS, so a priority >= 0 would silently make GungnirVfs the default VFS for every GIO app once the module is installed.
  - Selection is opt-in per process: `GIO_USE_VFS=gungnir` (GIO looks the extension up by name, regardless of priority). The integration test checks both cases: with the variable it gets `GungnirVfs`, without it `GLocalVfs`.
  - Until the daemon path exists, the `GVfsClass` vfuncs `get_file_for_path`, `get_file_for_uri` and `parse_name` delegate to `g_vfs_get_local()` (transfer none: never unref it), never to `g_vfs_get_default()` (that is GungnirVfs itself and would recurse). Their results are transfer full and are returned as is. `is_active` returns TRUE.
  - **Each client feature's behaviour** (the daemon connection in `link.zig`, metadata hooks `gmeta.zig`, mount health `health.zig`, `GungnirFileOp` `fileop.zig`, `trash:`/`recent:` `vfsfile.zig`): `docs/spec/client.md`. Read it before changing any of those files, their threads, budgets or error mapping.
  - `get_supported_uri_schemes` returns GungnirVfs's own static, NULL-terminated class list (`{ "file", "trash", "recent", NULL }`; only schemes that work). Never return `g_vfs_get_supported_uri_schemes(g_vfs_get_local())`: GVfs caches the element pointers, which point into the local VFS's private scheme table (freed by `g_vfs_unregister_uri_scheme`: use-after-free), and the base class would list `resource` twice.
- **C Linkage & VTable Definitions:**
  - Link `libc` and `libgio-2.0` (mandatory; host GTK processes already link glibc).
  - Consume GLib/GIO headers exclusively through the build graph: `b.addTranslateC` on a header generated in `build.zig` (`#include <gio/gio.h>`), imported as module `c` (`const c = @import("c");`). `@cImport` no longer exists on Zig master.
  - Variadic C macros (e.g. `g_critical`, `g_warning`) cannot be translated; call the underlying function (`c.g_log`) directly.
  - Implement GObject virtual tables (`GVfsClass`, `GFileIface`) as Zig `extern struct` types containing typed function pointers matching C ABI prototypes. Untyped `*anyopaque` or `void*` casts for vtables are forbidden. Class structs embed the translated parent class (`extern struct { parent_class: c.GVfsClass }`) and `class_init` assigns typed `callconv(.c)` functions to its slots; the only pointer casts allowed are GObject's own: `class_init`'s `gpointer` class argument to the class struct, and instance upcasts such as `*GIOModule` to `*GTypeModule`.
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
  - **Daemon structure** (start-up order in `daemon.rs`, the service `Router`, `hooks::Hooks`, the `proto` modules and `protocol/wire.txt`, `LockFile`): `docs/spec/daemon.md`.
  - **Wire protocol and services** (handshake, rings, every message kind and payload, the metadata, health, file-op, trash and recent semantics, non-blocking rules): `docs/spec/protocol.md`. Read it before changing `ipc.rs`/`ipc.zig`, a service or its Zig mirror; change both sides together.
- **Metadata storage and file identity** (SQLite WAL settings, schema, the `fs_uuid`/`subvol_id`/`inode_num`/`generation` key, the Resolver): `docs/spec/store.md`. Read it before touching `store.rs`, `fsid.rs`, `mdsvc.rs` or the schema.
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
- All temporary sockets, test roots, and build artifacts MUST reside in `./.build/` or `$HOME/.cache/gungnir/`:
  - Cargo: `.cargo/config.toml` sets `[build] target-dir = ".build/target"` (applies from the repo root and from `src/daemon-rust`).
  - Zig: build through the repo-root wrapper `./zb` (`zig build --prefix .build/zig-out --cache-dir .build/zig-cache`, run inside `src/client-zig`); neither directory can be set from `build.zig`. Do not run a bare `zig build` in `src/client-zig`: it creates `src/client-zig/.zig-cache` and `zig-out`. The global cache stays in `~/.cache/zig`.
  - The integration test's module dir is a build-cache directory under `.build/zig-cache`.
- Safe command execution: Never emit destructive commands (`git reset --hard`, `git clean -fdx`, or commands closing active terminal sessions).
- Compilation failure circuit breaker: If an analyzer or compiler fails twice with the same diagnostic, stop and output the exact error trace.
- No personal names, emails, or other personal details in code, metadata (`authors` fields), or commits.
- `main` is protected on GitLab: land a branch through a merge request (auto-merge "when checks pass" once its pipeline runs), never a direct push.

## 4. CONCRETE VERIFICATION TARGETS & SLOs
Before declaring any task complete, run `./check`, one line per gate. It is the only copy of the gates: each CI job calls one of its subcommands (`./check --help` lists them), so it runs everything a push pipeline runs (the cross-user tests only as root: `sudo ./check cross-user`; the scheduled `./check perf` apart). `./check --fast` runs the static gates in seconds (also the pre-commit hook: `./check --install-hook`); `./check --snapshot` runs on a copy of the working tree under `.build/snapshot`, so editing can go on during the 10-minute suite. What each suite must cover, and the skip policy: `docs/spec/testing.md`. The SLOs below are the targets the suites measure.

1. **Batch Removal & Event Throughput Benchmark:**
   - An automated test burst of **50,000 file deletion/update events** must satisfy:
     - Total burst completion time: **< 1.5 seconds** wall-clock time.
     - Per-operation p99 latency: **< 1.0 millisecond**.
     - Maximum client-thread blocking pause: **< 5.0 milliseconds** on any single GIO slice.
     - Peak resident set size (RSS): **< 40 MiB**.
