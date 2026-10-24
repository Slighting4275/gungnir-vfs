# Gungnir (gungnir-vfs)

> Odin's spear never hesitates, never stops mid-flight, and never misses.

Gungnir is a high-performance replacement for GVfs, the GNOME virtual filesystem layer. It is engineered from the ground up as a non-blocking I/O pipeline: no filesystem call or UI application thread ever blocks or hangs on a broken mount, stalled network share, or metadata lock.

---

## Architecture & Milestones

Gungnir's 12-milestone architecture delivers zero-stall virtual filesystem operations:

| Milestone | Subsystem | Status | Highlights |
| :--- | :--- | :--- | :--- |
| **M1** | Dynamic GIO Extension Module | **Complete** | `libgiogungnir.so` dynamic registration, `GungnirVfs` subclass, opt-in via `GIO_USE_VFS=gungnir`. |
| **M2** | Handshake Protocol v1 & IPC | **Complete** | AF_UNIX control socket, SPSC ring pair in sealed `memfd`, process-shared futex wakeups. |
| **M3** | Protocol v2 Ring Architecture | **Complete** | 32 slots × 4096-byte frames, 64 concurrent clients, zero-copy atomic ring slots. |
| **M4** | Filesystem Identity Resolver | **Complete** | Recycled inode detection, `fs_uuid`, subvolume IDs, generation ioctls, deterministic BLAKE3 synthetic IDs. |
| **M5** | Metadata Service over IPC | **Complete** | SQLite in WAL mode (`metadata.db`), btime staleness checks, single-thread DB worker queue. |
| **M6** | GIO `metadata::` Attributes | **Complete** | Dynamic `GVfsClass` hooks, `local_file_moved` and `local_file_removed` tracking, live `gio set` / `gio info`. |
| **M7** | Hang-Proof Mount Health Monitor | **Complete** | Sacrificial probe threads, automatic detection of hung/gone network and FUSE mounts, fail-fast refusal (`SuspectMount`). |
| **M8** | Asynchronous File Operations Engine | **Complete** | Native kernel `io_uring` with POSIX fallback, reflink (`FICLONE`), sparse copying (`copy_file_range`), atomic rename, progress events & cancellation. |
| **M9** | Trash & Recent Items Engine | **Complete** | FreeDesktop.org Trash spec 1.0 (`trash://`, `.trashinfo`), `recent://` URI schemes, mount boundary defenses (`DIB-F001`), relative path sanitization (`SEC-F-001`). |
| **M10** | Volume & Mount Monitor | **In Progress** | `GVolumeMonitor`, `GVolume`, `GMount`, `GDrive` event-driven lifecycle. |
| **M11** | Daemon Lifecycle Management | **Queued** | Socket activation, idle auto-shutdown, live upgrade handoff. |
| **M12** | Hardening & System Release | **Queued** | Seccomp BPF filters, fuzzing verification, PKGBUILD, systemd user service. |

---

## Components

| Part | Language | Path | Role |
| :--- | :--- | :--- | :--- |
| `libgiogungnir.so` | Zig (nightly) | `src/client-zig` | GIO extension module loaded directly into GLib/GTK applications |
| `gungnird` | Rust 2024 | `src/daemon-rust` | Background daemon owning mounts, rings, file ops, and metadata |

---

## Key Design Principles

- **Zero-Copy IPC & Futex Signaling**: Client and daemon communicate through sealed `memfd` shared memory rings. Process-shared futexes (`FUTEX_WAIT` / `FUTEX_WAKE`) eliminate CPU spin and latency. D-Bus is completely excluded from the data plane.
- **Persistent Inode-Resilient Metadata**: Stored in SQLite in WAL mode. Rows are uniquely keyed by filesystem UUID, subvolume ID, inode number, and generation number—metadata follows file renames and moves seamlessly and survives inode recycling via birth-time (`btime`) checks.
- **Fail-Fast Mount Health Protection**: A dedicated sacrificial thread monitor probes network (NFS, SMB/CIFS, 9P, Ceph) and FUSE mounts. Mounts exceeding deadlines or exhibiting kernel stalls are marked suspect; subsequent requests are rejected immediately with `SuspectMount` before any syscall touches them.
- **High-Performance Async File Operations**: Direct `io_uring` queues execute file copies, moves, and deletions with zero main-thread overhead. Transparently uses Btrfs/XFS reflink (`FICLONE`), sparse extent skipping (`SEEK_DATA` / `SEEK_HOLE`), and atomic temporary file swapping.
- **Strict Host Security**: Build and test outputs are confined to `.build/` to honor hardened `noexec` `/tmp` environments. Zero personal data or host credentials in code or commits.

---

## Requirements

- Linux kernel 5.8+ (6.8+ recommended for native `FS_IOC_GETFSUUID`)
- Zig master (nightly)
- Rust stable (edition 2024)
- GLib/GIO development packages and `pkg-config`

---

## Build and Test

```sh
# Build Zig GIO module (outputs strictly under .build/)
./zb
./zb test --summary all

# Build and test Rust daemon
cargo build --release
cargo test --release
cargo clippy --release --all-targets -- -D warnings
```

---

## Usage

Gungnir registers at low priority (`-100`) so it never overrides default VFS providers unless explicitly selected:

```sh
# Run any GIO/GLib tool through Gungnir VFS
GIO_USE_VFS=gungnir gio info .

# Set and inspect metadata
GIO_USE_VFS=gungnir gio set file.txt metadata::project "Gungnir"
GIO_USE_VFS=gungnir gio info -a 'metadata::*' file.txt
```

---

## CI & Verification

Every push and merge request executes [`.gitlab-ci.yml`](.gitlab-ci.yml) against a verified Arch Linux environment:
- `cargo fmt --all --check` & `zig fmt --check src/client-zig`
- `cargo clippy --release --all-targets -- -D warnings`
- `cargo test --release` (with and without `--features test-hooks`)
- `./zb test --summary all` across all 11 integration test modes: `opt-in`, `no-opt-in`, `daemon`, `hung`, `metadata`, `gio-metadata`, `gio-cli`, `daemon-stopped`, `ui-thread`, `hung-mount`, `file-ops`.

---

## License

Gungnir is licensed under the GNU GPL v3.0 or later **and** the GNU AGPL v3.0 or later, combined (SPDX: `GPL-3.0-or-later AND AGPL-3.0-or-later`). See [COPYING](COPYING) and [LICENSES/](LICENSES).
