# Gungnir (gungnir-vfs)

> Odin's spear never hesitates, never stops mid-flight, and never misses.

Gungnir is a high-performance replacement for GVfs, the GNOME virtual filesystem layer. It is designed as a non-blocking I/O pipeline. The design goal is that no filesystem call or UI application thread blocks or hangs on a broken mount, stalled network share, or metadata lock; that goal is not yet met in every case (G-N, BC-PR-F005 are open).

---

## Architecture & Milestones

Gungnir's 12-milestone architecture aims at stall-free virtual filesystem operations (a design goal; see the open issues below):

| Milestone | Subsystem | Status | Highlights |
| :--- | :--- | :--- | :--- |
| **M1** | Dynamic GIO Extension Module | **Complete** | `libgiogungnir.so` dynamic registration, `GungnirVfs` subclass, opt-in via `GIO_USE_VFS=gungnir`. |
| **M2** | Handshake Protocol v1 & IPC | **Complete** | AF_UNIX control socket, SPSC ring pair in sealed `memfd`, process-shared futex wakeups. |
| **M3** | Protocol v2 Ring Architecture | **Complete** | 32 slots × 4096-byte frames, 64 concurrent clients, zero-copy atomic ring slots. |
| **M4** | Filesystem Identity Resolver | **Complete** | Recycled inode detection, `fs_uuid`, subvolume IDs, generation ioctls, deterministic BLAKE3 synthetic IDs. |
| **M5** | Metadata Service over IPC | **Complete** | SQLite in WAL mode (`metadata.db`), btime staleness checks, single-thread DB worker queue. |
| **M6** | GIO `metadata::` Attributes | **Complete** | Dynamic `GVfsClass` hooks, `local_file_moved` and `local_file_removed` tracking, live `gio set` / `gio info`. |
| **M7** | Hang-Proof Mount Health Monitor | **Complete** | Sacrificial probe threads, automatic detection of hung/gone network and FUSE mounts, fail-fast refusal (`SuspectMount`). |
| **M8** | Asynchronous File Operations Engine | **Implemented; known open issues (INT-HIGH-001, C1, PR-F008)** | Native kernel `io_uring` with POSIX fallback, reflink (`FICLONE`), sparse copying (`copy_file_range`), atomic rename, progress events & cancellation. |
| **M9** | Trash & Recent Items Engine | **Not on main (T-005 port pending)** | `trash://` and `recent://` are not implemented on this branch. |
| **M10** | Volume & Mount Monitor | **Experimental, opt-in; no mount change signals yet (F01b)** | `GVolumeMonitor`, `GVolume`, `GMount` from a non-blocking mountinfo parser, active only with `GIO_USE_VOLUME_MONITOR=gungnir`; mounts and volumes are listed, but no mount-added/removed signals are emitted yet. |
| **M11** | Daemon Lifecycle Management | **Partial: shutdown is not yet graceful for in-flight ops (AUD-03, BC-HC-F06 open)** | systemd socket activation (`LISTEN_FDS`/`LISTEN_PID`, fd 3 adoption), idle auto-shutdown (`--idle-timeout` / `GUNGNIR_IDLE_TIMEOUT_SEC`), race-free `signalfd` multiplexing (`SIGINT`/`SIGTERM` shutdown, which does not yet wait for or clean up in-flight file ops, `SIGHUP`/`SIGUSR1` live in-place upgrade re-exec handover), SQLite WAL checkpointing. |
| **M12** | Hardening & System Release | **In review (HC-001: seccomp hardening D-044, unit hardening AUD-01)** | Zero-dependency Linux seccomp BPF filter sandbox (`--seccomp`), systemd user units (`gungnird.service` / `gungnird.socket`; their sandboxing is under review, AUD-01), Arch Linux `PKGBUILD` packaging, wire and metadata-wire fuzz tests. The 50,000-event stress benchmark is outside the default test suite: the CI job `rust:perf` runs it (`cargo test --release --test stress_throughput -- --ignored`, SLO asserts unchanged) in scheduled and manually started pipelines only; its throughput, p99 and RSS figures are not reproduced here (tracked in T-010). |

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

Supported configurations (D-025):

| Dimension | Supported |
| :--- | :--- |
| Linux kernel | **5.8 or newer required.** 5.8 to 6.9 (no `STATX_SUBVOL` / `FS_IOC_GETFSUUID`) is **experimental**: its fallbacks are not tested on a real old kernel. |
| GLib / GIO | **2.84 or newer** |
| Architecture | **x86_64 only** |
| Client and daemon | **Same revision only.** There is no capability negotiation yet. |

Build requirements:

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

# Run background daemon with custom socket, DB path, idle auto-shutdown, and seccomp BPF sandbox
gungnird --socket /run/user/1000/gungnir/control.sock --db ~/.local/share/gungnir/metadata.db --idle-timeout 300 --seccomp

# Live in-place upgrade without dropping incoming connections
kill -HUP $(pgrep gungnird)

# Enable systemd user socket activation
systemctl --user enable --now gungnird.socket
```

---

## Packaging & Systemd Units

- **Systemd User Units**: Located in [`init/systemd/`](init/systemd/):
  - `gungnird.socket`: Socket activation unit listening on `%t/gungnir/gungnird.sock`.
  - `gungnird.service`: Sandboxed service unit with `ProtectSystem=strict`, `ProtectHome=read-only`, and system call filtering.
- **Arch Linux PKGBUILD**: Provided in [`packaging/archlinux/PKGBUILD`](packaging/archlinux/PKGBUILD) and [`packaging/PKGBUILD`](packaging/PKGBUILD). Builds `gungnird` and `libgiogungnir.so`, runs verification tests, and packages binaries, systemd units, licenses, and documentation.

---

## CI & Verification

Every push and merge request executes [`.gitlab-ci.yml`](.gitlab-ci.yml) against a verified Arch Linux environment:
- `cargo fmt --all --check` & `zig fmt --check src/client-zig`
- `cargo clippy --release --all-targets -- -D warnings`
- `cargo test --release --no-fail-fast`, with the io_uring engine (`rust:test`) and, in its own job, with `GUNGNIR_NO_URING=1` (thread engine, `rust:test-no-uring`)
- `./zb test --summary all` across all 14 integration test modes: `opt-in`, `no-opt-in`, `daemon`, `hung`, `metadata`, `gio-metadata`, `gio-cli`, `daemon-stopped`, `ui-thread`, `hung-mount`, `file-ops`, `volmon`, `volmon-off`, `volmon-installed`.

Scheduled and manually started pipelines also run `rust:perf`: `cargo test --release --test stress_throughput -- --ignored`, the 50,000-event benchmark with its SLO asserts.

---

## License

Gungnir is licensed under the GNU GPL v3.0 or later **and** the GNU AGPL v3.0 or later, combined (SPDX: `GPL-3.0-or-later AND AGPL-3.0-or-later`). Both apply at once; it is not a choice between them. The full text of both licenses is written in [COPYING](COPYING), [LICENSE](LICENSE), and the [LICENSES/](LICENSES) directory.
