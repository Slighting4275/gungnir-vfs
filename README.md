# Gungnir (gungnir-vfs)

> Odin's spear never hesitates, never stops mid-flight, and never misses.

Gungnir is a replacement for GVfs, the GNOME virtual filesystem layer. It is built as a
non-blocking I/O pipeline: no call ever waits on a broken mount or a metadata lock.

**Status:** early skeleton. It does not replace GVfs yet. The GIO module currently
hands every operation to GLib's local VFS.

## Components

| Part | Language | Path | Role |
|------|----------|------|------|
| `libgiogungnir.so` | Zig | `src/client-zig` | GIO extension module loaded into GLib applications |
| `gungnird` | Rust | `src/daemon-rust` | Background daemon that owns mounts and metadata |

## Design

- The client and daemon talk over memfd shared-memory rings with futex wakeups, using an AF_UNIX socket for setup. There is no D-Bus on the data path.
- Metadata is stored in SQLite in WAL mode. Each row is keyed by filesystem UUID, subvolume, inode number, and inode generation, so the data survives inode reuse.
- Filesystems without a UUID get a stable synthetic ID derived with BLAKE3.

The full rules are in [AGENTS.md](AGENTS.md).

## Requirements

- Linux
- Zig master (nightly)
- Rust stable (edition 2024)
- GLib/GIO development files and `pkg-config`

## Build and test

```sh
# Zig GIO module (./zb runs zig build with every output under .build/)
./zb
./zb test --summary all

# Rust daemon
cargo build --release
cargo test --release
cargo clippy --release --all-targets -- -D warnings
```

Build artifacts stay inside the repo under `.build/`, so nothing needs to run from `/tmp`.

## Trying it

Gungnir only loads when you ask for it. It registers at a low priority, so it is never
picked by default:

```sh
GIO_USE_VFS=gungnir gio info .
```

## CI

Every push and merge request runs [`.gitlab-ci.yml`](.gitlab-ci.yml) on GitLab in a pinned
`archlinux` image (tag and digest) that installs packages from the Arch Linux Archive snapshot
of the same day, so runs are reproducible. Lint checks formatting (`cargo fmt --check`,
`zig fmt --check`), `cargo check` with `-D warnings` and
`cargo clippy --all-targets -- -D warnings`. Build runs `cargo build --release` and `./zb`
with the exported-symbol and `gio-querymodules` checks.
Test runs `cargo test --release` and `./zb test --summary all`. CI uses the current Zig master
tarball from ziglang.org and rejects it unless its minisign signature, signed file name and
sha256 verify, and it is not older than `minimum_zig_version` in `build.zig.zon`.

## Contributing

Read [AGENTS.md](AGENTS.md) first. It covers the language rules (Zig for the client, Rust
for the daemon, nothing else) and the build and test gates every change must pass.

## License

Gungnir is licensed under the GNU GPL v3.0 or later **and** the GNU AGPL v3.0 or later, combined
(SPDX: `GPL-3.0-or-later AND AGPL-3.0-or-later`). Both apply at once; it is not a choice
between them. See [COPYING](COPYING) and the full texts in [LICENSES/](LICENSES).
