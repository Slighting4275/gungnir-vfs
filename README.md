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
# Zig GIO module
cd src/client-zig
zig build
zig build test --summary all
cd ../..

# Rust daemon
cargo build --release
cargo test --release
cargo clippy --release -- -D warnings
```

Build artifacts stay inside the repo under `.build/`, so nothing needs to run from `/tmp`.

## Trying it

Gungnir only loads when you ask for it. It registers at a low priority, so it is never
picked by default:

```sh
GIO_USE_VFS=gungnir gio info .
```

## Contributing

Read [AGENTS.md](AGENTS.md) first. It covers the language rules (Zig for the client, Rust
for the daemon, nothing else) and the build and test gates every change must pass.

## License

Not yet chosen.
