# Metadata store and file identity

The SQLite store (`store.rs`), its schema, and how a file is identified (`fsid.rs`, the Resolver).

- **Metadata Storage (SQLite in WAL Mode):**
  - Default database path: `$XDG_DATA_HOME/gungnir/metadata.db`, else `$HOME/.local/share/gungnir/metadata.db` (absolute values only; overridable by the first CLI argument). The directory is created `0700` and refused if it is not ours or is group/world-writable; the file is created (or tightened to) `0600`, and SQLite gives `-wal`/`-shm` the same mode. A database SQLite cannot read (not starting with its header, or "not a database"/"malformed" at open) is renamed, never deleted, to `metadata.db.corrupt-<secs>` with its `-wal`/`-shm` (a bad header is set aside before SQLite opens it, so the journal survives), made `0600`, and the daemon starts on an empty store instead of failing every start.
  - Required PRAGMAs:
    `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;` and `busy_timeout` 20 ms with at most 2 retries (5 ms apart), then `busy`. Never a long busy_timeout while serving: one DB thread serves every client. Opening the database (switching to WAL, creating the schema) happens before anything is served and may wait up to 5 s (busy_timeout, plus retrying the setup on an immediate `SQLITE_BUSY`), so a second opener or a backup cannot stop the daemon from starting.
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
    `value` is the wire encoding of the value (type byte first). Last known path, a hint for later moves and GC (recorded on set from the connection's last identify of that identity; dropped with the file's last key):
    ```sql
    CREATE TABLE path_hint (
      fs_uuid TEXT NOT NULL, subvol_id INTEGER NOT NULL, inode_num INTEGER NOT NULL,
      generation INTEGER NOT NULL, path BLOB NOT NULL, updated INTEGER NOT NULL,
      PRIMARY KEY (fs_uuid, subvol_id, inode_num, generation)
    ) WITHOUT ROWID;
    CREATE INDEX path_hint_by_path ON path_hint (path); -- removed/moved look hints up by path (M6)
    ```
  - Unlink/delete path:
    - Deleted files are removed with `DELETE FROM metadata WHERE fs_uuid = ? AND subvol_id = ? AND inode_num = ?`, batched in a single transaction per event burst.
    - Do NOT add a separate index on `(fs_uuid, subvol_id, inode_num)`: the PRIMARY KEY prefix already serves deletes, and an extra index adds a write to every insert.
    - GIO deletes (milestone 6, `removed`) currently drop one identity's rows by the full key including `generation`, one transaction per notification; the batched burst path is for the future event watcher.
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
    - Resolver (milestone 4, `src/daemon-rust/src/fsid.rs`): a path is opened `O_PATH | O_NOFOLLOW` (a symlink is identified as itself) and one `statx` (`AT_STATX_DONT_SYNC`) gives `inode_num`, `subvol_id`, `btime` and `STATX_MNT_ID`. The ioctls need a readable fd, so only regular files and directories are reopened through `/proc/self/fd` (`O_RDONLY | O_NONBLOCK`); FIFOs, devices and every FUSE file are never opened and get `generation = 0` (FUSE forwards `FS_IOC_GETVERSION` to the userspace server and has no `s_uuid`). A failed reopen is returned (`EACCES`, `EMFILE`, no procfs), never turned into `generation = 0`; the one exception is `EACCES`/`EPERM` on a filesystem whose root directory (same mount id) answers `FS_IOC_GETVERSION` as unsupported, where 0 is what a readable fd gives too. On btrfs without `STATX_SUBVOL` (Linux < 6.10) `subvol_id` comes from the unprivileged `BTRFS_IOC_INO_LOOKUP` (treeid 0, objectid 256) on that readable fd, the same value `STATX_SUBVOL` reports; a btrfs symlink, FIFO or device there fails with `NoSubvol` rather than collide on subvolume 0. Unsupported ioctls (`ENOTTY`, `EINVAL`, `EOPNOTSUPP`, `ENOSYS`) mean 0/next step; any other error is returned, never turned into a different key. `fs_uuid` and `f_type` (one `statfs`, a server round trip on NFS/FUSE) are resolved once per mount and cached by mount id (an entry is dropped when its mountinfo line changes or vanishes); step 1 tries the file, then the mount's root directory (same mount id only); UUIDs are lowercase in both steps 1 and 2. Synthetic ids hash `f_type` as the 32-bit magic zero-extended to a little-endian u64. `/proc/self/mountinfo` fields are split on single spaces (an empty source is a real field). It is re-read only when a zero-timeout `poll` reports `POLLPRI`; `poll` itself clears the kernel's flag, so a failed re-read is retried on the next lookup.
    - Non-blocking rule for identity: every syscall on the target runs on a `Resolver` worker (4 started, at most 16 threads counting stuck ones, a bounded queue). The caller waits at most the deadline (250 ms): a request a worker started but did not finish returns `Timeout` and marks its mount (longest mount-point prefix, from the cached table, never a syscall on the target; asked again at the timeout if the cache was busy at dispatch) suspect for 30 s (a span that overflows `Instant` means until cleared), so later requests for it fail fast with `SuspectMount`; a request that never reached a worker returns `Busy` and blames no mount.
