use std::{
    fmt, io,
    path::{Path, PathBuf},
};

use rusqlite::Connection;

pub mod ipc;

/// Scratch directories for tests, under `<repo>/.build/tmp` (AGENTS.md §3: never /tmp).
#[cfg(test)]
pub(crate) mod testdir {
    use std::{
        ffi::CString,
        fs, io,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, PermissionsExt},
            },
        },
        path::{Path, PathBuf},
        sync::atomic::{AtomicU32, Ordering},
    };

    /// A fresh directory that only we can enter (0700), one per test, removed with its
    /// contents on drop. CI runners check the repo out with umask 0000, which leaves
    /// `.build/tmp` itself 0777, and `ipc::bind` (rightly) refuses a socket directory that
    /// others can write to. Every check and chmod is done on an fd opened with
    /// `O_NOFOLLOW` (never by path), so a symlink or a directory swapped in between the
    /// check and the chmod can never redirect it to some other directory.
    pub(crate) struct TestDir(PathBuf);

    fn euid() -> u32 {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// Open `name` (relative to `dirfd`, or a path if `dirfd` is `AT_FDCWD`) as a
    /// directory without following a symlink in its last component, and require that it
    /// is a directory owned by us.
    fn open_own_dir(dirfd: i32, name: &CString) -> io::Result<fs::File> {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `name` is a valid NUL-terminated string that outlives the call.
        let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by openat and nothing else owns it.
        let dir = unsafe { fs::File::from_raw_fd(fd) };
        let md = dir.metadata()?; // fstat: the object we opened, not whatever the path is now
        if !md.is_dir() || md.uid() != euid() {
            return Err(io::Error::other("not a directory owned by us"));
        }
        Ok(dir)
    }

    fn cstr(p: &[u8]) -> io::Result<CString> {
        CString::new(p).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }

    impl TestDir {
        pub(crate) fn new(name: &str) -> io::Result<Self> {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let (base_path, base) = base()?;
            loop {
                let n = NEXT.fetch_add(1, Ordering::Relaxed);
                let leaf = format!("{name}-{}-{n}", std::process::id());
                let c_leaf = cstr(leaf.as_bytes())?;
                // mkdirat in the directory we checked; never adopt an existing entry.
                // SAFETY: `base` is an open directory fd and `c_leaf` is NUL-terminated.
                if unsafe { libc::mkdirat(base.as_raw_fd(), c_leaf.as_ptr(), 0o700) } < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::AlreadyExists && n < 1_000_000 {
                        continue;
                    }
                    return Err(e);
                }
                let dir = TestDir(base_path.join(&leaf));
                // The umask may have stripped bits from 0700, never added any: make it exact.
                open_own_dir(base.as_raw_fd(), &c_leaf)?
                    .set_permissions(fs::Permissions::from_mode(0o700))?;
                return Ok(dir);
            }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }

        pub(crate) fn join(&self, file: &str) -> PathBuf {
            self.0.join(file)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            // remove_dir_all never follows symlinks inside the tree (std, since 1.58.1).
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// `<repo>/.build/tmp` (its parent canonicalised: `sun_path` holds only 108 bytes),
    /// opened `O_NOFOLLOW`: a symlink there is refused, never followed. It must be a
    /// directory owned by us, and its group/world write bits are removed via `fchmod` on
    /// that fd, so no other user can swap a test's directory out from under it.
    fn base() -> io::Result<(PathBuf, fs::File)> {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build");
        let path = fs::canonicalize(&parent)?.join("tmp");
        if let Err(e) = fs::create_dir(&path)
            && e.kind() != io::ErrorKind::AlreadyExists
        {
            return Err(e);
        }
        let dir =
            open_own_dir(libc::AT_FDCWD, &cstr(path.as_os_str().as_bytes())?).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: {e} (symlinks are refused)", path.display()),
                )
            })?;
        let mode = dir.metadata()?.mode();
        if mode & 0o022 != 0 {
            dir.set_permissions(fs::Permissions::from_mode(mode & 0o7755))?;
        }
        Ok((path, dir))
    }

    #[test]
    fn test_dirs_are_private_whatever_the_umask() -> io::Result<()> {
        let a = TestDir::new("priv")?;
        let b = TestDir::new("priv")?;
        assert_ne!(a.path(), b.path());
        for d in [&a, &b] {
            let md = fs::symlink_metadata(d.path())?;
            assert!(md.is_dir());
            assert_eq!(md.mode() & 0o7777, 0o700);
            let parent = d.path().parent().ok_or(io::ErrorKind::NotFound)?;
            assert_eq!(fs::symlink_metadata(parent)?.mode() & 0o022, 0);
        }
        let gone = a.path().to_path_buf();
        fs::write(a.join("f"), b"x")?;
        drop(a);
        assert!(!gone.exists());
        Ok(())
    }
    #[test]
    fn open_own_dir_never_follows_a_symlink() -> io::Result<()> {
        let t = TestDir::new("sym")?;
        let real = t.join("real");
        fs::create_dir(&real)?;
        let link = t.join("link");
        std::os::unix::fs::symlink(&real, &link)?;
        let c = cstr(link.as_os_str().as_bytes())?;
        assert!(open_own_dir(libc::AT_FDCWD, &c).is_err());
        assert!(open_own_dir(libc::AT_FDCWD, &cstr(real.as_os_str().as_bytes())?).is_ok());
        Ok(())
    }
}

// `journal_mode` reports the mode actually in effect and silently keeps the old
// one when WAL is unavailable (e.g. ":memory:"), so it is queried and checked.
const JOURNAL_MODE_WAL: &str = "PRAGMA journal_mode = WAL";
const PRAGMAS: &str = "PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;";

// No separate delete index: the PRIMARY KEY prefix (fs_uuid, subvol_id, inode_num)
// already serves unlink deletes; an extra index only adds write cost.
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS metadata (
  fs_uuid    TEXT    NOT NULL,
  subvol_id  INTEGER NOT NULL,
  inode_num  INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  key        TEXT    NOT NULL,
  btime_sec  INTEGER NOT NULL DEFAULT 0,
  btime_nsec INTEGER NOT NULL DEFAULT 0,
  value      BLOB,
  PRIMARY KEY (fs_uuid, subvol_id, inode_num, generation, key)
) WITHOUT ROWID;";

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Sqlite(rusqlite::Error),
    NoHome,
    WalUnavailable(String),
    NoSocketPath,
    SocketPathTooLong(PathBuf),
    AlreadyRunning(PathBuf),
    NotASocket(PathBuf),
    InsecureSocketDir(PathBuf),
    Protocol(&'static str),
    RingFull,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Sqlite(e) => write!(f, "sqlite: {e}"),
            Error::NoHome => write!(f, "HOME is not set and no database path was given"),
            Error::WalUnavailable(mode) => {
                write!(
                    f,
                    "sqlite refused WAL journal mode (still in '{mode}' mode)"
                )
            }
            Error::NoSocketPath => write!(f, "no socket path (set XDG_RUNTIME_DIR or HOME)"),
            Error::SocketPathTooLong(p) => write!(f, "socket path too long: {}", p.display()),
            Error::AlreadyRunning(p) => write!(f, "already listening on {}", p.display()),
            Error::NotASocket(p) => write!(f, "{} exists and is not a socket", p.display()),
            Error::InsecureSocketDir(p) => write!(
                f,
                "{} must be a directory owned by this user and not world-writable",
                p.display()
            ),
            Error::Protocol(what) => write!(f, "protocol: {what}"),
            Error::RingFull => write!(f, "ring full"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Open (or create) the metadata DB, apply the required PRAGMAs and schema.
///
/// # Errors
/// I/O errors creating the parent directory, SQLite errors, or
/// [`Error::WalUnavailable`] if SQLite does not switch to WAL.
pub fn open_db(path: &Path) -> Result<Connection> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let conn = Connection::open(path)?;
    let mode: String = conn.query_row(JOURNAL_MODE_WAL, [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(Error::WalUnavailable(mode));
    }
    conn.execute_batch(PRAGMAS)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Synthetic fs id for UUID-less filesystems: `synth-<first 32 hex of BLAKE3>`.
/// Each part is length-prefixed so ("ab","c") and ("a","bc") never collide.
#[must_use]
pub fn synth_fs_id(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let hex = h.finalize().to_hex();
    format!("synth-{}", &hex[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::path::PathBuf;

    /// Test DB in its own private directory under <repo>/.build/tmp (AGENTS.md: never
    /// /tmp), independent of TMPDIR. The directory and the DB (with its -wal and -shm
    /// files) are removed on drop, so a failing assertion (tests unwind even with
    /// panic = "abort" in the release profile) or an early `?` cleans up too.
    struct TestDb(PathBuf, #[allow(dead_code)] TestDir);

    impl TestDb {
        fn new(name: &str) -> Result<Self> {
            let dir = TestDir::new(&format!("db-{name}"))?;
            Ok(Self(dir.join("metadata.db"), dir))
        }
    }

    #[test]
    fn db_opens_in_wal_with_schema() -> Result<()> {
        let db = TestDb::new("wal")?;
        let conn = open_db(&db.0)?;
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        assert_eq!(mode, "wal");
        let sql: String = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'metadata'",
            [],
            |r| r.get(0),
        )?;
        assert!(sql.contains("WITHOUT ROWID"));
        Ok(())
    }

    #[test]
    fn non_wal_database_is_rejected() {
        let err = open_db(Path::new(":memory:")).err();
        assert!(matches!(err, Some(Error::WalUnavailable(ref m)) if m == "memory"));
    }

    #[test]
    fn synth_id_format_and_separation() {
        let id = synth_fs_id(&[b"tmpfs", b"/run/user/1000"]);
        assert!(id.starts_with("synth-"));
        assert_eq!(id.len(), "synth-".len() + 32);
        assert!(id[6..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, synth_fs_id(&[b"tmpfs", b"/run/user/1000"]));
        assert_ne!(synth_fs_id(&[b"ab", b"c"]), synth_fs_id(&[b"a", b"bc"]));
    }
}
