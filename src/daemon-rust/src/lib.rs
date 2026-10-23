use std::{fmt, io, path::Path};

use rusqlite::Connection;

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
    use std::path::PathBuf;

    /// Test DB under <repo>/.build/tmp (AGENTS.md: never /tmp), independent of
    /// TMPDIR, removed on drop so a failing assertion (tests unwind even with
    /// panic = "abort" in the release profile) or an early `?` cleans up too.
    struct TestDb(PathBuf);

    impl TestDb {
        fn new(name: &str) -> Self {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build/tmp");
            Self(dir.join(format!("gungnird-{name}-{}.db", std::process::id())))
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            for ext in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{ext}", self.0.display()));
            }
        }
    }

    #[test]
    fn db_opens_in_wal_with_schema() -> Result<()> {
        let db = TestDb::new("wal");
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
