//! Metadata store (milestone 5): SQLite in WAL mode, keyed by the M4 file identity, and
//! the dedicated database thread that owns the connection.
//!
//! Non-blocking rule: only the database thread ever touches SQLite. Ring threads hand it
//! jobs through a bounded queue ([`DbHandle::submit`] fails with [`MdError::Busy`] when it
//! is full) and never wait for them: the job's completion callback writes the reply. A
//! lock held by another process (a second daemon on the same file, a `sqlite3` shell)
//! costs at most `busy_timeout` x (`busy_retries` + 1) per job and then answers Busy;
//! jobs that sat in the queue longer than `max_age` are answered Busy without running,
//! except follow-ups ([`DbReq::is_follow_up`]), which record what already happened on disk.

use std::{
    ffi::OsStr,
    fs,
    os::fd::AsRawFd,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, SyncSender, TrySendError},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior, params};

use crate::{
    Error, Result,
    md::{Ident, MAX_KEYS_PER_FILE, MdError, Value, check_key, list_body},
};

// `journal_mode` reports the mode actually in effect and silently keeps the old
// one when WAL is unavailable (e.g. ":memory:"), so it is queried and checked.
const JOURNAL_MODE_WAL: &str = "PRAGMA journal_mode = WAL";
// busy_timeout is set separately from the config (small: see the module docs).
const PRAGMAS: &str = "PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = OFF;";

// No separate delete index on metadata: the PRIMARY KEY prefix (fs_uuid, subvol_id,
// inode_num) already serves unlink deletes; an extra index only adds write cost. path_hint
// (written only when a value is set) is indexed by path for removed/moved (milestone 6).
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
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS path_hint (
  fs_uuid    TEXT    NOT NULL,
  subvol_id  INTEGER NOT NULL,
  inode_num  INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  path       BLOB    NOT NULL,
  updated    INTEGER NOT NULL,
  links      INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (fs_uuid, subvol_id, inode_num, generation)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS path_hint_by_path ON path_hint (path);";

const ID_WHERE: &str = "fs_uuid = ?1 AND subvol_id = ?2 AND inode_num = ?3 AND generation = ?4";

/// Database file: `$XDG_DATA_HOME/gungnir/metadata.db`, else
/// `$HOME/.local/share/gungnir/metadata.db` (absolute values only).
///
/// # Errors
/// [`Error::NoHome`] if neither is set to an absolute path.
pub fn default_db_path(xdg_data_home: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf> {
    fn abs(v: Option<&OsStr>) -> Option<&Path> {
        v.map(Path::new).filter(|p| p.is_absolute())
    }
    if let Some(d) = abs(xdg_data_home) {
        return Ok(d.join("gungnir/metadata.db"));
    }
    if let Some(h) = abs(home) {
        return Ok(h.join(".local/share/gungnir/metadata.db"));
    }
    Err(Error::NoHome)
}

fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Create the database directory (0700) if missing and refuse one that is not ours or
/// is writable by others.
fn prepare_dir(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let md = fs::symlink_metadata(dir)?;
        if !md.is_dir() || md.uid() != euid() || md.mode() & 0o022 != 0 {
            return Err(Error::InsecureDbDir(dir.to_path_buf()));
        }
    }
    Ok(())
}

/// One daemon per store (DIR-C1-F02): an exclusive `flock` on `<db>.lock`, held for the
/// daemon's whole life. The socket's own lock only serialises daemons on one socket; two
/// daemons on different sockets sharing a store would each sweep the other's live temp
/// files and move its temp ledger aside. The lock file is never removed while another
/// daemon could be waiting on it, only by a failed start that created the store and
/// still holds it (see `FreshStore` in main.rs). Closed on exec, so a live upgrade
/// (an `execve` of the same process) takes it again.
#[derive(Debug)]
pub struct StoreLock {
    _file: fs::File,
    path: PathBuf,
    created: bool,
}

impl StoreLock {
    /// The lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this start created the lock file.
    #[must_use]
    pub fn created(&self) -> bool {
        self.created
    }

    /// The lock's fd (carried across a live upgrade, BC-CM-D02).
    #[must_use]
    pub fn fd(&self) -> std::os::fd::RawFd {
        self._file.as_raw_fd()
    }
}

/// Take the store's lock (see [`StoreLock`]), creating its directory as
/// [`open_db`] would. `None` for an in-memory database. `carried` is the lock's fd a live
/// upgrade's old image left open ([`crate::ipc::UPGRADE_STORE_LOCK_ENV`]): adopted, never
/// reopened, so the lock is held throughout the upgrade (BC-CM-D02).
///
/// # Errors
/// [`Error::StoreInUse`] if another daemon holds it, [`Error::InsecureDbDir`], a carried
/// fd that is not this store's lock, or I/O errors.
pub fn lock_store(db: &Path, carried: Option<std::os::fd::RawFd>) -> Result<Option<StoreLock>> {
    if db.as_os_str() == ":memory:" {
        return Ok(None);
    }
    prepare_dir(db)?;
    let mut path = db.as_os_str().to_os_string();
    path.push(".lock");
    let path = PathBuf::from(path);
    if let Some(fd) = carried {
        let file = crate::ipc::adopt_lock_fd(fd, &path)?;
        return Ok(Some(StoreLock {
            _file: file,
            path,
            created: false,
        }));
    }
    let open = |create_new: bool| {
        let mut o = fs::OpenOptions::new();
        o.read(true).write(true).mode(0o600);
        if create_new {
            o.create_new(true);
        }
        o.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
    };
    let (file, created) = match open(true) {
        Ok(f) => (f, true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (open(false)?, false),
        Err(e) => return Err(e.into()),
    };
    let md = file.metadata()?;
    if !md.is_file() || md.uid() != euid() {
        return Err(Error::InsecureDbDir(path));
    }
    // SAFETY: flock on an fd this function owns; no pointers.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
            Error::StoreInUse(db.to_path_buf())
        } else {
            e.into()
        });
    }
    Ok(Some(StoreLock {
        _file: file,
        path,
        created,
    }))
}

/// Create the database directory as [`prepare_dir`] does; create the file 0600 (and
/// tighten an existing file of ours). SQLite gives `-wal` and `-shm` the database
/// file's mode.
fn prepare_files(path: &Path) -> Result<()> {
    if path.as_os_str() == ":memory:" {
        return Ok(());
    }
    prepare_dir(path)?;
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let md = f.metadata()?;
    if !md.is_file() || md.uid() != euid() {
        return Err(Error::InsecureDbDir(path.to_path_buf()));
    }
    if md.mode() & 0o077 != 0 {
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Open (or create) the metadata DB, apply the PRAGMAs and schema.
///
/// # Errors
/// I/O errors creating the directory or file, [`Error::InsecureDbDir`], SQLite errors,
/// or [`Error::WalUnavailable`] if SQLite does not switch to WAL.
pub fn open_db(path: &Path, busy_timeout: Duration) -> Result<Connection> {
    prepare_files(path)?;
    let conn = Connection::open(path)?;
    // Setup (switching to WAL, creating the schema) runs once, before anything is served:
    // it may wait out another opener (a second daemon on the same file starting at the
    // same moment, a backup), so it gets SQLite's usual patience. The short serving
    // timeout applies from the first request on.
    // SQLite also returns SQLITE_BUSY at once, without its busy handler, where waiting
    // could deadlock (two connections switching a fresh file to WAL), so setup is retried
    // as a whole until the same deadline.
    conn.busy_timeout(OPEN_BUSY_TIMEOUT)?;
    let deadline = Instant::now() + OPEN_BUSY_TIMEOUT;
    loop {
        match setup(&conn) {
            Err(Error::Sqlite(e)) if is_busy(&e) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            r => break r?,
        }
    }
    conn.busy_timeout(busy_timeout)?;
    Ok(conn)
}

fn setup(conn: &Connection) -> Result<()> {
    let mode: String = conn.query_row(JOURNAL_MODE_WAL, [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(Error::WalUnavailable(mode));
    }
    conn.execute_batch(PRAGMAS)?;
    conn.execute_batch(SCHEMA)?;
    // Milestone 5 databases: path_hint without the hard link count.
    let has_links: bool = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('path_hint') WHERE name = 'links'",
        [],
        |r| r.get::<_, i64>(0).map(|n| n > 0),
    )?;
    if !has_links {
        conn.execute_batch("ALTER TABLE path_hint ADD COLUMN links INTEGER NOT NULL DEFAULT 1")?;
    }
    Ok(())
}

/// SQLite's wait for a lock while the database is being opened (not while serving).
pub const OPEN_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub struct StoreConfig {
    /// SQLite's own wait for a lock, per attempt. Small: the DB thread serves everyone.
    pub busy_timeout: Duration,
    /// Further attempts after a busy one.
    pub busy_retries: u32,
    /// Pause between attempts.
    pub retry_pause: Duration,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            busy_timeout: Duration::from_millis(20),
            busy_retries: 2,
            retry_pause: Duration::from_millis(5),
        }
    }
}

/// Errors inside a store transaction: SQLite's, or a protocol-level refusal.
enum TxErr {
    Sql(rusqlite::Error),
    Md(MdError),
}

impl From<rusqlite::Error> for TxErr {
    fn from(e: rusqlite::Error) -> Self {
        TxErr::Sql(e)
    }
}

fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

/// Same metadata key (btime is only a staleness check, not part of the key).
fn same_key(a: &Ident, b: &Ident) -> bool {
    a.fs_uuid == b.fs_uuid
        && a.subvol_id == b.subvol_id
        && a.inode_num == b.inode_num
        && a.generation == b.generation
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// SQLite stores INTEGER as i64; identity fields are u64 bit patterns.
fn sql_u64(v: u64) -> i64 {
    v as i64
}

/// The metadata database. Owned by exactly one thread (see [`spawn`]).
pub struct Store {
    conn: Connection,
    cfg: StoreConfig,
}

impl Store {
    /// # Errors
    /// As [`open_db`].
    pub fn open(path: &Path, cfg: StoreConfig) -> Result<Self> {
        Ok(Self {
            conn: open_db(path, cfg.busy_timeout)?,
            cfg,
        })
    }

    /// Checkpoint the WAL journal into the main database and truncate the WAL file.
    ///
    /// # Errors
    /// [`MdError::Busy`] if busy retries are exhausted, or [`MdError::Db`] on SQLite error.
    pub fn checkpoint(&mut self) -> std::result::Result<(), MdError> {
        let mut attempt = 0;
        loop {
            match self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
                Ok(()) => return Ok(()),
                Err(e) if is_busy(&e) => {
                    if attempt >= self.cfg.busy_retries {
                        return Err(MdError::Busy);
                    }
                    attempt += 1;
                    thread::sleep(self.cfg.retry_pause);
                }
                Err(e) => {
                    eprintln!("gungnird: checkpoint error: {e}");
                    return Err(MdError::Db);
                }
            }
        }
    }

    /// Run `f` in an IMMEDIATE transaction, retrying a busy database a bounded number of
    /// times, then [`MdError::Busy`]. Any other SQLite error is [`MdError::Db`].
    fn write<T>(
        &mut self,
        mut f: impl FnMut(&rusqlite::Transaction<'_>) -> std::result::Result<T, TxErr>,
    ) -> std::result::Result<T, MdError> {
        let mut attempt = 0;
        loop {
            let r = (|| {
                let tx = self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let v = f(&tx)?;
                tx.commit()?;
                Ok(v)
            })();
            match r {
                Ok(v) => return Ok(v),
                Err(TxErr::Md(e)) => return Err(e),
                Err(TxErr::Sql(e)) if is_busy(&e) => {
                    if attempt >= self.cfg.busy_retries {
                        return Err(MdError::Busy);
                    }
                    attempt += 1;
                    thread::sleep(self.cfg.retry_pause);
                }
                Err(TxErr::Sql(e)) => {
                    eprintln!("gungnird: metadata db: {e}");
                    return Err(MdError::Db);
                }
            }
        }
    }

    /// Read-only statement(s), with the same bounded retry.
    fn read<T>(
        &self,
        mut f: impl FnMut(&Connection) -> rusqlite::Result<T>,
    ) -> std::result::Result<T, MdError> {
        let mut attempt = 0;
        loop {
            match f(&self.conn) {
                Ok(v) => return Ok(v),
                Err(e) if is_busy(&e) => {
                    if attempt >= self.cfg.busy_retries {
                        return Err(MdError::Busy);
                    }
                    attempt += 1;
                    thread::sleep(self.cfg.retry_pause);
                }
                Err(e) => {
                    eprintln!("gungnird: metadata db: {e}");
                    return Err(MdError::Db);
                }
            }
        }
    }

    /// True if the stored rows belong to an earlier file that had this inode: both the
    /// stored and the current btime are known (non-zero) and differ.
    fn is_stale(conn: &Connection, id: &Ident) -> rusqlite::Result<bool> {
        if (id.btime_sec, id.btime_nsec) == (0, 0) {
            return Ok(false);
        }
        let stored: Option<(i64, i64)> = conn
            .prepare_cached(&format!(
                "SELECT btime_sec, btime_nsec FROM metadata WHERE {ID_WHERE} \
                 AND (btime_sec != 0 OR btime_nsec != 0) LIMIT 1"
            ))?
            .query_row(Self::id_params(id), |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        Ok(stored.is_some_and(|s| s != (id.btime_sec, i64::from(id.btime_nsec))))
    }

    fn id_params(id: &Ident) -> (&str, i64, i64, i64) {
        (
            id.fs_uuid.as_str(),
            sql_u64(id.subvol_id),
            sql_u64(id.inode_num),
            sql_u64(id.generation),
        )
    }

    fn forget(tx: &Connection, id: &Ident) -> rusqlite::Result<()> {
        tx.prepare_cached(&format!("DELETE FROM metadata WHERE {ID_WHERE}"))?
            .execute(Self::id_params(id))?;
        tx.prepare_cached(&format!("DELETE FROM path_hint WHERE {ID_WHERE}"))?
            .execute(Self::id_params(id))?;
        Ok(())
    }

    /// Drop the rows of a recycled inode: `id` must carry the btime the daemon itself
    /// just observed (identify), never one a client sent. Returns true if it did.
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn purge_stale(&mut self, id: &Ident) -> std::result::Result<bool, MdError> {
        if !self.read(|c| Self::is_stale(c, id))? {
            return Ok(false);
        }
        self.write(|tx| {
            if Self::is_stale(tx, id)? {
                Self::forget(tx, id)?;
            }
            Ok(())
        })?;
        Ok(true)
    }

    /// The encoded value of `key`, `None` if unset.
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn get(&mut self, id: &Ident, key: &str) -> std::result::Result<Option<Vec<u8>>, MdError> {
        // A btime that differs from the stored one: either the rows or the client's
        // identity are stale, and only identify can tell (it sees the file). Never delete
        // on a client's word: the rows are just not this file's.
        if self.read(|c| Self::is_stale(c, id))? {
            return Ok(None);
        }
        self.read(|c| {
            let (u, s, i, g) = Self::id_params(id);
            c.prepare_cached(&format!(
                "SELECT value FROM metadata WHERE {ID_WHERE} AND key = ?5"
            ))?
            .query_row(params![u, s, i, g, key], |r| r.get::<_, Option<Vec<u8>>>(0))
            .optional()
            .map(Option::flatten)
        })
    }

    /// Set `key` to an already validated, encoded value; remember `hint` as the file's
    /// last known path.
    ///
    /// # Errors
    /// [`MdError::TooManyKeys`], [`MdError::NoSuchFile`] (the stored rows carry another
    /// btime: re-identify), [`MdError::Busy`] or [`MdError::Db`].
    pub fn set(
        &mut self,
        id: &Ident,
        key: &str,
        value: &[u8],
        hint: Option<&[u8]>,
    ) -> std::result::Result<(), MdError> {
        self.set_linked(id, key, value, hint.map(|p| (p, 1)))
    }

    /// [`Store::set`], recording the file's hard link count with the path hint: a file
    /// with several links keeps its metadata when one of them is deleted.
    ///
    /// # Errors
    /// As [`Store::set`].
    pub fn set_linked(
        &mut self,
        id: &Ident,
        key: &str,
        value: &[u8],
        hint: Option<(&[u8], u32)>,
    ) -> std::result::Result<(), MdError> {
        let now = unix_now();
        self.write(|tx| {
            if Self::is_stale(tx, id)? {
                return Err(TxErr::Md(MdError::NoSuchFile));
            }
            let (u, s, i, g) = Self::id_params(id);
            let exists = tx
                .prepare_cached(&format!(
                    "SELECT 1 FROM metadata WHERE {ID_WHERE} AND key = ?5"
                ))?
                .exists(params![u, s, i, g, key])?;
            if !exists {
                let n: i64 = tx
                    .prepare_cached(&format!("SELECT count(*) FROM metadata WHERE {ID_WHERE}"))?
                    .query_row(Self::id_params(id), |r| r.get(0))?;
                if usize::try_from(n).unwrap_or(usize::MAX) >= MAX_KEYS_PER_FILE {
                    return Err(TxErr::Md(MdError::TooManyKeys));
                }
            }
            let bs = id.btime_sec;
            let bn = i64::from(id.btime_nsec);
            tx.prepare_cached(
                "INSERT INTO metadata \
                 (fs_uuid, subvol_id, inode_num, generation, key, btime_sec, btime_nsec, value) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                 ON CONFLICT (fs_uuid, subvol_id, inode_num, generation, key) \
                 DO UPDATE SET value = excluded.value, btime_sec = excluded.btime_sec, \
                 btime_nsec = excluded.btime_nsec",
            )?
            .execute(params![u, s, i, g, key, bs, bn, value])?;
            if (bs, bn) != (0, 0) {
                // Older rows recorded before btime was known: adopt the current one.
                tx.prepare_cached(&format!(
                    "UPDATE metadata SET btime_sec = ?5, btime_nsec = ?6 WHERE {ID_WHERE} \
                     AND btime_sec = 0 AND btime_nsec = 0"
                ))?
                .execute(params![u, s, i, g, bs, bn])?;
            }
            if let Some((p, links)) = hint {
                tx.prepare_cached(
                    "INSERT INTO path_hint \
                     (fs_uuid, subvol_id, inode_num, generation, path, updated, links) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                     ON CONFLICT (fs_uuid, subvol_id, inode_num, generation) \
                     DO UPDATE SET path = excluded.path, updated = excluded.updated, \
                     links = excluded.links",
                )?
                .execute(params![u, s, i, g, p, now, links])?;
            }
            Ok(())
        })
    }

    /// Remove `key` (a no-op if it is not set). The path hint goes with the last key.
    ///
    /// # Errors
    /// [`MdError::NoSuchFile`] (another btime is stored: re-identify), [`MdError::Busy`]
    /// or [`MdError::Db`].
    pub fn unset(&mut self, id: &Ident, key: &str) -> std::result::Result<(), MdError> {
        self.write(|tx| {
            if Self::is_stale(tx, id)? {
                return Err(TxErr::Md(MdError::NoSuchFile));
            }
            let (u, s, i, g) = Self::id_params(id);
            tx.prepare_cached(&format!(
                "DELETE FROM metadata WHERE {ID_WHERE} AND key = ?5"
            ))?
            .execute(params![u, s, i, g, key])?;
            let left = tx
                .prepare_cached(&format!("SELECT 1 FROM metadata WHERE {ID_WHERE} LIMIT 1"))?
                .exists(Self::id_params(id))?;
            if !left {
                tx.prepare_cached(&format!("DELETE FROM path_hint WHERE {ID_WHERE}"))?
                    .execute(Self::id_params(id))?;
            }
            Ok(())
        })
    }

    /// Up to `limit` keys strictly after `after` (byte order), and whether more follow.
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn list(
        &mut self,
        id: &Ident,
        after: &str,
        limit: usize,
    ) -> std::result::Result<(Vec<String>, bool), MdError> {
        if self.read(|c| Self::is_stale(c, id))? {
            return Ok((Vec::new(), false));
        }
        let lim = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let mut keys = self.read(|c| {
            let (u, s, i, g) = Self::id_params(id);
            let mut st = c.prepare_cached(&format!(
                "SELECT key FROM metadata WHERE {ID_WHERE} AND key > ?5 ORDER BY key LIMIT ?6"
            ))?;
            st.query_map(params![u, s, i, g, after, lim], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()
        })?;
        let more = keys.len() > limit;
        keys.truncate(limit);
        Ok((keys, more))
    }

    /// The identities whose last known path is `path`.
    /// Identities last seen at `path`, with their hard link count then.
    fn hinted_at(tx: &Connection, path: &[u8]) -> rusqlite::Result<Vec<(Ident, i64)>> {
        let mut st = tx.prepare_cached(
            "SELECT fs_uuid, subvol_id, inode_num, generation, links FROM path_hint \
             WHERE path = ?1",
        )?;
        st.query_map(params![path], |r| {
            Ok((
                Ident {
                    fs_uuid: r.get(0)?,
                    subvol_id: r.get::<_, i64>(1)? as u64,
                    inode_num: r.get::<_, i64>(2)? as u64,
                    generation: r.get::<_, i64>(3)? as u64,
                    btime_sec: 0,
                    btime_nsec: 0,
                },
                r.get(4)?,
            ))
        })?
        .collect()
    }

    /// `id`'s name at its hinted path is gone (deleted, or replaced by a rename). With
    /// one link the file is gone: drop its metadata. With several, the file lives on
    /// under another name the daemon does not know: keep the metadata (keyed by
    /// identity, it is found again from any link), drop only the outdated hint.
    /// Returns whether the metadata was dropped.
    fn unlinked(tx: &Connection, id: &Ident, links: i64) -> rusqlite::Result<bool> {
        if links > 1 {
            tx.prepare_cached(&format!("DELETE FROM path_hint WHERE {ID_WHERE}"))?
                .execute(Self::id_params(id))?;
            return Ok(false);
        }
        Self::forget(tx, id)?;
        Ok(true)
    }

    /// The file at `path` was deleted: drop the metadata of every identity last seen
    /// there, except `alive` (what is at `path` now, if anything: a file created again
    /// at the same path, or the same file still linked there). Returns how many
    /// identities were dropped.
    ///
    /// Only files whose metadata was set through `path` (their path hint) can be found:
    /// the file is gone, so its identity cannot be read any more. A file renamed behind
    /// GIO's back keeps its old hint until its next set; a later delete of whatever then
    /// sits at the old path drops it too (see AGENTS.md).
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn removed(
        &mut self,
        path: &[u8],
        alive: Option<&Ident>,
    ) -> std::result::Result<u32, MdError> {
        // Every GIO delete reports here; most files never had metadata. Look before
        // taking the write lock.
        if self.read(|c| Self::hinted_at(c, path))?.is_empty() {
            return Ok(0);
        }
        self.write(|tx| {
            let mut n = 0u32;
            for (id, links) in Self::hinted_at(tx, path)? {
                if alive.is_some_and(|a| same_key(a, &id)) {
                    continue;
                }
                n += u32::from(Self::unlinked(tx, &id, links)?);
            }
            Ok(n)
        })
    }

    /// The file `id` was renamed from `src` to `dest`. Its rows stay (they are keyed by
    /// identity); its path hint becomes `dest`, the hints of all files below `src/` are
    /// rewritten to below `dest/` in the same transaction, and files last seen at `dest`
    /// (replaced by the rename) are dropped, unless they had other hard links (only their
    /// hint goes). Returns
    /// `(hints rewritten, identities dropped)`.
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn moved(
        &mut self,
        src: &[u8],
        dest: &[u8],
        id: &Ident,
    ) -> std::result::Result<(u32, u32), MdError> {
        let now = unix_now();
        let lo = [src, b"/"].concat();
        let hi = [src, b"0"].concat();
        // Most renamed files have no metadata, nothing hinted at `dest` and nothing below:
        // look before taking the write lock.
        let anything = self.read(|c| {
            Ok(!Self::hinted_at(c, dest)?.is_empty()
                || c.prepare_cached(&format!("SELECT 1 FROM metadata WHERE {ID_WHERE} LIMIT 1"))?
                    .exists(Self::id_params(id))?
                || c.prepare_cached(
                    "SELECT 1 FROM path_hint WHERE path >= ?1 AND path < ?2 LIMIT 1",
                )?
                .exists(params![lo, hi])?)
        })?;
        if !anything {
            return Ok((0, 0));
        }
        self.write(|tx| {
            let mut forgotten = 0u32;
            for (other, links) in Self::hinted_at(tx, dest)? {
                if !same_key(&other, id) {
                    forgotten += u32::from(Self::unlinked(tx, &other, links)?);
                }
            }
            if Self::is_stale(tx, id)? {
                Self::forget(tx, id)?;
            }
            let mut rewritten = 0u32;
            let has_rows = tx
                .prepare_cached(&format!("SELECT 1 FROM metadata WHERE {ID_WHERE} LIMIT 1"))?
                .exists(Self::id_params(id))?;
            if has_rows {
                let (u, s, i, g) = Self::id_params(id);
                tx.prepare_cached(
                    "INSERT INTO path_hint (fs_uuid, subvol_id, inode_num, generation, path, updated) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                     ON CONFLICT (fs_uuid, subvol_id, inode_num, generation) \
                     DO UPDATE SET path = excluded.path, updated = excluded.updated",
                )?
                .execute(params![u, s, i, g, dest, now])?;
                rewritten += 1;
            }
            // Below a renamed directory: paths in [src/, src0) ('0' follows '/'), byte
            // order, all of them in this transaction (one indexed range update, however
            // many: a hint left at the old path would let a later delete there drop the
            // moved file's metadata). CAST keeps the result a BLOB: `||` yields TEXT,
            // which sorts after every BLOB and would fall out of these byte ranges.
            let n = tx
                .prepare_cached(
                    "UPDATE path_hint SET path = CAST(?3 || substr(path, ?4) AS BLOB), \
                     updated = ?5 WHERE path >= ?1 AND path < ?2",
                )?
                .execute(params![lo, hi, dest, src.len() + 1, now])?;
            rewritten = rewritten.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
            Ok((rewritten, forgotten))
        })
    }

    /// `to` is a new copy of the file `from` (milestone 8 file ops), now at `hint`: its
    /// metadata rows are duplicated to `to` (whatever `to` had before is dropped: a new
    /// file, or a recycled inode) and `to`'s path hint becomes `hint` (one link). Files
    /// last seen at `hint` were replaced by the copy and lose their name there (the
    /// [`Self::removed`] rule: dropped, unless they had other hard links). With
    /// `forget_from` (a move across filesystems: `from`'s name was unlinked) `from` follows
    /// the same rule. Returns how many keys were copied.
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn copy_meta(
        &mut self,
        from: &Ident,
        to: &Ident,
        hint: &[u8],
        forget_from: bool,
    ) -> std::result::Result<u32, MdError> {
        if same_key(from, to) {
            return Ok(0);
        }
        let now = unix_now();
        self.write(|tx| {
            if Self::is_stale(tx, from)? {
                Self::forget(tx, from)?;
            }
            Self::forget(tx, to)?;
            for (other, links) in Self::hinted_at(tx, hint)? {
                if !same_key(&other, from) {
                    Self::unlinked(tx, &other, links)?;
                }
            }
            let rows: Vec<(String, Option<Vec<u8>>)> = {
                let mut st = tx.prepare_cached(&format!(
                    "SELECT key, value FROM metadata WHERE {ID_WHERE} ORDER BY key LIMIT ?5"
                ))?;
                let (u, s, i, g) = Self::id_params(from);
                st.query_map(params![u, s, i, g, MAX_KEYS_PER_FILE as i64], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            let (u, s, i, g) = Self::id_params(to);
            let (bs, bn) = (to.btime_sec, i64::from(to.btime_nsec));
            for (k, v) in &rows {
                tx.prepare_cached(
                    "INSERT INTO metadata \
                     (fs_uuid, subvol_id, inode_num, generation, key, btime_sec, btime_nsec, value) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )?
                .execute(params![u, s, i, g, k, bs, bn, v])?;
            }
            if !rows.is_empty() {
                tx.prepare_cached(
                    "INSERT INTO path_hint \
                     (fs_uuid, subvol_id, inode_num, generation, path, updated, links) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1) \
                     ON CONFLICT (fs_uuid, subvol_id, inode_num, generation) \
                     DO UPDATE SET path = excluded.path, updated = excluded.updated, links = 1",
                )?
                .execute(params![u, s, i, g, hint, now])?;
            }
            if forget_from {
                let links: Option<i64> = tx
                    .prepare_cached(&format!("SELECT links FROM path_hint WHERE {ID_WHERE}"))?
                    .query_row(Self::id_params(from), |r| r.get(0))
                    .optional()?;
                Self::unlinked(tx, from, links.unwrap_or(1))?;
            }
            Ok(u32::try_from(rows.len()).unwrap_or(u32::MAX))
        })
    }

    /// Identities last seen at `path` or anywhere below `path/` (byte ranges: '0'
    /// follows '/'), with their hard link count then. All of them: no cap (a capped
    /// list would leave rows whose files are gone).
    fn hinted_in_tree(tx: &Connection, path: &[u8]) -> rusqlite::Result<Vec<(Ident, i64)>> {
        let lo = [path, b"/"].concat();
        let hi = [path, b"0"].concat();
        let mut st = tx.prepare_cached(
            "SELECT fs_uuid, subvol_id, inode_num, generation, links FROM path_hint \
             WHERE path = ?1 OR (path >= ?2 AND path < ?3)",
        )?;
        st.query_map(params![path, lo, hi], |r| {
            Ok((
                Ident {
                    fs_uuid: r.get(0)?,
                    subvol_id: r.get::<_, i64>(1)? as u64,
                    inode_num: r.get::<_, i64>(2)? as u64,
                    generation: r.get::<_, i64>(3)? as u64,
                    btime_sec: 0,
                    btime_nsec: 0,
                },
                r.get(4)?,
            ))
        })?
        .collect()
    }

    /// `path` was deleted with everything below it (milestone 8 recursive delete): every
    /// identity last seen at `path` or below `path/` lost that name (the
    /// [`Self::removed`] rule: dropped, unless it had other hard links). One
    /// transaction, however many. Returns how many identities were dropped.
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn removed_tree(&mut self, path: &[u8]) -> std::result::Result<u32, MdError> {
        self.removed_paths(&[(path.to_vec(), true)])
    }

    /// Paths a recursive delete removed (milestone 8): `(path, true)` a directory with
    /// everything below it, `(path, false)` one entry; each identity last seen there
    /// follows the [`Self::removed`] rule. In one transaction. Returns how many
    /// identities were dropped.
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn removed_paths(
        &mut self,
        paths: &[(Vec<u8>, bool)],
    ) -> std::result::Result<u32, MdError> {
        if paths.is_empty() {
            return Ok(0);
        }
        // If the path_hint table is empty, no paths can match.
        let has_hints = self.read(|c| {
            let mut st = c.prepare_cached("SELECT 1 FROM path_hint LIMIT 1")?;
            st.exists([])
        })?;
        if !has_hints {
            return Ok(0);
        }
        self.write(|tx| {
            let mut n = 0u32;
            for (path, tree) in paths {
                let found = if *tree {
                    Self::hinted_in_tree(tx, path)?
                } else {
                    Self::hinted_at(tx, path)?
                };
                for (id, links) in found {
                    n += u32::from(Self::unlinked(tx, &id, links)?);
                }
            }
            Ok(n)
        })
    }

    /// The last path a value was set through (diagnostics, later moves and GC).
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn path_hint(&self, id: &Ident) -> std::result::Result<Option<Vec<u8>>, MdError> {
        self.read(|c| {
            c.prepare_cached(&format!("SELECT path FROM path_hint WHERE {ID_WHERE}"))?
                .query_row(Self::id_params(id), |r| r.get(0))
                .optional()
        })
    }
}

// ---------------------------------------------------------------------------------------
// The database thread

/// A request for the database thread (already parsed and validated on the ring thread).
#[derive(Debug, Clone)]
pub enum DbReq {
    Get(Ident, String),
    /// Encoded value, optional path hint.
    /// The value, and the path hint with the file's hard link count.
    Set(Ident, String, Vec<u8>, Option<(Vec<u8>, u32)>),
    Unset(Ident, String),
    /// Cursor (keys strictly after it).
    List(Ident, String),
    /// Drop stale rows for an identity the daemon just resolved (identify). Runs even
    /// when older than `max_age`: requests queued behind it rely on it.
    Purge(Ident),
    /// Deleted path, and the identity found at it now (if any) on the ring thread.
    Removed(Vec<u8>, Option<Ident>),
    /// Source path, destination path, identity of the renamed file.
    Moved(Vec<u8>, Vec<u8>, Ident),
    /// Milestone 8: source identity, copy's identity, copy's path, drop the source's rows.
    Copied(Ident, Ident, Vec<u8>, bool),
    /// Milestone 8: a directory tree deleted at this path.
    RemovedTree(Vec<u8>),
    /// Milestone 8: what a failed recursive delete removed (`true`: with its subtree).
    RemovedPaths(Vec<(Vec<u8>, bool)>),
    /// Milestone 11: flush and truncate the SQLite WAL log.
    Checkpoint,
}

impl DbReq {
    /// A record of something that already happened on disk (a file op's or GIO's move,
    /// copy or delete), not a question a client is waiting on. Skipping one would leave
    /// the store disagreeing with the files: a copy without its metadata, rows of a
    /// deleted file, a stale hint (T-010, PR-F008). So it is never aged out: the queue
    /// is FIFO, so a late one still runs in order.
    #[must_use]
    pub fn is_follow_up(&self) -> bool {
        matches!(
            self,
            Self::Removed(..)
                | Self::Moved(..)
                | Self::Copied(..)
                | Self::RemovedTree(_)
                | Self::RemovedPaths(_)
        )
    }
}

/// Reply body on success (see `md` for the layouts), or the failure status.
pub type DbResult = std::result::Result<Vec<u8>, MdError>;

pub struct Job {
    pub req: DbReq,
    pub enqueued: Instant,
    /// Called exactly once on the database thread (or on drop of the queue, never).
    pub done: Box<dyn FnOnce(DbResult) + Send>,
}

#[derive(Debug, Clone, Copy)]
pub struct DbConfig {
    /// Jobs that may wait; beyond this, [`DbHandle::submit`] answers Busy.
    pub queue: usize,
    /// A job older than this when the thread gets to it is answered Busy, not run.
    pub max_age: Duration,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            queue: 128,
            max_age: Duration::from_millis(500),
        }
    }
}

/// Sending side of the database thread's queue. Cheap to clone.
#[derive(Clone)]
pub struct DbHandle {
    tx: SyncSender<Job>,
}

impl DbHandle {
    /// Queue a job without ever waiting. A refused job is dropped without calling
    /// `done`: the caller answers [`MdError::Busy`] itself.
    ///
    /// # Errors
    /// [`MdError::Busy`] if the queue is full or the thread is gone.
    pub fn submit(&self, job: Job) -> std::result::Result<(), MdError> {
        match self.tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => Err(MdError::Busy),
        }
    }

    /// [`submit`](Self::submit), but waiting up to `wait` for room while the queue is
    /// full. Only for threads that may wait (file-op workers), never a ring thread.
    ///
    /// # Errors
    /// [`MdError::Busy`] if the queue stays full for `wait`, or the thread is gone.
    pub fn submit_wait(&self, job: Job, wait: Duration) -> std::result::Result<(), MdError> {
        let deadline = Instant::now() + wait;
        let mut job = job;
        loop {
            match self.tx.try_send(job) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Disconnected(_)) => return Err(MdError::Busy),
                Err(TrySendError::Full(j)) => {
                    if Instant::now() >= deadline {
                        return Err(MdError::Busy);
                    }
                    job = j;
                    thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    /// Synchronously flush all queued writes and checkpoint the WAL.
    ///
    /// # Errors
    /// [`MdError::Busy`] or [`MdError::Db`].
    pub fn flush_and_checkpoint(&self) -> std::result::Result<(), MdError> {
        let (tx, rx) = mpsc::channel();
        let job = Job {
            req: DbReq::Checkpoint,
            enqueued: Instant::now(),
            done: Box::new(move |res| {
                let _ = tx.send(res);
            }),
        };
        self.tx.send(job).map_err(|_| MdError::Busy)?;
        rx.recv().map_err(|_| MdError::Busy)?.map(|_| ())
    }
}

/// Run one job against the store.
pub fn execute(store: &mut Store, req: &DbReq) -> DbResult {
    match req {
        DbReq::Get(id, k) => {
            let v = store.get(id, k)?.ok_or(MdError::NotFound)?;
            // The file is only ours by convention: a row written by something else must
            // never reach the client (or overflow a reply slot) unvalidated.
            Value::decode(&v).map_err(|_| MdError::Db)?;
            Ok(v)
        }
        DbReq::Set(id, k, v, hint) => store
            .set_linked(id, k, v, hint.as_ref().map(|(p, n)| (p.as_slice(), *n)))
            .map(|()| Vec::new()),
        DbReq::Unset(id, k) => store.unset(id, k).map(|()| Vec::new()),
        DbReq::Purge(id) => store.purge_stale(id).map(|_| Vec::new()),
        DbReq::List(id, after) => {
            let (mut keys, more) = store.list(id, after, MAX_KEYS_PER_FILE)?;
            // Same for keys: one that the protocol could not carry is skipped.
            keys.retain(|k| check_key(k.as_bytes()).is_ok());
            Ok(list_body(&keys, more))
        }
        DbReq::Removed(path, alive) => store
            .removed(path, alive.as_ref())
            .map(|n| n.to_le_bytes().to_vec()),
        DbReq::Moved(src, dest, id) => store.moved(src, dest, id).map(|(r, f)| {
            let mut b = r.to_le_bytes().to_vec();
            b.extend_from_slice(&f.to_le_bytes());
            b
        }),
        DbReq::Copied(from, to, hint, forget) => store
            .copy_meta(from, to, hint, *forget)
            .map(|n| n.to_le_bytes().to_vec()),
        DbReq::RemovedTree(path) => store.removed_tree(path).map(|n| n.to_le_bytes().to_vec()),
        DbReq::RemovedPaths(paths) => store.removed_paths(paths).map(|n| n.to_le_bytes().to_vec()),
        DbReq::Checkpoint => store.checkpoint().map(|()| Vec::new()),
    }
}

fn db_thread(mut store: Store, rx: &Receiver<Job>, max_age: Duration) {
    while let Ok(job) = rx.recv() {
        let r = if job.enqueued.elapsed() > max_age
            && !matches!(job.req, DbReq::Purge(_) | DbReq::Checkpoint)
            && !job.req.is_follow_up()
        {
            Err(MdError::Busy)
        } else {
            execute(&mut store, &job.req)
        };
        (job.done)(r);
    }
    let _ = store.checkpoint();
}

/// Start the database thread; it owns `store` and exits when every handle is dropped.
///
/// # Errors
/// [`Error::Io`] if the thread cannot be started.
pub fn spawn(store: Store, cfg: DbConfig) -> Result<DbHandle> {
    let (tx, rx) = mpsc::sync_channel(cfg.queue.max(1));
    thread::Builder::new()
        .name("gungnir-db".into())
        .spawn(move || db_thread(store, &rx, cfg.max_age))
        .map_err(Error::Io)?;
    Ok(DbHandle { tx })
}

#[cfg(test)]
mod tests;
