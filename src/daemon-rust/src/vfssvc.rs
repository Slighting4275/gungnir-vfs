//! `trash://` and `recent://` on the ring (milestone 9). Requests that touch a disk run on
//! a request thread, never on the connection's ring thread, and at most [`MAX_WAITERS`]
//! exist at once: the next request is answered `busy` at once, so one empty stuck on a
//! hung volume can never queue work without bound. Deletions and restores go through the
//! M8 engine: its walker never follows a symlink or crosses a mount, and its gate refuses
//! hung and gone mounts.
//!
//! Kinds, still protocol v2 (older daemons answer 13 `unsupported`):
//! - list (40): `scheme u8 | cursor u32`; reply `next u32 (0: the end) | count u16 |
//!   entries`, each `name len16 | orig len16 | target len16 | deleted len16 | kind u8 |
//!   size u64 | mtime i64`. Cursor 0 takes a new snapshot; later cursors read it.
//! - delete (41): `scheme u8 | name len16`.
//! - restore (42): `name len16 | dest len16` (an empty dest: the original path).
//! - empty (43): reply `deleted u32 | failed u32 | skipped len16`, whatever the status.
//! - stat (45): `scheme u8 | name len16`; reply a list page of one. `<item>/<path>` names
//!   an entry inside a trashed folder.
//! - children (46): `cursor u32 | name len16`; reply a list page.
//! - stamp (47): `scheme u8`; reply `stamp u64`.
//!
//! Statuses beyond the metadata ones: 15 OS error (body `errno i32`), 17 a mount inside
//! the item, 18 items remain. Empty reports the first item error, else 18 if items
//! remain, else 4 (suspect mount) naming the skipped volumes.

use std::{
    ffi::OsStr,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    btrfs,
    fsid::{self, MountEntry},
    ipc::{Handler, Msg, PAYLOAD_MAX, Port, Session},
    ops::{
        Anchor, Done, OpError, OpKind, OpRequest, Ops, Progress, ST_CANCELLED, ST_OS_ERROR, Sink,
    },
    proto::{
        MSG_REPLY, ST_BAD_REQUEST, ST_BUSY, ST_IO_ERROR, ST_NOT_FOUND, ST_OK, ST_SUSPECT_MOUNT,
        ST_TIMEOUT, reply_payload,
    },
    recent,
    trash::{self, Item, Pins, TrashDir},
};

pub use crate::proto::{
    MSG_TRASH_EMPTY, MSG_VFS_BEAT, MSG_VFS_CHILDREN, MSG_VFS_DELETE, MSG_VFS_LIST, MSG_VFS_RESTORE,
    MSG_VFS_STAMP, MSG_VFS_STAT, SCHEME_RECENT, SCHEME_TRASH, ST_MOUNT_INSIDE, ST_NOT_EMPTY,
};

/// Request threads that may exist at once; the next request gets `busy`.
pub const MAX_WAITERS: usize = 4;
/// Longest one item's op is waited for. Past the engine's own limits, which end it first:
/// no progress for 30 s, or an hour in all. A big restore across devices needs that hour.
const OP_DEADLINE: Duration = Duration::from_secs(3610);
const CANCEL_WAIT: Duration = Duration::from_secs(2);
/// A job this old is stuck, or a very long op that can spare its place in the queue.
const SLOT_LEASE: Duration = Duration::from_secs(63);
/// Threads the service will leave blocked before it refuses everything.
const STUCK_MAX: usize = 32;
const SUBVOLS_TTL: Duration = Duration::from_secs(5);
/// How long a request waits for a subvolume search before answering without it.
const SUBVOLS_WAIT: Duration = Duration::from_secs(2);
const BEAT: Duration = Duration::from_secs(5);
const GONE_CHECK: Duration = Duration::from_millis(250);
/// Items one snapshot keeps; a bigger list is cut, never an unbounded allocation.
const SNAPSHOT_MAX: usize = 1 << 17;
/// Test hook (`test-hooks` builds only): this directory is one more volume.
pub const TEST_TOP_ENV: &str = "GUNGNIR_TEST_TRASH_TOP";

/// Why an item could not be handled, as a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub status: u32,
    pub errno: i32,
}

impl Failure {
    fn st(status: u32) -> Self {
        Self { status, errno: 0 }
    }

    fn os(errno: i32) -> Self {
        // A mount inside the item: retryable once it is unmounted, unlike a plain error.
        if errno == libc::EXDEV || errno == libc::EBUSY {
            return Self::st(ST_MOUNT_INSIDE);
        }
        Self {
            status: ST_OS_ERROR,
            errno,
        }
    }

    fn body(self) -> Vec<u8> {
        if self.status == ST_OS_ERROR {
            self.errno.to_le_bytes().to_vec()
        } else {
            Vec::new()
        }
    }
}

impl From<OpError> for Failure {
    fn from(e: OpError) -> Self {
        match e {
            OpError::Os(errno) => Self::os(errno),
            other => {
                let (status, errno) = other.status();
                Self { status, errno }
            }
        }
    }
}

fn io_failure(e: &std::io::Error) -> Failure {
    Failure::os(e.raw_os_error().unwrap_or(libc::EIO))
}

/// Hears one op's end.
#[derive(Default)]
struct Wait {
    done: Mutex<Option<Result<(), OpError>>>,
    cv: Condvar,
}

impl Sink for Wait {
    fn progress(&self, _: u64, _: &Progress) {}

    fn done(&self, d: &Done) {
        *self.done.lock().unwrap_or_else(PoisonError::into_inner) = Some(d.result);
        self.cv.notify_all();
    }
}

/// The request a job runs for.
pub struct Ctx {
    port: Arc<Port>,
    seq: u64,
    last_beat: Mutex<Instant>,
    /// The connection went: nobody wants the answer, so an op in progress stops.
    gone: Arc<AtomicBool>,
}

impl Ctx {
    fn last_beat_due(&self) -> bool {
        let mut t = self
            .last_beat
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let due = t.elapsed() >= BEAT;
        if due {
            *t = Instant::now();
        }
        due
    }
}

/// What the trash directories are right now.
struct Dirs {
    dirs: Vec<TrashDir>,
    skipped: Vec<PathBuf>,
    /// Every subvolume was seen.
    complete: bool,
}

/// The subvolume search, shared with its thread: the lock is never held across it.
#[derive(Default)]
struct Subvols {
    /// The last search: when it ended, what it found, whether that was everything.
    done: Option<(Instant, Vec<PathBuf>, bool)>,
    /// When the search under way began.
    started: Option<Instant>,
}

impl Wait {
    fn until(&self, end: Instant) -> Option<Result<(), OpError>> {
        let mut g = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(r) = *g {
                return Some(r);
            }
            let left = end.checked_duration_since(Instant::now())?;
            g = self
                .cv
                .wait_timeout(g, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// Everything the service takes from its surroundings, read once.
pub struct SvcConfig {
    /// `$XDG_DATA_HOME`, where the home trash and the recent list live.
    pub xdg_data: Option<std::ffi::OsString>,
    /// `$HOME`, whose subvolumes hold trash as well.
    pub home: Option<std::ffi::OsString>,
    /// Whose trash directories these are.
    pub uid: u32,
    /// Volumes beyond the mount table.
    pub extra_tops: Vec<PathBuf>,
    /// Search the host's btrfs mounts for subvolumes.
    pub host_subvols: bool,
    pub mounts: Box<dyn MountTable>,
}

impl SvcConfig {
    /// The daemon's: the environment, its euid, procfs. In `test-hooks` builds
    /// [`TEST_TOP_ENV`] adds a volume, and the host's btrfs mounts are left alone so a
    /// test daemon keeps to its own volumes.
    #[must_use]
    pub fn from_env() -> Self {
        #[cfg(feature = "test-hooks")]
        let extra_tops = std::env::var_os(TEST_TOP_ENV)
            .map(PathBuf::from)
            .into_iter()
            .collect();
        #[cfg(not(feature = "test-hooks"))]
        let extra_tops = Vec::new();
        Self {
            xdg_data: std::env::var_os("XDG_DATA_HOME"),
            home: std::env::var_os("HOME"),
            // SAFETY: plain getter.
            uid: unsafe { libc::geteuid() },
            extra_tops,
            host_subvols: cfg!(not(feature = "test-hooks")),
            mounts: Box::new(ProcMounts),
        }
    }
}

/// What the service works on.
pub struct Svc {
    ops: Arc<Ops>,
    home: Option<TrashDir>,
    xbel: Option<PathBuf>,
    uid: u32,
    /// `$HOME`, whose subvolumes hold trash as well.
    home_root: Option<PathBuf>,
    subvols: Arc<(Mutex<Subvols>, Condvar)>,
    /// Search the host's btrfs mounts; test daemons keep to their own volume.
    host_subvols: bool,
    /// Volumes beyond the mount table (the test hook).
    extra_tops: Vec<PathBuf>,
    mounts: Box<dyn MountTable>,
    in_flight: AtomicUsize,
    /// Every running job: when it started, and whether it has ended.
    jobs: Mutex<Vec<(Instant, Arc<AtomicBool>)>>,
    draining: AtomicBool,
}

/// Filesystems that never hold a volume trash.
const NO_TRASH_TYPES: [&str; 13] = [
    "proc",
    "sysfs",
    "devpts",
    "cgroup",
    "cgroup2",
    "devtmpfs",
    "debugfs",
    "tracefs",
    "securityfs",
    "nsfs",
    "bpf",
    "autofs",
    "mqueue",
];

/// Where the service reads the mount table: procfs in the daemon, a fixture in tests.
pub trait MountTable: Send + Sync {
    /// The table as it is now.
    ///
    /// # Errors
    /// It could not be read; a listing then says it may be incomplete.
    fn read(&self) -> std::io::Result<Vec<MountEntry>>;
}

/// `/proc/self/mountinfo`, read as bytes: a mount point is any bytes, not UTF-8.
pub struct ProcMounts;

impl MountTable for ProcMounts {
    fn read(&self) -> std::io::Result<Vec<MountEntry>> {
        Ok(fsid::parse_mountinfo(&fs::read("/proc/self/mountinfo")?))
    }
}

fn is_type(e: &MountEntry, names: &[&str]) -> bool {
    names.iter().any(|n| n.as_bytes() == e.fstype.as_slice())
}

/// Mount points of a mount table that could hold a trash directory.
fn mount_points(table: &[MountEntry]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in table.iter().filter(|e| !is_type(e, &NO_TRASH_TYPES)) {
        let p = e.mount_point_path();
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// The mount `path` is on: the longest of `tops` above it, so a mount below another one
/// counts as itself.
fn mount_of<'a>(tops: &'a [PathBuf], path: &Path) -> Option<&'a PathBuf> {
    tops.iter()
        .filter(|t| path.starts_with(t))
        .max_by_key(|t| t.components().count())
}

/// The mount points of a mount table whose topmost mount is FUSE: a FUSE mount found
/// gone has lost its server for good (a remount is a new mount), so it can hold no trash
/// anyone can reach again.
fn fuse_mounts(table: &[MountEntry]) -> Vec<PathBuf> {
    let mut top: Vec<(PathBuf, bool)> = Vec::new();
    for e in table {
        let fuse = is_type(e, &["fuse", "fuseblk"]) || e.fstype.starts_with(b"fuse.");
        let p = e.mount_point_path();
        // A later line mounted over the same point: it is what the path reaches now.
        top.retain(|(q, _)| *q != p);
        top.push((p, fuse));
    }
    top.into_iter()
        .filter(|(_, f)| *f)
        .map(|(p, _)| p)
        .collect()
}

/// The mount points of a mount table that are btrfs: opening anything else to find out
/// would touch mounts that may hang.
fn btrfs_mounts(table: &[MountEntry]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in table.iter().filter(|e| is_type(e, &["btrfs"])) {
        let p = e.mount_point_path();
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Admission over `jobs`: at most [`MAX_WAITERS`] jobs younger than the lease, and
/// [`STUCK_MAX`] in all. A job past its lease stops counting against the first bound
/// (it keeps running and still answers): a thread blocked for good in a filesystem call
/// on a mount that hung after its check costs one thread, not the whole service.
fn admit(jobs: &mut Vec<(Instant, Arc<AtomicBool>)>, now: Instant) -> Option<Arc<AtomicBool>> {
    jobs.retain(|(_, done)| !done.load(Ordering::SeqCst));
    let young = jobs
        .iter()
        .filter(|(t, _)| now.duration_since(*t) < SLOT_LEASE)
        .count();
    if young >= MAX_WAITERS || jobs.len() >= STUCK_MAX {
        return None;
    }
    let done = Arc::new(AtomicBool::new(false));
    jobs.push((now, Arc::clone(&done)));
    Some(done)
}

impl Svc {
    fn admit(&self, now: Instant) -> Option<Arc<AtomicBool>> {
        admit(
            &mut self.jobs.lock().unwrap_or_else(PoisonError::into_inner),
            now,
        )
    }

    /// A service over `ops`, as `cfg` says.
    #[must_use]
    pub fn new(ops: Arc<Ops>, cfg: SvcConfig) -> Arc<Self> {
        let trash_home = trash::home_dir(cfg.xdg_data.as_deref(), cfg.home.as_deref());
        let xbel = trash_home
            .as_ref()
            .map(|d| d.top.join("recently-used.xbel"));
        Arc::new(Self {
            ops,
            home: trash_home,
            home_root: cfg.home.map(PathBuf::from),
            subvols: Arc::default(),
            host_subvols: cfg.host_subvols,
            xbel,
            uid: cfg.uid,
            extra_tops: cfg.extra_tops,
            mounts: cfg.mounts,
            in_flight: AtomicUsize::new(0),
            jobs: Mutex::new(Vec::new()),
            draining: AtomicBool::new(false),
        })
    }

    fn blocked(&self, p: &Path) -> bool {
        self.ops.blocked(p.as_os_str().as_bytes()).is_some()
    }

    /// Every trash directory reachable now, and the volumes skipped as hung or gone.
    fn dirs(&self) -> Dirs {
        self.dirs_as_of(false)
    }

    /// The subvolumes below `roots`, and whether that is all of them. Every item query
    /// lists, and a machine can have hundreds: remembered briefly, except for an empty,
    /// which has to answer for what is there now. The search runs on its own thread, one
    /// at a time, with no lock held: a mount that hangs under it costs that thread, and
    /// everyone else answers without it, saying the answer is not complete.
    fn subvolumes(&self, roots: Vec<PathBuf>, fresh: bool) -> (Vec<PathBuf>, bool) {
        let (lock, cv) = &*self.subvols;
        let mut g = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if !fresh
            && let Some((at, found, complete)) = &g.done
            && at.elapsed() < SUBVOLS_TTL
        {
            return (found.clone(), *complete);
        }
        if g.started.is_none() {
            let shared = Arc::clone(&self.subvols);
            let ops = Arc::clone(&self.ops);
            let spawned = thread::Builder::new()
                .name("gungnir-subvols".into())
                .spawn(move || {
                    let skip = |p: &Path| ops.blocked(p.as_os_str().as_bytes()).is_some();
                    let (mut found, mut complete) = (Vec::new(), true);
                    for root in roots {
                        // A hung root is named as skipped: that says more than "incomplete".
                        if skip(&root) {
                            continue;
                        }
                        let (more, whole) = btrfs::subvolumes(&root, btrfs::SUBVOLS_MAX, &skip);
                        complete &= whole;
                        found.extend(
                            more.into_iter()
                                .filter(|p| !found.contains(p))
                                .collect::<Vec<_>>(),
                        );
                    }
                    let (lock, cv) = &*shared;
                    let mut g = lock.lock().unwrap_or_else(PoisonError::into_inner);
                    g.done = Some((Instant::now(), found, complete));
                    g.started = None;
                    cv.notify_all();
                });
            if spawned.is_err() {
                let found = g.done.as_ref().map_or_else(Vec::new, |d| d.1.clone());
                return (found, false);
            }
            g.started = Some(Instant::now());
        }
        while let Some(t) = g.started {
            let Some(left) = SUBVOLS_WAIT.checked_sub(t.elapsed()) else {
                let found = g.done.as_ref().map_or_else(Vec::new, |d| d.1.clone());
                return (found, false);
            };
            g = cv
                .wait_timeout(g, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        g.done
            .as_ref()
            .map_or((Vec::new(), false), |d| (d.1.clone(), d.2))
    }

    fn dirs_as_of(&self, fresh: bool) -> Dirs {
        let mut dirs: Vec<TrashDir> = Vec::new();
        let mut skipped = Vec::new();
        if let Some(h) = &self.home {
            if self.blocked(&h.dir) {
                skipped.push(h.dir.clone());
            } else {
                dirs.push(h.clone());
            }
        }
        // A table that cannot be read hides every volume: the listing says it may not be
        // all, never that the volumes have no trash.
        let (table, readable) = match self.mounts.read() {
            Ok(t) => (t, true),
            Err(_) => (Vec::new(), false),
        };
        let mut tops = mount_points(&table);
        tops.extend(self.extra_tops.iter().cloned());
        let mut roots = if self.host_subvols {
            btrfs_mounts(&table)
        } else {
            Vec::new()
        };
        roots.extend(self.extra_tops.iter().cloned());
        // A mounted snapshot is a backup, unless the system or the user lives on it (a
        // rollback runs from one, even with /home mounted apart): only then is its trash
        // a real one.
        let lived_on: Vec<PathBuf> = [
            Some(Path::new("/")),
            self.home_root.as_deref(),
            self.home.as_ref().map(|h| h.dir.as_path()),
        ]
        .into_iter()
        .flatten()
        .filter_map(|p| mount_of(&tops, p).cloned())
        .collect();
        tops.retain(|t| {
            !roots.contains(t) || self.blocked(t) || lived_on.contains(t) || !btrfs::is_snapshot(t)
        });
        roots.retain(|t| tops.contains(t));
        // A subvolume needs no mount of its own, and g_file_trash treats it as a volume.
        // Btrfs lists its own, at any depth. Other filesystems: what shows as another
        // device right below a root, which needs no walking of the disk.
        let (subvols, complete) = self.subvolumes(roots, fresh);
        let mut below = Vec::new();
        for root in tops.iter().chain(&self.home_root) {
            if !self.blocked(root) {
                below.extend(trash::subvolume_tops(root, &|p| self.blocked(p)));
            }
        }
        tops.extend(below);
        tops.extend(subvols);
        let fuse = fuse_mounts(&table);
        for top in tops {
            // A FUSE mount whose server is gone can never be read again (a stale AppImage
            // mount, say): no trash there to miss, so it does not make listings partial.
            // Hung mounts, and network mounts that may come back, still do.
            if fuse.contains(&top) && self.ops.gone(top.as_os_str().as_bytes()) {
                continue;
            }
            if self.blocked(&top) {
                // Only a volume with a trash matters, and asking would touch it: a hung
                // mount from the mount table is named, as it may hold one.
                skipped.push(top);
                continue;
            }
            for d in trash::volume_dirs(&top, self.uid) {
                if !dirs.iter().any(|x| x.dir == d.dir) {
                    dirs.push(d);
                }
            }
        }
        Dirs {
            dirs,
            skipped,
            complete: complete && readable,
        }
    }

    /// Everything in every trash, and whether that may not be all of it.
    fn snapshot_trash(&self) -> (Vec<Item>, bool) {
        let found = self.dirs();
        let mut partial = !found.complete || !found.skipped.is_empty();
        let mut items = Vec::new();
        let mut left = trash::SCAN_BYTES_MAX;
        for d in found.dirs.iter() {
            if !trash::sound(d, self.uid) {
                partial |= trash::unusable(d, self.uid);
                continue;
            }
            match trash::scan_capped(d, &mut left) {
                Ok(i) => {
                    partial |= left == 0 || trash::stuck_orphans(d, &i);
                    items.extend(i);
                }
                // The home trash not existing yet is the normal case.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    partial = true;
                    eprintln!("gungnird: trash {}: {e}", d.dir.display());
                }
            }
            if items.len() >= SNAPSHOT_MAX {
                items.truncate(SNAPSHOT_MAX);
                partial = true;
                break;
            }
        }
        (items, partial)
    }

    /// One recent entry as an item.
    fn recent_item(&self, e: recent::Entry) -> Item {
        {
            let target = recent::file_path(&e.uri).unwrap_or_default();
            let (mut kind, mut size, mut mtime) = (trash::KIND_SPECIAL, 0, 0);
            let tp = Path::new(OsStr::from_bytes(&target));
            // A file on a hung mount is listed without touching it.
            if !target.is_empty()
                && !self.blocked(tp)
                && let Ok(m) = fs::symlink_metadata(tp)
            {
                use std::os::unix::fs::MetadataExt;
                kind = if m.is_dir() {
                    trash::KIND_DIR
                } else {
                    trash::KIND_FILE
                };
                size = m.len();
                mtime = m.mtime();
            }
            Item {
                name: hex(&e.uri).into_bytes(),
                entry: Vec::new(),
                orig: e.uri,
                target,
                kind,
                size,
                mtime,
                deleted: Vec::new(),
                link: Vec::new(),
            }
        }
    }

    fn snapshot_recent(&self) -> Result<Vec<Item>, Failure> {
        let path = self.xbel.as_ref().ok_or(Failure::st(ST_IO_ERROR))?;
        let text = recent::load(path).map_err(|e| io_failure(&e))?;
        Ok(recent::parse(&text)
            .into_iter()
            .take(SNAPSHOT_MAX)
            .map(|e| self.recent_item(e))
            .collect())
    }

    /// The trash directory, item and path inside it of a name, all pinned.
    fn locate<'a>(&self, found: &'a Dirs, name: &'a [u8]) -> Result<Located<'a>, Failure> {
        let (item, rel) = match name.iter().position(|&b| b == b'/') {
            Some(at) => (&name[..at], &name[at + 1..]),
            None => (name, &name[..0]),
        };
        // One spelling per path: an empty part or a `..` would get past the health check
        // below, which sees the path as written, not as it is walked.
        if !rel.is_empty() && !rel.split(|&b| b == b'/').all(trash::valid_entry) {
            return Err(Failure::st(ST_NOT_FOUND));
        }
        let (d, entry) = trash::resolve(&found.dirs, item).ok_or_else(|| self.unresolved(item))?;
        if !trash::sound(d, self.uid) {
            return Err(Failure::os(libc::ENOTDIR));
        }
        // A mount can sit inside a trashed folder: known hung, it is not to be touched.
        let inner = d.files().join(OsStr::from_bytes(&entry));
        if self.blocked(&inner.join(OsStr::from_bytes(rel))) {
            return Err(Failure::st(ST_SUSPECT_MOUNT));
        }
        let pins = d.pins().map_err(|e| missing_or(&e))?;
        trash::stat_payload(&pins.files, &entry).map_err(|e| missing_or(&e))?;
        Ok((d, entry, rel, pins))
    }

    /// One item by name: no scan, whatever the size of the trash.
    fn stat(&self, scheme: u8, name: &[u8]) -> Result<Item, Failure> {
        if scheme == SCHEME_RECENT {
            let uri = unhex(name).ok_or(Failure::st(ST_NOT_FOUND))?;
            let path = self.xbel.as_ref().ok_or(Failure::st(ST_IO_ERROR))?;
            let text = recent::load(path).map_err(|e| io_failure(&e))?;
            let e = recent::parse(&text)
                .into_iter()
                .find(|e| e.uri == uri)
                .ok_or(Failure::st(ST_NOT_FOUND))?;
            return Ok(self.recent_item(e));
        }
        let found = self.dirs();
        let (d, entry, rel, pins) = self.locate(&found, name)?;
        if rel.is_empty() {
            return Ok(trash::item_in(d, &pins, &entry));
        }
        trash::child_item(d, &pins, &entry, rel, name).map_err(|e| missing_or(&e))
    }

    fn children(&self, name: &[u8]) -> Result<(Vec<Item>, bool), Failure> {
        let found = self.dirs();
        let (d, entry, rel, pins) = self.locate(&found, name)?;
        let mut left = trash::SCAN_BYTES_MAX;
        let skip = |t: &[u8]| self.blocked(Path::new(OsStr::from_bytes(t)));
        let items = trash::children_of(d, &pins, &entry, rel, name, &mut left, &skip)
            .map_err(|e| missing_or(&e))?;
        let partial = left == 0;
        Ok((items, partial))
    }

    /// A number that changes when the scheme's list may have.
    fn stamp(&self, scheme: u8) -> u64 {
        use std::os::unix::fs::MetadataExt;
        if scheme == SCHEME_RECENT {
            let m = self.xbel.as_ref().and_then(|p| fs::metadata(p).ok());
            return m.map_or(0, |m| {
                let h = trash::fnv(1, &m.mtime().to_le_bytes());
                let h = trash::fnv(h, &m.mtime_nsec().to_le_bytes());
                trash::fnv(h, &m.len().to_le_bytes())
            });
        }
        self.dirs()
            .dirs
            .iter()
            .filter(|d| trash::sound(d, self.uid))
            .fold(1, |h, d| trash::fnv(h, &trash::stamp(d).to_le_bytes()))
    }

    /// Run one op to its end, within the deadline, telling the client it is alive.
    fn run(&self, req: OpRequest, ctx: &Ctx) -> Result<(), Failure> {
        let w = Arc::new(Wait::default());
        let ctl = self.ops.submit(req, w.clone())?;
        let end = Instant::now() + OP_DEADLINE;
        loop {
            let now = Instant::now();
            // Short enough for a disconnect to stop the op promptly.
            if let Some(r) = w.until(end.min(now + GONE_CHECK)) {
                return r.map_err(Failure::from);
            }
            if ctx.gone.load(Ordering::SeqCst) || Instant::now() >= end {
                break;
            }
            if ctx.last_beat_due() {
                ctx.port.reply(MSG_VFS_BEAT, ctx.seq, &[]);
            }
        }
        self.ops.cancel(&ctl);
        match w.until(Instant::now() + CANCEL_WAIT) {
            Some(r) => r.map_err(Failure::from),
            None => Err(Failure::st(ST_TIMEOUT)),
        }
    }

    /// Delete one item ([`trash::delete`]), its payload through the M8 engine.
    fn delete_item(&self, d: &TrashDir, entry: &[u8], ctx: &Ctx) -> Result<(), Failure> {
        trash::delete(d, self.uid, entry, |s| self.run(op_request(s), ctx)).map_err(item_failure)
    }

    fn delete(&self, scheme: u8, name: &[u8], ctx: &Ctx) -> Result<(), Failure> {
        if scheme == SCHEME_RECENT {
            let uri = unhex(name).ok_or(Failure::st(ST_BAD_REQUEST))?;
            let path = self.xbel.as_ref().ok_or(Failure::st(ST_IO_ERROR))?;
            return recent::forget(path, &uri).map_err(|e| match e {
                recent::ForgetError::Busy => Failure::st(ST_BUSY),
                recent::ForgetError::NotFound => Failure::st(ST_NOT_FOUND),
                recent::ForgetError::Io(e) => io_failure(&e),
            });
        }
        let found = self.dirs();
        let (d, entry) = trash::resolve(&found.dirs, name).ok_or_else(|| self.unresolved(name))?;
        self.delete_item(d, &entry, ctx)
    }

    fn clear_recent(&self) -> Result<(), Failure> {
        let path = self.xbel.as_ref().ok_or(Failure::st(ST_IO_ERROR))?;
        recent::clear(path).map_err(|e| match e {
            recent::ForgetError::Busy => Failure::st(ST_BUSY),
            recent::ForgetError::NotFound => Failure::st(ST_NOT_FOUND),
            recent::ForgetError::Io(e) => io_failure(&e),
        })
    }

    fn restore(&self, name: &[u8], dest: &[u8], ctx: &Ctx) -> Result<(), Failure> {
        let found = self.dirs();
        let (d, entry) = trash::resolve(&found.dirs, name).ok_or_else(|| self.unresolved(name))?;
        trash::restore(d, self.uid, &entry, dest, |s| {
            self.run(op_request(s), ctx).map_err(restore_failure)
        })
        .map_err(item_failure)
    }

    /// Empty what can be reached. Returns the reply status and body.
    fn empty(&self, ctx: &Ctx) -> (u32, Vec<u8>) {
        let Dirs {
            dirs,
            skipped,
            complete,
        } = self.dirs_as_of(true);
        let (mut deleted, mut failed) = (0u32, 0u32);
        let mut first: Option<Failure> = None;
        // More subvolumes than were looked at: one of them may hold a trash.
        let mut truncated = !complete;
        'dirs: for d in &dirs {
            if trash::unusable(d, self.uid) {
                failed += 1;
                first.get_or_insert(Failure::os(libc::ENOTDIR));
                continue;
            }
            if !trash::sound(d, self.uid) {
                continue; // nothing there yet
            }
            let items = match trash::scan(d) {
                Ok(i) => i,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    first.get_or_insert(io_failure(&e));
                    continue;
                }
            };
            for item in items {
                // Nobody is there any more: the op in flight stopped, and so does this.
                if ctx.gone.load(Ordering::SeqCst) {
                    first = Some(Failure::st(ST_CANCELLED));
                    break 'dirs;
                }
                match self.delete_item(d, &item.entry, ctx) {
                    Ok(()) => deleted += 1,
                    Err(f) => {
                        failed += 1;
                        first.get_or_insert(f);
                    }
                }
            }
            let _ = trash::remove_orphans(d);
            // Past the scan's cap, trashed while this ran, or an info that would not go: it
            // stays (the user chose to empty what was there), but "emptied" would be a lie.
            match trash::has_items(d) {
                Ok(left) => truncated |= left,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    first.get_or_insert(io_failure(&e));
                }
            }
        }
        let mut names = Vec::new();
        for p in &skipped {
            if !names.is_empty() {
                names.push(b' ');
            }
            names.extend_from_slice(p.as_os_str().as_bytes());
        }
        names.truncate(PAYLOAD_MAX - 64);
        let mut body = Vec::with_capacity(names.len() + 16);
        body.extend_from_slice(&deleted.to_le_bytes());
        body.extend_from_slice(&failed.to_le_bytes());
        body.extend_from_slice(&(names.len() as u16).to_le_bytes());
        body.extend_from_slice(&names);
        (empty_status(first, truncated, !skipped.is_empty()), body)
    }
}

/// A trash step as the M8 engine's request; the held places are set only by the daemon.
fn op_request(s: trash::Step) -> OpRequest {
    let anchor = |a: trash::At| Anchor {
        dir: Arc::new(a.dir),
        leaf: a.leaf,
    };
    match s {
        trash::Step::DeleteTree { src, src_at } => OpRequest {
            kind: OpKind::DeleteTree,
            flags: 0,
            timeout_ms: 0,
            src,
            dest: Vec::new(),
            src_at: Some(anchor(src_at)),
            dest_at: None,
        },
        trash::Step::Move {
            src,
            src_at,
            dest,
            dest_at,
        } => OpRequest {
            kind: OpKind::Move,
            flags: 0,
            timeout_ms: 0,
            src,
            dest,
            src_at: Some(anchor(src_at)),
            dest_at: dest_at.map(anchor),
        },
    }
}

fn item_failure(e: trash::ItemError<Failure>) -> Failure {
    match e {
        trash::ItemError::Os(errno) => Failure::os(errno),
        trash::ItemError::NotFound => Failure::st(ST_NOT_FOUND),
        trash::ItemError::BadRequest => Failure::st(ST_BAD_REQUEST),
        trash::ItemError::Step(f) => f,
    }
}

/// Nothing in a restore is a mount in an item to unmount: say what it is.
fn restore_failure(f: Failure) -> Failure {
    if f.status == ST_MOUNT_INSIDE {
        Failure {
            status: ST_OS_ERROR,
            errno: libc::EXDEV,
        }
    } else {
        f
    }
}

/// Stopped by a drain, not by anyone who asked: for the client that is "try again", never
/// the silent cancel a file manager would not report.
fn reply_status(st: u32, draining: bool) -> u32 {
    if st == ST_CANCELLED && draining {
        ST_BUSY
    } else {
        st
    }
}

/// A name resolved: its trash, its entry, the path inside it, and the held directories.
type Located<'a> = (&'a TrashDir, Vec<u8>, &'a [u8], Pins);

/// "It is not there" as a not-found, not as an OS error.
fn missing_or(e: &std::io::Error) -> Failure {
    if e.kind() == std::io::ErrorKind::NotFound {
        Failure::st(ST_NOT_FOUND)
    } else {
        io_failure(e)
    }
}

/// What an empty reports: never success while anything may remain.
fn empty_status(first: Option<Failure>, truncated: bool, skipped: bool) -> u32 {
    match first {
        Some(f) => f.status,
        None if truncated => ST_NOT_EMPTY,
        None if skipped => ST_SUSPECT_MOUNT,
        None => ST_OK,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.chunks(2).map(crate::hex_byte).collect()
}

fn put16(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s);
}

/// Encoded size of an item, if it can ever fit one reply.
fn encoded(i: &Item) -> usize {
    10 + i.name.len() + i.orig.len() + i.target.len() + i.deleted.len() + i.link.len() + 17
}

/// One page of `items` from `cursor`: the reply body. An item too big for a reply is
/// listed with its long strings dropped, never skipped: it can still be deleted by name.
#[must_use]
pub fn page(items: &[Item], cursor: usize, partial: bool) -> Vec<u8> {
    let max = PAYLOAD_MAX - 4;
    let mut body = vec![0u8; 7];
    body[6] = u8::from(partial);
    let (mut at, mut count) = (cursor, 0u16);
    while let Some(i) = items.get(at) {
        let degraded;
        let it = if encoded(i) > max - 7 {
            degraded = Item {
                orig: Vec::new(),
                target: Vec::new(),
                deleted: Vec::new(),
                link: Vec::new(),
                ..i.clone()
            };
            &degraded
        } else {
            i
        };
        if encoded(it) > max - 7 {
            // Not even its name fits: nothing could address it. Say so, and move on.
            eprintln!("gungnird: a trash item's name is too long to list");
            body[6] = 1; // it exists, and no client will ever see it
            at += 1;
            continue;
        }
        if body.len() + encoded(it) > max {
            break;
        }
        put16(&mut body, &it.name);
        put16(&mut body, &it.orig);
        put16(&mut body, &it.target);
        put16(&mut body, &it.deleted);
        put16(&mut body, &it.link);
        body.push(it.kind);
        body.extend_from_slice(&it.size.to_le_bytes());
        body.extend_from_slice(&it.mtime.to_le_bytes());
        count += 1;
        at += 1;
    }
    let next = if at < items.len() { at as u32 } else { 0 };
    body[..4].copy_from_slice(&next.to_le_bytes());
    body[4..6].copy_from_slice(&count.to_le_bytes());
    body
}

/// Bounds-checked `len16` string.
fn take16<'a>(p: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (l, rest) = p.split_first_chunk::<2>()?;
    let (s, rest) = rest.split_at_checked(usize::from(u16::from_le_bytes(*l)))?;
    *p = rest;
    Some(s)
}

impl Svc {
    /// Why `name` resolves to nothing: its volume is hung or gone, or it is no item.
    fn unresolved(&self, name: &[u8]) -> Failure {
        match trash::volume_of(name) {
            Some(dir) if self.blocked(&dir) => Failure::st(ST_SUSPECT_MOUNT),
            // The home trash left the list because its mount hung: that is no missing item.
            None if name.starts_with(b"h-")
                && self.home.as_ref().is_some_and(|h| self.blocked(&h.dir)) =>
            {
                Failure::st(ST_SUSPECT_MOUNT)
            }
            _ => Failure::st(ST_NOT_FOUND),
        }
    }
}

/// Serves the kinds above and hands everything else to `inner`.
pub struct VfsHandler {
    inner: Arc<dyn Handler>,
    svc: Arc<Svc>,
}

impl VfsHandler {
    pub fn new(inner: Arc<dyn Handler>, svc: Arc<Svc>) -> Self {
        Self { inner, svc }
    }
}

impl Handler for VfsHandler {
    fn session(&self) -> Box<dyn Session> {
        Box::new(VfsSession {
            inner: self.inner.session(),
            svc: Arc::clone(&self.svc),
            snapshot: Arc::new(Mutex::new((Vec::new(), false))),
            gone: Arc::new(AtomicBool::new(false)),
        })
    }

    fn is_busy(&self) -> bool {
        self.svc.in_flight.load(Ordering::SeqCst) > 0 || self.inner.is_busy()
    }

    fn begin_drain(&self) {
        self.svc.draining.store(true, Ordering::SeqCst);
        self.inner.begin_drain();
    }

    fn cancel_all(&self) -> usize {
        self.inner.cancel_all()
    }
}

struct VfsSession {
    inner: Box<dyn Session>,
    svc: Arc<Svc>,
    snapshot: Arc<Mutex<(Vec<Item>, bool)>>,
    gone: Arc<AtomicBool>,
}

impl Drop for VfsSession {
    fn drop(&mut self) {
        self.gone.store(true, Ordering::SeqCst);
    }
}

/// Gives a request-thread slot back, whatever the thread does.
struct Slot(Arc<Svc>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl VfsSession {
    /// Run `job` on a request thread; it returns the reply. `busy` when none is free.
    fn spawn(
        &self,
        port: &Arc<Port>,
        seq: u64,
        job: impl FnOnce(&Svc, &Ctx) -> (u32, Vec<u8>) + Send + 'static,
    ) {
        let busy = || port.reply(MSG_REPLY, seq, &reply_payload(ST_BUSY, &[]));
        if self.svc.draining.load(Ordering::SeqCst) {
            return busy();
        }
        let Some(done) = self.svc.admit(Instant::now()) else {
            return busy();
        };
        self.svc.in_flight.fetch_add(1, Ordering::SeqCst);
        let slot = Slot(Arc::clone(&self.svc));
        let ended = Arc::clone(&done);
        let p = Arc::clone(port);
        let ctx = Ctx {
            port: Arc::clone(port),
            seq,
            last_beat: Mutex::new(Instant::now()),
            gone: Arc::clone(&self.gone),
        };
        let spawned = thread::Builder::new()
            .name("gungnir-vfs".into())
            .spawn(move || {
                let (st, body) = job(&slot.0, &ctx);
                let st = reply_status(st, slot.0.draining.load(Ordering::SeqCst));
                p.reply(MSG_REPLY, seq, &reply_payload(st, &body));
                drop(slot);
                ended.store(true, Ordering::SeqCst);
            });
        if spawned.is_err() {
            done.store(true, Ordering::SeqCst);
            busy();
        }
    }

    fn list(&self, port: &Arc<Port>, msg: &Msg) {
        let p = msg.payload();
        let bad = || port.reply(MSG_REPLY, msg.seq, &reply_payload(ST_BAD_REQUEST, &[]));
        let [scheme, a, b, c, d] = *p else {
            return bad();
        };
        if scheme > SCHEME_RECENT {
            return bad();
        }
        let cursor = u32::from_le_bytes([a, b, c, d]) as usize;
        if cursor > 0 {
            let s = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
            let body = page(&s.0, cursor, s.1);
            return port.reply(MSG_REPLY, msg.seq, &reply_payload(ST_OK, &body));
        }
        let snap = Arc::clone(&self.snapshot);
        self.spawn(port, msg.seq, move |svc, _| {
            let items = if scheme == SCHEME_TRASH {
                Ok(svc.snapshot_trash())
            } else {
                svc.snapshot_recent().map(|i| (i, false))
            };
            match items {
                Ok((items, partial)) => {
                    let body = page(&items, 0, partial);
                    *snap.lock().unwrap_or_else(PoisonError::into_inner) = (items, partial);
                    (ST_OK, body)
                }
                Err(f) => (f.status, f.body()),
            }
        });
    }
}

fn outcome(r: Result<(), Failure>) -> (u32, Vec<u8>) {
    match r {
        Ok(()) => (ST_OK, Vec::new()),
        Err(f) if f.status == ST_CANCELLED => (ST_CANCELLED, Vec::new()),
        Err(f) => (f.status, f.body()),
    }
}

impl Session for VfsSession {
    fn request(&mut self, port: &Arc<Port>, msg: &Msg) {
        let bad = || port.reply(MSG_REPLY, msg.seq, &reply_payload(ST_BAD_REQUEST, &[]));
        match msg.kind {
            MSG_VFS_LIST => self.list(port, msg),
            MSG_VFS_DELETE => {
                let mut p = msg.payload();
                let Some((&scheme, rest)) = p.split_first() else {
                    return bad();
                };
                p = rest;
                let Some(name) = take16(&mut p).filter(|_| p.is_empty()).map(<[u8]>::to_vec) else {
                    return bad();
                };
                if scheme > SCHEME_RECENT {
                    return bad();
                }
                self.spawn(port, msg.seq, move |svc, ctx| {
                    outcome(svc.delete(scheme, &name, ctx))
                });
            }
            MSG_VFS_RESTORE => {
                let mut p = msg.payload();
                let (Some(name), Some(dest)) = (take16(&mut p), take16(&mut p)) else {
                    return bad();
                };
                if !p.is_empty() {
                    return bad();
                }
                let (name, dest) = (name.to_vec(), dest.to_vec());
                self.spawn(port, msg.seq, move |svc, ctx| {
                    outcome(svc.restore(&name, &dest, ctx))
                });
            }
            MSG_TRASH_EMPTY => {
                let p = msg.payload();
                if p.first() == Some(&SCHEME_RECENT) {
                    self.spawn(port, msg.seq, move |svc, _| outcome(svc.clear_recent()));
                } else {
                    self.spawn(port, msg.seq, Svc::empty);
                }
            }
            MSG_VFS_STAT => {
                let mut p = msg.payload();
                let Some((&scheme, rest)) = p.split_first() else {
                    return bad();
                };
                p = rest;
                let Some(name) = take16(&mut p).filter(|_| p.is_empty()).map(<[u8]>::to_vec) else {
                    return bad();
                };
                if scheme > SCHEME_RECENT {
                    return bad();
                }
                self.spawn(port, msg.seq, move |svc, _| match svc.stat(scheme, &name) {
                    Ok(item) => (ST_OK, page(&[item], 0, false)),
                    Err(f) => (f.status, f.body()),
                });
            }
            MSG_VFS_CHILDREN => {
                let mut p = msg.payload();
                let Some((c, rest)) = p.split_first_chunk::<4>() else {
                    return bad();
                };
                let cursor = u32::from_le_bytes(*c) as usize;
                p = rest;
                let Some(name) = take16(&mut p).filter(|_| p.is_empty()).map(<[u8]>::to_vec) else {
                    return bad();
                };
                if cursor > 0 {
                    let s = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
                    let body = page(&s.0, cursor, s.1);
                    return port.reply(MSG_REPLY, msg.seq, &reply_payload(ST_OK, &body));
                }
                let snap = Arc::clone(&self.snapshot);
                self.spawn(port, msg.seq, move |svc, _| match svc.children(&name) {
                    Ok((items, partial)) => {
                        let body = page(&items, 0, partial);
                        *snap.lock().unwrap_or_else(PoisonError::into_inner) = (items, partial);
                        (ST_OK, body)
                    }
                    Err(f) => (f.status, f.body()),
                });
            }
            MSG_VFS_STAMP => {
                let [scheme] = *msg.payload() else {
                    return bad();
                };
                if scheme > SCHEME_RECENT {
                    return bad();
                }
                self.spawn(port, msg.seq, move |svc, _| {
                    (ST_OK, svc.stamp(scheme).to_le_bytes().to_vec())
                });
            }
            _ => self.inner.request(port, msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuse_mounts_are_the_topmost_fuse_ones() {
        let table = "1 0 0:1 / / rw - btrfs /dev/sda2 rw\n\
            2 1 0:2 / /tmp/.mount_app rw - fuse.app app ro\n\
            3 1 0:3 / /home/u/remote rw - fuse.sshfs h:/ rw\n\
            4 1 0:4 / /mnt/x rw - fuse dead rw\n\
            5 4 0:5 / /mnt/x rw - ext4 /dev/sdb1 rw\n\
            6 1 0:6 / /m\\040n rw - fuseblk /dev/sdc1 rw\n";
        let got = fuse_mounts(&fsid::parse_mountinfo(table.as_bytes()));
        assert_eq!(
            got,
            [
                PathBuf::from("/tmp/.mount_app"),
                PathBuf::from("/home/u/remote"),
                PathBuf::from("/m n"),
            ]
        );
    }

    /// A mount nested in a snapshot is not the snapshot: home on it says nothing of that.
    #[test]
    fn home_belongs_to_the_nearest_mount() {
        let tops: Vec<PathBuf> = ["/", "/mnt/snap", "/mnt/snap/home"]
            .map(PathBuf::from)
            .into();
        let on = |p: &str| mount_of(&tops, Path::new(p)).map(|t| t.to_str().unwrap_or(""));
        assert_eq!(on("/mnt/snap/home/u"), Some("/mnt/snap/home"));
        assert_eq!(on("/mnt/snap/x"), Some("/mnt/snap"));
        assert_eq!(on("/home/u"), Some("/"));
    }

    #[test]
    fn only_btrfs_mounts_are_searched() {
        let table = "36 1 0:32 / / rw - btrfs /dev/a rw\n\
                     37 1 0:33 / /mnt/my\\040disk rw shared:1 - btrfs /dev/b rw\n\
                     38 1 0:34 / /mnt/nfs rw - nfs4 s:/x rw\n";
        assert_eq!(
            btrfs_mounts(&fsid::parse_mountinfo(table.as_bytes())),
            vec![PathBuf::from("/"), PathBuf::from("/mnt/my disk")]
        );
    }

    #[test]
    fn a_failed_restore_says_what_failed() {
        assert_eq!(
            restore_failure(Failure::st(ST_MOUNT_INSIDE)).errno,
            libc::EXDEV
        );
        assert_eq!(restore_failure(Failure::st(ST_TIMEOUT)).status, ST_TIMEOUT);
        assert_eq!(reply_status(ST_CANCELLED, true), ST_BUSY);
        assert_eq!(reply_status(ST_CANCELLED, false), ST_CANCELLED);
        assert_eq!(reply_status(ST_OK, true), ST_OK);
    }

    /// A search stuck under a hung mount holds nobody up, and says it is not complete.
    #[test]
    fn a_stuck_subvolume_search_costs_only_itself() {
        let t = Dir::new("stuck-subvols");
        let svc = svc(&t.0.join("home"), Fixture(Some(Vec::new())));
        {
            let mut g = svc.subvols.0.lock().unwrap();
            g.done = Some((
                Instant::now() - SUBVOLS_TTL,
                vec![PathBuf::from("/old")],
                true,
            ));
            g.started = Some(Instant::now());
        }
        let t0 = Instant::now();
        let (found, complete) = svc.subvolumes(Vec::new(), false);
        assert!(t0.elapsed() < SUBVOLS_WAIT * 2);
        assert_eq!(found, vec![PathBuf::from("/old")]);
        assert!(!complete);
        // The lock was free all along, and an old search is not waited for at all.
        svc.subvols.0.lock().unwrap().started = Some(Instant::now() - SUBVOLS_WAIT);
        let t0 = Instant::now();
        assert!(!svc.subvolumes(Vec::new(), true).1);
        assert!(t0.elapsed() < Duration::from_millis(500));
    }

    /// How an enumeration learns it was not told everything.
    #[test]
    fn a_page_says_when_the_listing_is_partial() {
        let items = vec![item(0, 4)];
        assert_eq!(page(&items, 0, false)[6], 0);
        assert_eq!(page(&items, 0, true)[6], 1);
        // An item too long to name is one no client can see.
        let mut long = item(1, 4);
        long.name = vec![b'n'; PAYLOAD_MAX];
        assert_eq!(page(&[long], 0, false)[6], 1);
    }

    /// Stuck jobs hand their slot back after the lease, and the total stays bounded.
    #[test]
    fn a_stuck_job_gives_its_slot_back() {
        let mut jobs = Vec::new();
        let t0 = Instant::now();
        for _ in 0..MAX_WAITERS {
            assert!(admit(&mut jobs, t0).is_some());
        }
        assert!(admit(&mut jobs, t0).is_none());
        let mut now = t0 + SLOT_LEASE;
        let mut taken = MAX_WAITERS;
        while taken < STUCK_MAX {
            for _ in 0..MAX_WAITERS {
                if admit(&mut jobs, now).is_some() {
                    taken += 1;
                }
            }
            now += SLOT_LEASE;
        }
        assert!(admit(&mut jobs, now).is_none());
        jobs[0].1.store(true, Ordering::SeqCst);
        assert!(admit(&mut jobs, now).is_some());
    }

    fn item(n: usize, text: usize) -> Item {
        Item {
            name: format!("h-{n}").into_bytes(),
            entry: format!("{n}").into_bytes(),
            orig: vec![b'o'; text],
            target: vec![b't'; text],
            kind: trash::KIND_FILE,
            size: 1,
            mtime: 2,
            deleted: Vec::new(),
            link: Vec::new(),
        }
    }

    fn count(body: &[u8]) -> (u32, u16) {
        (
            u32::from_le_bytes(body[..4].try_into().unwrap()),
            u16::from_le_bytes(body[4..6].try_into().unwrap()),
        )
    }

    #[test]
    fn pages_cover_everything_and_fit_a_reply() {
        let items: Vec<_> = (0..500).map(|n| item(n, 40)).collect();
        let (mut cursor, mut seen) = (0, 0usize);
        loop {
            let b = page(&items, cursor, false);
            assert!(b.len() + 4 <= PAYLOAD_MAX);
            let (next, n) = count(&b);
            seen += usize::from(n);
            if next == 0 {
                break;
            }
            cursor = next as usize;
        }
        assert_eq!(seen, 500);
    }

    /// One long item never fails the page or stops it making progress.
    #[test]
    fn an_oversized_item_is_listed_without_its_long_strings() {
        let items = vec![item(0, 60_000), item(1, 10)];
        let b = page(&items, 0, false);
        assert!(b.len() + 4 <= PAYLOAD_MAX);
        assert_eq!(count(&b), (0, 2));
    }

    /// A name that fits no reply (a very long volume path) cannot be addressed anyway:
    /// it must not stop the page or end the list early.
    #[test]
    fn an_item_whose_name_fits_no_reply_does_not_stop_the_list() {
        let mut huge = item(0, 1);
        huge.name = vec![b'n'; 9000];
        let items = vec![item(1, 1), huge, item(2, 1), item(3, 1)];
        let (mut cursor, mut seen) = (0, 0usize);
        for _ in 0..8 {
            let b = page(&items, cursor, false);
            let (next, n) = count(&b);
            seen += usize::from(n);
            if next == 0 {
                break;
            }
            assert!(next as usize > cursor, "no progress");
            cursor = next as usize;
        }
        assert_eq!(seen, 3);
    }

    #[test]
    fn empty_reports_success_only_when_nothing_can_remain() {
        let f = Failure::os(libc::EACCES);
        assert_eq!(empty_status(Some(f), true, true), ST_OS_ERROR);
        assert_eq!(empty_status(None, true, true), ST_NOT_EMPTY);
        assert_eq!(empty_status(None, false, true), ST_SUSPECT_MOUNT);
        assert_eq!(empty_status(None, false, false), ST_OK);
    }

    #[test]
    fn a_mount_refusal_is_its_own_status() {
        assert_eq!(Failure::os(libc::EXDEV).status, ST_MOUNT_INSIDE);
        assert_eq!(Failure::os(libc::EBUSY).status, ST_MOUNT_INSIDE);
        assert_eq!(Failure::os(libc::EACCES).status, ST_OS_ERROR);
        assert_eq!(Failure::os(libc::EACCES).body(), libc::EACCES.to_le_bytes());
    }

    #[test]
    fn mountinfo_gives_candidate_volumes() {
        let t = "22 1 0:21 / / rw - ext4 /dev/sda1 rw\n\
                 23 22 0:22 / /proc rw - proc proc rw\n\
                 24 22 0:23 / /mnt/my\\040disk rw shared:1 - vfat /dev/sdb1 rw\n\
                 garbage line\n";
        assert_eq!(
            mount_points(&fsid::parse_mountinfo(t.as_bytes())),
            [PathBuf::from("/"), PathBuf::from("/mnt/my disk")]
        );
    }

    /// A fixed mount table, or a table that cannot be read.
    struct Fixture(Option<Vec<u8>>);

    impl MountTable for Fixture {
        fn read(&self) -> std::io::Result<Vec<MountEntry>> {
            self.0
                .as_deref()
                .map(fsid::parse_mountinfo)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EACCES))
        }
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../.build/tmp")
                .join(format!("vs-{tag}-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn me() -> u32 {
        // SAFETY: plain getter.
        unsafe { libc::geteuid() }
    }

    /// A service over a scratch home and the given mount table, no daemon, no socket.
    fn svc(home: &Path, mounts: Fixture) -> Arc<Svc> {
        let ops = Ops::start(
            crate::ops::OpsConfig::default(),
            crate::ops::io::EngineKind::Threads,
            Arc::new(crate::ops::NoGate),
            Arc::new(crate::ops::NoMeta),
        )
        .expect("ops");
        Svc::new(
            Arc::new(ops),
            SvcConfig {
                xdg_data: Some(home.join("data").into_os_string()),
                home: Some(home.as_os_str().to_owned()),
                uid: me(),
                extra_tops: Vec::new(),
                host_subvols: false,
                mounts: Box::new(mounts),
            },
        )
    }

    fn table_line(mnt: &[u8]) -> Vec<u8> {
        let mut l = b"30 1 0:99 / ".to_vec();
        l.extend_from_slice(mnt);
        l.extend_from_slice(b" rw - ext4 /dev/x rw\n");
        l
    }

    /// One mount point that is not UTF-8 must not hide the others: their trash is still
    /// listed (the old text parser read the whole table as a string and lost it all).
    #[test]
    fn a_non_utf8_mount_point_hides_no_volume() {
        let t = Dir::new("nonutf8");
        let vol = t.0.join("vol");
        fs::create_dir_all(vol.join(format!(".Trash-{}/files", me()))).unwrap();
        fs::create_dir_all(vol.join(format!(".Trash-{}/info", me()))).unwrap();
        let mut table = table_line(b"/mnt/caf\xe9");
        table.extend(table_line(vol.as_os_str().as_bytes()));
        let s = svc(&t.0.join("home"), Fixture(Some(table)));
        let found = s.dirs_as_of(false);
        assert!(
            found.dirs.iter().any(|d| d.top == vol),
            "the volume trash is listed: {:?}",
            found.dirs
        );
        assert!(found.complete);
    }

    /// A table that cannot be read gives a listing that says it may not be everything.
    #[test]
    fn an_unreadable_mount_table_is_no_complete_listing() {
        let t = Dir::new("notable");
        let s = svc(&t.0.join("home"), Fixture(None));
        assert!(!s.dirs_as_of(false).complete);
        let (_, partial) = s.snapshot_trash();
        assert!(partial);
    }
}
