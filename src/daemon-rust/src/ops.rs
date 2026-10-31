//! Asynchronous bulk file operations (milestone 8): copy, move, delete, recursive delete
//! (trash preparation) and fsync of local files, run by gungnird so that no GIO caller
//! ever blocks on a slow or hung mount.
//!
//! - Engines ([`io`]): io_uring (`io-uring` crate, one ring per worker, probed at
//!   startup) or plain syscalls on the same worker threads when io_uring is unavailable
//!   (old kernel, `io_uring_disabled`, seccomp/container `ENOSYS`/`EPERM`) or disabled
//!   with `GUNGNIR_NO_URING=1`.
//! - Copy: `FICLONE` (reflink) first, then `copy_file_range` in chunks, then
//!   read/write chunks through the engine; holes are kept (`SEEK_DATA`/`SEEK_HOLE`). The
//!   data goes to a temporary file in the destination directory that is renamed into
//!   place (`RENAME_NOREPLACE` unless overwriting), so a cancelled or failed copy never
//!   leaves a partial destination. Mode and timestamps are kept (GIO's
//!   `TARGET_DEFAULT_PERMS` / `TARGET_DEFAULT_MODIFIED_TIME` turn that off), extended
//!   attributes and gungnir metadata only with `ALL_METADATA` (best effort).
//! - Move: `renameat2`; across filesystems (`EXDEV`) a file is copied with all its
//!   metadata, fsynced and the source unlinked (unless `NO_FALLBACK_FOR_MOVE`); a
//!   directory gives `WOULD_RECURSE`, as GIO's own move does.
//! - Scheduling ([`Ops`]): a bounded queue and a pool of workers (4 started, at most
//!   `max_threads` alive counting stuck ones); every op has an id, a deadline and a stall
//!   limit (no progress for `stall`). A "gungnir-opwatch" thread enforces them and
//!   cancellations: it asks the worker to stop and, if the worker does not report back
//!   within `grace` (stuck in a syscall on a hung mount), answers for it, abandons the
//!   thread, marks the mount suspect and starts a replacement worker.
//! - Health gate: paths on mounts the M7 monitor reports hung or gone, or that an op
//!   timed out on in the last `suspect_for`, are refused at submission, before any
//!   syscall touches them.
//!
//! Protocol (protocol v2 stays: new message kinds only; an M7 daemon answers them with
//! `ST_UNSUPPORTED`; mirrored in `src/client-zig/src/fileop.zig`). Integers little-endian.
//! - [`MSG_OP_START`] `op u8 | flags u32 | timeout_ms u32 | src path16 | dest path16`
//!   (`op`: [`OP_COPY`] .. [`OP_FSYNC`]; `flags`: GIO's `GFileCopyFlags` bit values;
//!   `timeout_ms` 0: the default; dest empty for delete, delete-tree and fsync). Answered
//!   at once with `MSG_MD_REPLY` `status u32 | op_id u64`.
//! - [`MSG_OP_CANCEL`] `op_id u64`: `MSG_MD_REPLY` `ST_OK`, or `ST_NOT_FOUND` if the op
//!   is unknown or already finished on this connection.
//! - [`MSG_OP_PROGRESS`] (`seq` 0, may be dropped when the ring is busy):
//!   `op_id u64 | bytes_done u64 | bytes_total u64 | files_done u64`.
//! - [`MSG_OP_DONE`] (`seq` = the start request's): `op_id u64 | status u32 | errno i32 |
//!   bytes_done u64 | files_done u64`, exactly once per started op, after a last
//!   progress event. Status [`ST_OS_ERROR`] carries the errno.

pub mod io;

use std::{
    collections::VecDeque,
    ffi::{CStr, CString},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::md::{
    Ident, ST_BAD_REQUEST, ST_BUSY, ST_OK, ST_SUSPECT_MOUNT, ST_TIMEOUT, ST_UNSUPPORTED,
};
use io::{EngineKind, Io, Step, StepError, Stop, SyncIo, UringIo, Watch};

pub const MSG_OP_START: u32 = 25;
pub const MSG_OP_CANCEL: u32 = 26;
pub const MSG_OP_PROGRESS: u32 = 34;
pub const MSG_OP_DONE: u32 = 35;

pub const OP_COPY: u8 = 1;
pub const OP_MOVE: u8 = 2;
pub const OP_DELETE: u8 = 3;
pub const OP_DELETE_TREE: u8 = 4;
pub const OP_FSYNC: u8 = 5;

// GIO's GFileCopyFlags values.
pub const FLAG_OVERWRITE: u32 = 1;
pub const FLAG_BACKUP: u32 = 2;
pub const FLAG_NOFOLLOW_SYMLINKS: u32 = 4;
pub const FLAG_ALL_METADATA: u32 = 8;
pub const FLAG_NO_FALLBACK_FOR_MOVE: u32 = 16;
pub const FLAG_TARGET_DEFAULT_PERMS: u32 = 32;
pub const FLAG_TARGET_DEFAULT_MODIFIED_TIME: u32 = 64;
const KNOWN_FLAGS: u32 = 127;

/// Done statuses beyond `md`'s.
pub const ST_CANCELLED: u32 = 14;
pub const ST_OS_ERROR: u32 = 15;
pub const ST_WOULD_RECURSE: u32 = 16;

/// The environment variable that forces the thread-pool engine.
pub const NO_URING_ENV: &str = "GUNGNIR_NO_URING";
/// Test hook (`test-hooks` builds only): sleep this many ms before every data chunk or
/// directory entry, so tests can cancel an op mid-way.
pub const SLOW_OPS_ENV: &str = "GUNGNIR_TEST_SLOW_OPS_MS";
/// Test hook (`test-hooks` builds only): hold every copy at this point (`mid-copy`,
/// `before-publish`) until it is stopped, so a test can interrupt it exactly there.
pub const PAUSE_AT_ENV: &str = "GUNGNIR_TEST_PAUSE_AT";

/// Test hook (`test-hooks` builds only): the first worker to pick up an op loses its ring,
/// as a worker replaced after a stuck mount does.
pub const RING_LOSS_ENV: &str = "GUNGNIR_TEST_RING_LOSS";
#[cfg(feature = "test-hooks")]
static RING_LOSS: AtomicBool = AtomicBool::new(false);

/// Whether [`RING_LOSS_ENV`] takes this worker's ring now.
fn ring_lost() -> bool {
    #[cfg(feature = "test-hooks")]
    {
        RING_LOSS.swap(false, Ordering::SeqCst)
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        false
    }
}

/// Where the [`PAUSE_AT_ENV`] test hook holds an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PausePoint {
    /// After the first chunk of data reached the temp file.
    MidCopy,
    /// With the temp file complete, just before the rename that publishes it.
    BeforePublish,
}

impl PausePoint {
    /// The hook's value for `s`, if it names a point.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mid-copy" => Some(Self::MidCopy),
            "before-publish" => Some(Self::BeforePublish),
            _ => None,
        }
    }
}

/// Longest path accepted (`PATH_MAX` without the NUL).
const MAX_PATH: usize = 4095;
/// Deepest directory nesting a recursive delete follows (one open fd per level).
pub const MAX_DEPTH: usize = 256;
const XATTR_MAX: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Copy,
    Move,
    Delete,
    DeleteTree,
    Fsync,
}

impl OpKind {
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            OpKind::Copy => OP_COPY,
            OpKind::Move => OP_MOVE,
            OpKind::Delete => OP_DELETE,
            OpKind::DeleteTree => OP_DELETE_TREE,
            OpKind::Fsync => OP_FSYNC,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            OP_COPY => OpKind::Copy,
            OP_MOVE => OpKind::Move,
            OP_DELETE => OpKind::Delete,
            OP_DELETE_TREE => OpKind::DeleteTree,
            OP_FSYNC => OpKind::Fsync,
            _ => return None,
        })
    }

    fn has_dest(self) -> bool {
        matches!(self, OpKind::Copy | OpKind::Move)
    }
}

/// Why an op failed. Maps 1:1 to a done status (plus errno).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpError {
    Os(i32),
    Cancelled,
    TimedOut,
    SuspectMount,
    Busy,
    WouldRecurse,
    Unsupported,
    BadRequest,
}

impl OpError {
    /// `(status, errno)`.
    #[must_use]
    pub fn status(self) -> (u32, i32) {
        match self {
            OpError::Os(e) => (ST_OS_ERROR, e),
            OpError::Cancelled => (ST_CANCELLED, 0),
            OpError::TimedOut => (ST_TIMEOUT, 0),
            OpError::SuspectMount => (ST_SUSPECT_MOUNT, 0),
            OpError::Busy => (ST_BUSY, 0),
            OpError::WouldRecurse => (ST_WOULD_RECURSE, 0),
            OpError::Unsupported => (ST_UNSUPPORTED, 0),
            OpError::BadRequest => (ST_BAD_REQUEST, 0),
        }
    }

    #[must_use]
    pub fn from_status(st: u32, errno: i32) -> Option<Self> {
        Some(match st {
            ST_OS_ERROR => OpError::Os(errno),
            ST_CANCELLED => OpError::Cancelled,
            ST_TIMEOUT => OpError::TimedOut,
            ST_SUSPECT_MOUNT => OpError::SuspectMount,
            ST_BUSY => OpError::Busy,
            ST_WOULD_RECURSE => OpError::WouldRecurse,
            ST_UNSUPPORTED => OpError::Unsupported,
            ST_BAD_REQUEST => OpError::BadRequest,
            _ => return None,
        })
    }
}

impl From<StepError> for OpError {
    fn from(e: StepError) -> Self {
        match e {
            StepError::Os(n) => OpError::Os(n),
            StepError::Stop(Stop::Cancelled) => OpError::Cancelled,
            StepError::Stop(Stop::TimedOut) => OpError::TimedOut,
        }
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpError::Os(e) => write!(f, "{}", std::io::Error::from_raw_os_error(*e)),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for OpError {}

pub type OpResult = std::result::Result<(), OpError>;

/// A validated start request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRequest {
    pub kind: OpKind,
    pub flags: u32,
    /// 0: the daemon's default deadline.
    pub timeout_ms: u32,
    pub src: Vec<u8>,
    /// Empty unless the op has a destination.
    pub dest: Vec<u8>,
}

/// An absolute, lexically canonical path: no NUL, no empty, `.` or `..` component, no
/// trailing slash. `root_ok`: "/" itself is accepted.
fn check_path(p: &[u8], root_ok: bool) -> bool {
    if p.first() != Some(&b'/') || p.len() > MAX_PATH || p.contains(&0) {
        return false;
    }
    if p == b"/" {
        return root_ok;
    }
    p[1..]
        .split(|&b| b == b'/')
        .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

fn take<'a>(p: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if p.len() < n {
        return None;
    }
    let (a, b) = p.split_at(n);
    *p = b;
    Some(a)
}

fn take_u32(p: &mut &[u8]) -> Option<u32> {
    take(p, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn take_u64(p: &mut &[u8]) -> Option<u64> {
    let b = take(p, 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Some(u64::from_le_bytes(a))
}

fn take_path16<'a>(p: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = take(p, 2)?;
    take(p, usize::from(u16::from_le_bytes([n[0], n[1]])))
}

impl OpRequest {
    /// Parse a [`MSG_OP_START`] payload.
    ///
    /// # Errors
    /// [`OpError::BadRequest`] for a malformed request, [`OpError::Unsupported`] for
    /// `G_FILE_COPY_BACKUP`.
    pub fn parse(payload: &[u8]) -> std::result::Result<Self, OpError> {
        let mut p = payload;
        let bad = OpError::BadRequest;
        let kind = take(&mut p, 1)
            .and_then(|b| OpKind::from_code(b[0]))
            .ok_or(bad)?;
        let flags = take_u32(&mut p).ok_or(bad)?;
        let timeout_ms = take_u32(&mut p).ok_or(bad)?;
        let src = take_path16(&mut p).ok_or(bad)?;
        let dest = take_path16(&mut p).ok_or(bad)?;
        if !p.is_empty() || flags & !KNOWN_FLAGS != 0 {
            return Err(bad);
        }
        if flags & FLAG_BACKUP != 0 {
            return Err(OpError::Unsupported);
        }
        let ok = if kind.has_dest() {
            check_path(src, false) && check_path(dest, false) && src != dest
        } else {
            dest.is_empty() && check_path(src, kind == OpKind::Fsync)
        };
        if !ok {
            return Err(bad);
        }
        Ok(Self {
            kind,
            flags,
            timeout_ms,
            src: src.to_vec(),
            dest: dest.to_vec(),
        })
    }

    /// Encode as a [`MSG_OP_START`] payload (no validation: tests send bad ones too).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + self.src.len() + self.dest.len());
        out.push(self.kind.code());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.timeout_ms.to_le_bytes());
        for p in [&self.src, &self.dest] {
            out.extend_from_slice(&(p.len() as u16).to_le_bytes());
            out.extend_from_slice(p);
        }
        out
    }
}

/// Progress counters of one op.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub files_done: u64,
}

/// [`MSG_OP_PROGRESS`] payload.
#[must_use]
pub fn progress_payload(id: u64, p: &Progress) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    for v in [id, p.bytes_done, p.bytes_total, p.files_done] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

/// Parse a [`MSG_OP_PROGRESS`] payload.
#[must_use]
pub fn parse_progress(b: &[u8]) -> Option<(u64, Progress)> {
    let mut p = b;
    let id = take_u64(&mut p)?;
    let pr = Progress {
        bytes_done: take_u64(&mut p)?,
        bytes_total: take_u64(&mut p)?,
        files_done: take_u64(&mut p)?,
    };
    p.is_empty().then_some((id, pr))
}

/// The end of an op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Done {
    pub id: u64,
    pub result: OpResult,
    pub progress: Progress,
}

/// [`MSG_OP_DONE`] payload.
#[must_use]
pub fn done_payload(d: &Done) -> Vec<u8> {
    let (st, errno) = match d.result {
        Ok(()) => (ST_OK, 0),
        Err(e) => e.status(),
    };
    let mut b = Vec::with_capacity(32);
    b.extend_from_slice(&d.id.to_le_bytes());
    b.extend_from_slice(&st.to_le_bytes());
    b.extend_from_slice(&errno.to_le_bytes());
    b.extend_from_slice(&d.progress.bytes_done.to_le_bytes());
    b.extend_from_slice(&d.progress.files_done.to_le_bytes());
    b
}

/// Parse a [`MSG_OP_DONE`] payload (`bytes_total` is not carried: 0).
#[must_use]
pub fn parse_done(b: &[u8]) -> Option<Done> {
    let mut p = b;
    let id = take_u64(&mut p)?;
    let st = take_u32(&mut p)?;
    let errno = take_u32(&mut p)? as i32;
    let bytes_done = take_u64(&mut p)?;
    let files_done = take_u64(&mut p)?;
    if !p.is_empty() {
        return None;
    }
    let result = if st == ST_OK {
        Ok(())
    } else {
        Err(OpError::from_status(st, errno)?)
    };
    Some(Done {
        id,
        result,
        progress: Progress {
            bytes_done,
            bytes_total: 0,
            files_done,
        },
    })
}

// ---------------------------------------------------------------------------------------
// Hooks into the rest of the daemon

/// Mount health, lexical only: never touches the path.
pub trait Gate: Send + Sync {
    /// The mount point `path` is on, if that mount is hung or gone.
    fn blocking(&self, path: &[u8]) -> Option<PathBuf>;
    /// The mount point `path` is on (to mark it suspect after a timeout).
    fn mount_of(&self, path: &[u8]) -> Option<PathBuf>;
}

/// No health information: nothing is refused, timeouts mark nothing.
pub struct NoGate;

impl Gate for NoGate {
    fn blocking(&self, _: &[u8]) -> Option<PathBuf> {
        None
    }
    fn mount_of(&self, _: &[u8]) -> Option<PathBuf> {
        None
    }
}

/// Keep gungnir metadata with the files (milestone 6 logic). Called on the worker after
/// the file operation succeeded; each call is bounded and best effort.
pub trait MetaHooks: Send + Sync {
    /// The identity of `path` (before a copy or a cross-device move).
    fn identify(&self, path: &[u8]) -> Option<Ident>;
    /// `src` was renamed to `dest` (same identity).
    fn moved(&self, src: &[u8], dest: &[u8]);
    /// `dest` is a copy of the file that had identity `from`: duplicate its rows to the
    /// identity of `dest`; `forget_src`: and drop `from`'s rows (cross-device move).
    fn copied(&self, from: &Ident, dest: &[u8], forget_src: bool);
    /// `path` was deleted (`tree`: with everything below it).
    fn removed(&self, path: &[u8], tree: bool);
    /// Several paths were deleted (a recursive delete that failed part-way reports
    /// exactly what it deleted).
    fn removed_paths(&self, paths: &[(Vec<u8>, bool)]) {
        for (p, tree) in paths {
            self.removed(p, *tree);
        }
    }
}

/// No metadata service.
pub struct NoMeta;

impl MetaHooks for NoMeta {
    fn identify(&self, _: &[u8]) -> Option<Ident> {
        None
    }
    fn moved(&self, _: &[u8], _: &[u8]) {}
    fn copied(&self, _: &Ident, _: &[u8], _: bool) {}
    fn removed(&self, _: &[u8], _: bool) {}
}

/// Where an op's events go (the connection's ring, or a test's channel).
pub trait Sink: Send + Sync {
    fn progress(&self, id: u64, p: &Progress);
    /// Called exactly once per op.
    fn done(&self, d: &Done);
}

// ---------------------------------------------------------------------------------------
// One op

const STOP_NONE: u8 = 0;
const STOP_CANCEL: u8 = 1;
const STOP_TIMEOUT: u8 = 2;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The shared state of one op: its request, stop flag, counters and sink.
pub struct OpCtl {
    pub id: u64,
    pub req: OpRequest,
    sink: Arc<dyn Sink>,
    deadline: Instant,
    stop: AtomicU8,
    stop_at: Mutex<Option<Instant>>,
    finished: AtomicBool,
    abandoned: AtomicBool,
    bytes_done: AtomicU64,
    bytes_total: AtomicU64,
    files_done: AtomicU64,
    last_progress: Mutex<Instant>,
    last_emit: Mutex<Option<Instant>>,
    emit_every: Duration,
}

impl Watch for OpCtl {
    fn stopped(&self) -> Option<Stop> {
        match self.stop.load(Ordering::Acquire) {
            STOP_CANCEL => Some(Stop::Cancelled),
            STOP_TIMEOUT => Some(Stop::TimedOut),
            _ => None,
        }
    }
}

impl OpCtl {
    fn request_stop(&self, s: u8) {
        if self
            .stop
            .compare_exchange(STOP_NONE, s, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            *lock(&self.stop_at) = Some(Instant::now());
        }
    }

    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn progress(&self) -> Progress {
        Progress {
            bytes_done: self.bytes_done.load(Ordering::Relaxed),
            bytes_total: self.bytes_total.load(Ordering::Relaxed),
            files_done: self.files_done.load(Ordering::Relaxed),
        }
    }

    fn touch(&self) {
        *lock(&self.last_progress) = Instant::now();
    }

    fn set_total(&self, n: u64) {
        self.bytes_total.store(n, Ordering::Relaxed);
    }

    fn add_bytes(&self, n: u64) {
        self.bytes_done.fetch_add(n, Ordering::Relaxed);
        self.touch();
        self.maybe_emit(false);
    }

    fn add_file(&self) {
        self.files_done.fetch_add(1, Ordering::Relaxed);
        self.touch();
        self.maybe_emit(false);
    }

    fn maybe_emit(&self, force: bool) {
        let now = Instant::now();
        {
            let mut last = lock(&self.last_emit);
            if !force && last.is_some_and(|t| now.duration_since(t) < self.emit_every) {
                return;
            }
            *last = Some(now);
        }
        if !self.is_finished() {
            self.sink.progress(self.id, &self.progress());
        }
    }

    /// Report the result, once: later calls do nothing. Returns whether this one did.
    fn finish(&self, result: OpResult) -> bool {
        if self.finished.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.sink.done(&Done {
            id: self.id,
            result,
            progress: self.progress(),
        });
        true
    }
}

// ---------------------------------------------------------------------------------------
// The scheduler

#[derive(Debug, Clone)]
pub struct OpsConfig {
    /// Workers kept running.
    pub workers: usize,
    /// Most worker threads alive, counting ones stuck in a syscall.
    pub max_threads: usize,
    /// Ops that may wait for a worker; beyond, submissions are answered Busy.
    pub queue: usize,
    /// Ops one connection may have unfinished at once.
    pub per_conn: usize,
    /// Deadline of an op that asked for none.
    pub default_timeout: Duration,
    /// Longest deadline an op may ask for.
    pub max_timeout: Duration,
    /// An op that makes no progress for this long has timed out.
    pub stall: Duration,
    /// How long a worker may take to stop after a cancel or timeout before it is
    /// abandoned and the op answered for.
    pub grace: Duration,
    /// Least time between two progress events of one op.
    pub progress_every: Duration,
    /// How long a mount stays suspect after an op timed out on it.
    pub suspect_for: Duration,
    /// Bytes per `copy_file_range` call.
    pub cfr_chunk: usize,
    /// Read/write buffer per worker.
    pub buf_size: usize,
    /// Test hook: sleep before every chunk / entry.
    pub slow: Duration,
    /// Test hook: hold copies at this point until they are stopped.
    pub pause_at: Option<PausePoint>,
    /// Tests: behave as if every rename and copy_file_range crossed filesystems.
    pub force_exdev: bool,
    /// Tests: skip FICLONE / copy_file_range, to exercise the read/write path.
    pub no_clone: bool,
    pub no_cfr: bool,
}

impl Default for OpsConfig {
    fn default() -> Self {
        Self {
            workers: 4,
            max_threads: 16,
            queue: 64,
            per_conn: 8,
            default_timeout: Duration::from_secs(3600),
            max_timeout: Duration::from_secs(86_400),
            stall: Duration::from_secs(30),
            grace: Duration::from_millis(250),
            progress_every: Duration::from_millis(100),
            suspect_for: Duration::from_secs(30),
            cfr_chunk: 8 << 20,
            buf_size: 1 << 20,
            slow: Duration::ZERO,
            pause_at: None,
            force_exdev: false,
            no_clone: false,
            no_cfr: false,
        }
    }
}

impl OpsConfig {
    /// The defaults plus the test hook from the environment (`test-hooks` builds).
    #[must_use]
    pub fn from_env() -> Self {
        #[cfg(feature = "test-hooks")]
        let mut cfg = Self::default();
        #[cfg(not(feature = "test-hooks"))]
        let cfg = Self::default();

        #[cfg(feature = "test-hooks")]
        if let Some(v) = std::env::var_os(SLOW_OPS_ENV) {
            let ms = v.to_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            eprintln!("gungnird: TEST HOOK: file ops sleep {ms} ms per chunk");
            cfg.slow = Duration::from_millis(ms);
            // A reflink has no chunks to slow down: on btrfs a "slow" copy would finish at
            // once and tests that interrupt it would find nothing left to stop.
            cfg.no_clone = true;
        }
        #[cfg(not(feature = "test-hooks"))]
        if std::env::var_os(SLOW_OPS_ENV).is_some() {
            eprintln!("gungnird: {SLOW_OPS_ENV} ignored (built without the test-hooks feature)");
        }
        #[cfg(feature = "test-hooks")]
        if std::env::var_os(RING_LOSS_ENV).is_some() {
            eprintln!("gungnird: TEST HOOK: the first worker with an op loses its ring");
            RING_LOSS.store(true, Ordering::SeqCst);
        }
        #[cfg(feature = "test-hooks")]
        if let Some(v) = std::env::var_os(PAUSE_AT_ENV) {
            cfg.pause_at = v.to_str().and_then(PausePoint::parse);
            eprintln!("gungnird: TEST HOOK: file ops pause at {:?}", cfg.pause_at);
            // A reflink finishes in one call: mid-copy needs the chunked path.
            cfg.no_clone = true;
        }
        #[cfg(not(feature = "test-hooks"))]
        if std::env::var_os(PAUSE_AT_ENV).is_some() {
            eprintln!("gungnird: {PAUSE_AT_ENV} ignored (built without the test-hooks feature)");
        }
        cfg
    }
}

/// Pick the engine: the thread pool if `GUNGNIR_NO_URING` is set to anything but "" or
/// "0", or if io_uring fails its probe. Returns the reason for the log.
#[must_use]
pub fn choose_engine(no_uring: Option<&std::ffi::OsStr>) -> (EngineKind, String) {
    if let Some(v) = no_uring
        && !v.is_empty()
        && v != "0"
    {
        return (EngineKind::Threads, format!("{NO_URING_ENV} is set"));
    }
    match io::probe() {
        Ok(()) => (EngineKind::Uring, "probe ok".to_owned()),
        Err(e) => (EngineKind::Threads, format!("io_uring unavailable: {e}")),
    }
}

struct State {
    queue: VecDeque<Arc<OpCtl>>,
    running: Vec<Arc<OpCtl>>,
    threads: usize,
    stuck: usize,
    shutdown: bool,
    /// Set by [`Ops::begin_drain`]: new submissions are refused (BC-A2-F03a).
    draining: bool,
}

struct Shared {
    cfg: OpsConfig,
    engine: EngineKind,
    gate: Arc<dyn Gate>,
    meta: Arc<dyn MetaHooks>,
    state: Mutex<State>,
    work: Condvar,
    watch: Condvar,
    next_id: AtomicU64,
    suspects: Mutex<Vec<(PathBuf, Instant)>>,
    uring_failed: AtomicBool,
    /// Workers that have built their engine, and how many of those got an io_uring ring
    /// (BC-A2-F01: a sandboxed daemon checks that every first worker did).
    io_made: AtomicUsize,
    io_uring: AtomicUsize,
    /// Where copies and moves record that they may leave temp files, until they end
    /// (see [`sweep_temp_ledger`]); none in tests.
    /// The file, and how many recorded ops have not ended: at 0 it is emptied, so it
    /// stays small in a long-running daemon.
    ledger: Mutex<Option<(std::fs::File, usize)>>,
}

/// The file-operation service: queue, workers and watchdog.
pub struct Ops {
    sh: Arc<Shared>,
}

impl Ops {
    /// Start `cfg.workers` workers and the watchdog.
    ///
    /// # Errors
    /// A thread could not be started.
    pub fn start(
        cfg: OpsConfig,
        engine: EngineKind,
        gate: Arc<dyn Gate>,
        meta: Arc<dyn MetaHooks>,
    ) -> std::io::Result<Self> {
        let workers = cfg.workers.max(1);
        let sh = Arc::new(Shared {
            cfg,
            engine,
            gate,
            meta,
            state: Mutex::new(State {
                queue: VecDeque::new(),
                running: Vec::new(),
                threads: 0,
                stuck: 0,
                shutdown: false,
                draining: false,
            }),
            work: Condvar::new(),
            watch: Condvar::new(),
            next_id: AtomicU64::new(1),
            suspects: Mutex::new(Vec::new()),
            uring_failed: AtomicBool::new(false),
            io_made: AtomicUsize::new(0),
            io_uring: AtomicUsize::new(0),
            ledger: Mutex::new(None),
        });
        for _ in 0..workers {
            spawn_worker(&sh)?;
        }
        let w = Arc::clone(&sh);
        thread::Builder::new()
            .name("gungnir-opwatch".into())
            .spawn(move || watchdog(&w))?;
        Ok(Self { sh })
    }

    #[must_use]
    pub fn engine(&self) -> EngineKind {
        self.sh.engine
    }

    /// Wait (at most `max`) until `n` workers have built their engine; returns how many
    /// have, and how many of those run on an io_uring ring.
    #[must_use]
    pub fn wait_workers_ready(&self, n: usize, max: Duration) -> (usize, usize) {
        let t0 = Instant::now();
        loop {
            let made = self.sh.io_made.load(Ordering::SeqCst);
            if made >= n || t0.elapsed() >= max {
                return (made, self.sh.io_uring.load(Ordering::SeqCst));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[must_use]
    pub fn config(&self) -> &OpsConfig {
        &self.sh.cfg
    }

    /// `(threads alive, of which stuck)`.
    #[must_use]
    pub fn threads(&self) -> (usize, usize) {
        let s = lock(&self.sh.state);
        (s.threads, s.stuck)
    }

    /// Whether any file operations are queued or running.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        let s = lock(&self.sh.state);
        !s.queue.is_empty() || !s.running.is_empty()
    }

    /// The mount `path` is refused on, if any (health monitor or a recent timeout).
    #[must_use]
    pub fn blocked(&self, path: &[u8]) -> Option<PathBuf> {
        self.sh.blocked(path)
    }

    /// Queue an op. Paths on hung, gone or suspect mounts and a full queue are refused
    /// at once, without a syscall.
    ///
    /// # Errors
    /// [`OpError::SuspectMount`], [`OpError::Busy`].
    pub fn submit(
        &self,
        req: OpRequest,
        sink: Arc<dyn Sink>,
    ) -> std::result::Result<Arc<OpCtl>, OpError> {
        for p in [&req.src, &req.dest] {
            if !p.is_empty() && self.sh.blocked(p).is_some() {
                return Err(OpError::SuspectMount);
            }
        }
        let cfg = &self.sh.cfg;
        let timeout = match req.timeout_ms {
            0 => cfg.default_timeout,
            ms => Duration::from_millis(u64::from(ms)).min(cfg.max_timeout),
        };
        let now = Instant::now();
        let ctl = Arc::new(OpCtl {
            id: self.sh.next_id.fetch_add(1, Ordering::Relaxed),
            req,
            sink,
            deadline: now + timeout,
            stop: AtomicU8::new(STOP_NONE),
            stop_at: Mutex::new(None),
            finished: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
            bytes_done: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            files_done: AtomicU64::new(0),
            last_progress: Mutex::new(now),
            last_emit: Mutex::new(None),
            emit_every: cfg.progress_every,
        });
        let mut s = lock(&self.sh.state);
        if s.shutdown || s.draining || s.queue.len() >= cfg.queue.max(1) {
            return Err(OpError::Busy);
        }
        s.queue.push_back(Arc::clone(&ctl));
        drop(s);
        self.sh.work.notify_one();
        self.sh.watch.notify_one();
        Ok(ctl)
    }

    /// Ask an op to stop. It finishes with [`OpError::Cancelled`] within `grace` (or
    /// sooner with whatever it finished with first).
    pub fn cancel(&self, ctl: &OpCtl) {
        ctl.request_stop(STOP_CANCEL);
        self.sh.watch.notify_one();
    }

    /// Refuse every new op from now on with [`OpError::Busy`] (the drain before an exit,
    /// BC-A2-F03a). Ops already queued or running are not touched.
    pub fn begin_drain(&self) {
        lock(&self.sh.state).draining = true;
    }

    /// Cancel every queued and running op (BC-A2-F03b/c): each finishes with
    /// [`OpError::Cancelled`] (its done event), and a running copy removes its temp file
    /// as on any failure. Returns how many ops were asked to stop.
    pub fn cancel_all(&self) -> usize {
        let s = lock(&self.sh.state);
        let mut n = 0;
        for ctl in s.queue.iter().chain(s.running.iter()) {
            if !ctl.is_finished() {
                ctl.request_stop(STOP_CANCEL);
                n += 1;
            }
        }
        drop(s);
        self.sh.watch.notify_all();
        self.sh.work.notify_all();
        n
    }

    /// Record copies and moves in `file` (append-only, see [`sweep_temp_ledger`]) from
    /// now on, so that a daemon that exits with one still running (killed, or a stuck
    /// worker abandoned at a drain) has its temp files removed by the next start.
    pub fn set_temp_ledger(&self, file: std::fs::File) {
        *lock(&self.sh.ledger) = Some((file, 0));
    }
}

impl Drop for Ops {
    fn drop(&mut self) {
        lock(&self.sh.state).shutdown = true;
        self.sh.work.notify_all();
        self.sh.watch.notify_all();
    }
}

impl Shared {
    fn blocked(&self, path: &[u8]) -> Option<PathBuf> {
        if let Some(m) = self.gate.blocking(path) {
            return Some(m);
        }
        let now = Instant::now();
        let mut s = lock(&self.suspects);
        s.retain(|(_, until)| *until > now);
        s.iter()
            .find(|(m, _)| under(path, m.as_os_str().as_encoded_bytes()))
            .map(|(m, _)| m.clone())
    }

    fn mark_suspect(&self, path: &[u8]) {
        let Some(m) = self.gate.mount_of(path) else {
            return;
        };
        if m.as_os_str().as_encoded_bytes() == b"/" {
            return; // never refuse everything because of one slow file
        }
        eprintln!(
            "gungnird: file op timed out on {}: suspect for {:?}",
            m.display(),
            self.cfg.suspect_for
        );
        let until = Instant::now() + self.cfg.suspect_for;
        let mut s = lock(&self.suspects);
        s.retain(|(x, _)| *x != m);
        s.push((m, until));
    }

    /// Record in the temp ledger that op `id` may leave temp files near `dest`; whether
    /// it was recorded.
    fn ledger_begin(&self, id: u64, dest: &[u8]) -> bool {
        use std::io::Write;
        let mut g = lock(&self.ledger);
        let Some((f, open)) = g.as_mut() else {
            return false;
        };
        // One write per line on an O_APPEND file: lines never interleave.
        let ok = f.write_all(&ledger_start(id, dest)).is_ok();
        if ok {
            *open += 1;
        }
        ok
    }

    /// Record that op `id` (recorded by [`Self::ledger_begin`]) left no temp file.
    fn ledger_end(&self, id: u64) {
        use std::io::Write;
        if let Some((f, open)) = lock(&self.ledger).as_mut() {
            *open = open.saturating_sub(1);
            if *open == 0 {
                let _ = f.set_len(0);
            } else {
                let _ = f.write_all(&ledger_end(id));
            }
        }
    }

    fn make_io(&self) -> Box<dyn Io> {
        let io = self.make_io_inner();
        self.io_made.fetch_add(1, Ordering::SeqCst);
        io
    }

    fn make_io_inner(&self) -> Box<dyn Io> {
        if self.engine == EngineKind::Uring {
            match UringIo::new(self.cfg.buf_size) {
                Ok(u) => {
                    self.io_uring.fetch_add(1, Ordering::SeqCst);
                    return Box::new(u);
                }
                // No new ring can be made once sandboxed, and a worker on plain syscalls
                // next to workers on rings is the mixed mode the sandbox refuses at start
                // (D-077). Exit: the service manager restarts the daemon with a full
                // pool, destinations are published by rename, and the temp ledger sweeps
                // what running copies leave behind (A2-MGR-03).
                Err(e) if io::sandbox_rings_only() => {
                    eprintln!(
                        "gungnird: error: no restricted io_uring ring left for a worker ({e}); \
                         exiting for the service manager to restart with a full pool"
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    if !self.uring_failed.swap(true, Ordering::Relaxed) {
                        eprintln!("gungnird: io_uring ring for a worker failed ({e}): syscalls");
                    }
                }
            }
        }
        Box::new(SyncIo::new(self.cfg.buf_size))
    }
}

/// `path` is `mount` or below it (lexical).
fn under(path: &[u8], mount: &[u8]) -> bool {
    if mount == b"/" {
        return true;
    }
    path.starts_with(mount) && matches!(path.get(mount.len()), None | Some(&b'/'))
}

// ---------------------------------------------------------------------------------------
// Temp ledger (BC-A2-F03b, BC-HC-F06)

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn ledger_start(id: u64, dest: &[u8]) -> Vec<u8> {
    format!("S {id:016x} {}\n", hex(dest)).into_bytes()
}

fn ledger_end(id: u64) -> Vec<u8> {
    format!("E {id:016x}\n").into_bytes()
}

/// Most directory entries the sweep looks at below one destination.
const SWEEP_MAX_ENTRIES: usize = 100_000;

/// Remove the temp files of copies and moves a previous daemon left unfinished, then
/// empty the ledger. Runs at startup, before any op. For every op the ledger shows
/// started and not ended, every `.gungnir-<its id>-*.tmp` next to its destination and,
/// if the destination is a directory (a partial tree copy), below it (no symlink
/// followed, same filesystem, at most [`SWEEP_MAX_ENTRIES`] entries) is unlinked.
/// Returns how many files were removed.
///
/// # Errors
/// The ledger cannot be read or emptied.
pub fn sweep_temp_ledger(ledger: &std::path::Path) -> std::io::Result<usize> {
    use std::{
        collections::BTreeMap,
        ffi::OsStr,
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
        path::Path,
    };
    let text = match std::fs::read(ledger) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut open: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for line in String::from_utf8_lossy(&text).lines() {
        let mut f = line.split(' ');
        match (f.next(), f.next(), f.next()) {
            (Some("S"), Some(id), Some(d)) if id.len() == 16 => {
                if let Some(d) = unhex(d) {
                    open.insert(id.to_owned(), d);
                }
            }
            (Some("E"), Some(id), None) => {
                open.remove(id);
            }
            _ => {}
        }
    }
    let mut removed = 0usize;
    for (id, dest) in &open {
        let prefix = format!(".gungnir-{id}-");
        let ours = |n: &OsStr| {
            let n = n.as_bytes();
            n.starts_with(prefix.as_bytes()) && n.ends_with(b".tmp")
        };
        let dest = Path::new(OsStr::from_bytes(dest));
        if !dest.is_absolute() {
            continue;
        }
        let mut dirs: Vec<std::path::PathBuf> = Vec::new();
        if let Some(p) = dest.parent() {
            dirs.push(p.to_owned());
        }
        let top = std::fs::symlink_metadata(dest).ok();
        let dev = top.as_ref().map(MetadataExt::dev);
        let mut below = top
            .is_some_and(|m| m.is_dir())
            .then(|| vec![dest.to_owned()]);
        let mut seen = 0usize;
        let mut sweep_dir = |dir: &Path, walk: &mut Option<Vec<std::path::PathBuf>>| {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                seen += 1;
                if seen > SWEEP_MAX_ENTRIES {
                    return;
                }
                let name = e.file_name();
                let Ok(md) = e.metadata() else { continue };
                if ours(&name) && !md.is_dir() {
                    if std::fs::remove_file(e.path()).is_ok() {
                        removed += 1;
                    }
                } else if md.is_dir()
                    && Some(md.dev()) == dev
                    && let Some(w) = walk.as_mut()
                {
                    w.push(e.path());
                }
            }
        };
        for d in &dirs {
            sweep_dir(d, &mut None);
        }
        while let Some(d) = below.as_mut().and_then(Vec::pop) {
            sweep_dir(&d, &mut below);
        }
    }
    std::fs::OpenOptions::new()
        .write(true)
        .open(ledger)?
        .set_len(0)?;
    Ok(removed)
}

fn spawn_worker(sh: &Arc<Shared>) -> std::io::Result<()> {
    lock(&sh.state).threads += 1;
    let w = Arc::clone(sh);
    let r = thread::Builder::new()
        .name("gungnir-op".into())
        .spawn(move || worker(&w));
    if r.is_err() {
        lock(&sh.state).threads -= 1;
    }
    r.map(drop)
}

fn worker(sh: &Arc<Shared>) {
    let mut io = sh.make_io();
    loop {
        let op = {
            let mut s = lock(&sh.state);
            loop {
                if let Some(op) = s.queue.pop_front() {
                    s.running.push(Arc::clone(&op));
                    break op;
                }
                if s.shutdown {
                    s.threads -= 1;
                    return;
                }
                s = sh.work.wait(s).unwrap_or_else(PoisonError::into_inner);
            }
        };
        if !op.is_finished() {
            if !io.healthy() || ring_lost() {
                io = sh.make_io();
            }
            op.touch();
            let ledgered = matches!(op.req.kind, OpKind::Copy | OpKind::Move)
                && sh.ledger_begin(op.id, &op.req.dest);
            let r = run_op(sh, &mut *io, &op);
            // Its temp files are gone (renamed or removed) by the time run_op returns:
            // recorded before the client hears the op is done.
            if ledgered {
                sh.ledger_end(op.id);
            }
            if r.is_ok() {
                op.maybe_emit(true);
            }
            op.finish(r);
        }
        let mut s = lock(&sh.state);
        s.running.retain(|x| !Arc::ptr_eq(x, &op));
        if op.abandoned.load(Ordering::Acquire) {
            s.stuck -= 1;
        }
        // A replacement took this thread's place while it was stuck: leave.
        if s.threads - s.stuck > sh.cfg.workers.max(1) {
            s.threads -= 1;
            return;
        }
    }
}

fn watchdog(sh: &Arc<Shared>) {
    let mut s = lock(&sh.state);
    loop {
        if s.shutdown {
            return;
        }
        let now = Instant::now();
        let mut finish: Vec<(Arc<OpCtl>, OpError)> = Vec::new();
        // Queued ops: cancelled or out of time before a worker got to them.
        s.queue.retain(|op| {
            let why = match op.stopped() {
                Some(Stop::Cancelled) => Some(OpError::Cancelled),
                Some(Stop::TimedOut) => Some(OpError::TimedOut),
                None if now >= op.deadline => Some(OpError::TimedOut),
                None => None,
            };
            match why {
                Some(e) => {
                    finish.push((Arc::clone(op), e));
                    false
                }
                None => true,
            }
        });
        let mut abandon = 0usize;
        let mut suspects: Vec<Vec<u8>> = Vec::new();
        for op in &s.running {
            if op.is_finished() || op.abandoned.load(Ordering::Acquire) {
                continue;
            }
            let idle = now.duration_since(*lock(&op.last_progress));
            if op.stopped().is_none() && (now >= op.deadline || idle >= sh.cfg.stall) {
                op.request_stop(STOP_TIMEOUT);
            }
            let since = *lock(&op.stop_at);
            if let Some(t) = since
                && now.duration_since(t) >= sh.cfg.grace
            {
                // The worker did not come back: stuck in the kernel. Answer for it.
                op.abandoned.store(true, Ordering::Release);
                abandon += 1;
                let e = match op.stopped() {
                    Some(Stop::Cancelled) => OpError::Cancelled,
                    _ => {
                        suspects.push(op.req.src.clone());
                        if !op.req.dest.is_empty() {
                            suspects.push(op.req.dest.clone());
                        }
                        OpError::TimedOut
                    }
                };
                finish.push((Arc::clone(op), e));
            }
        }
        s.stuck += abandon;
        let mut spawn = 0;
        while s.threads + spawn < sh.cfg.max_threads
            && s.threads + spawn - s.stuck < sh.cfg.workers.max(1)
        {
            spawn += 1;
        }
        let busy = !s.queue.is_empty() || !s.running.is_empty();
        drop(s);
        for p in suspects {
            sh.mark_suspect(&p);
        }
        for (op, e) in finish {
            op.finish(Err(e));
        }
        for _ in 0..spawn {
            if spawn_worker(sh).is_err() {
                break;
            }
        }
        s = lock(&sh.state);
        let tick = if busy {
            Duration::from_millis(20)
        } else {
            Duration::from_secs(1)
        };
        s = sh
            .watch
            .wait_timeout(s, tick)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

// ---------------------------------------------------------------------------------------
// Running one op

fn run_op(sh: &Shared, io: &mut dyn Io, op: &OpCtl) -> OpResult {
    if let Some(s) = op.stopped() {
        return Err(StepError::Stop(s).into());
    }
    for p in [&op.req.src, &op.req.dest] {
        if !p.is_empty() && sh.blocked(p).is_some() {
            return Err(OpError::SuspectMount);
        }
    }
    let mut x = Exec {
        io,
        op,
        cfg: &sh.cfg,
        meta: &*sh.meta,
    };
    match op.req.kind {
        OpKind::Copy => x.copy(),
        OpKind::Move => x.mv(),
        OpKind::Delete => x.delete(),
        OpKind::DeleteTree => x.delete_tree(),
        OpKind::Fsync => x.fsync(),
    }
}

fn cstr(p: &[u8]) -> std::result::Result<CString, OpError> {
    CString::new(p).map_err(|_| OpError::BadRequest)
}

/// `(parent, leaf)` of a canonical absolute path other than "/".
fn split(p: &[u8]) -> std::result::Result<(CString, CString), OpError> {
    let i = p
        .iter()
        .rposition(|&b| b == b'/')
        .ok_or(OpError::BadRequest)?;
    let parent = if i == 0 { &b"/"[..] } else { &p[..i] };
    Ok((cstr(parent)?, cstr(&p[i + 1..])?))
}

fn is_type(st: &libc::statx, t: u32) -> bool {
    u32::from(st.stx_mode) & libc::S_IFMT == t
}

/// `b` is on another mount than `a`: a different mount id where the kernel reports one
/// (`STATX_MNT_ID`, Linux 5.8: this also sees bind mounts of the same filesystem, which
/// share `st_dev`), a mount root (`STATX_ATTR_MOUNT_ROOT`), or a different device.
fn other_mount(a: &libc::statx, b: &libc::statx) -> bool {
    let id = libc::STATX_MNT_ID;
    if a.stx_mask & id != 0 && b.stx_mask & id != 0 && a.stx_mnt_id != b.stx_mnt_id {
        return true;
    }
    let root = libc::STATX_ATTR_MOUNT_ROOT as u64;
    if b.stx_attributes_mask & root != 0 && b.stx_attributes & root != 0 {
        return true;
    }
    (a.stx_dev_major, a.stx_dev_minor) != (b.stx_dev_major, b.stx_dev_minor)
}

/// Entries a failed recursive delete remembers (to report exactly what it deleted);
/// beyond, deleted files are not reported and keep their (orphaned, harmless) metadata.
const DELETED_LOG_MAX: usize = 1 << 16;

fn same_file(a: &libc::statx, b: &libc::statx) -> bool {
    a.stx_ino == b.stx_ino
        && a.stx_dev_major == b.stx_dev_major
        && a.stx_dev_minor == b.stx_dev_minor
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn ts(t: &libc::statx_timestamp) -> libc::timespec {
    libc::timespec {
        tv_sec: t.tv_sec,
        tv_nsec: libc::c_long::from(t.tv_nsec),
    }
}

/// Closes a `DIR*` stream (and its fd) on drop.
struct DirStream(*mut libc::DIR);

impl DirStream {
    fn open(fd: OwnedFd) -> Step<Self> {
        let raw = fd.into_raw_fd();
        // SAFETY: `raw` is an open directory fd whose ownership passes to the stream.
        let d = unsafe { libc::fdopendir(raw) };
        if d.is_null() {
            let e = last_errno();
            // SAFETY: fdopendir failed, so the fd is still ours to close.
            drop(unsafe { OwnedFd::from_raw_fd(raw) });
            return Err(StepError::Os(e));
        }
        Ok(Self(d))
    }

    fn fd(&self) -> RawFd {
        // SAFETY: a live stream.
        unsafe { libc::dirfd(self.0) }
    }

    /// The next entry's name and `d_type`, `None` at the end.
    fn next(&mut self) -> Step<Option<(CString, u8)>> {
        loop {
            // SAFETY: resetting errno, then reading one entry of a live stream; the entry
            // stays valid until the next readdir on this stream, and is copied before.
            unsafe { *libc::__errno_location() = 0 };
            let e = unsafe { libc::readdir64(self.0) };
            if e.is_null() {
                let n = last_errno();
                return if n == 0 {
                    Ok(None)
                } else {
                    Err(StepError::Os(n))
                };
            }
            // SAFETY: d_name is NUL-terminated within the entry.
            let (name, ty) = unsafe { (CStr::from_ptr((*e).d_name.as_ptr()), (*e).d_type) };
            let b = name.to_bytes();
            if b == b"." || b == b".." {
                continue;
            }
            return Ok(Some((name.to_owned(), ty)));
        }
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: a live stream, closed once.
        unsafe { libc::closedir(self.0) };
    }
}

struct Exec<'a> {
    io: &'a mut dyn Io,
    op: &'a OpCtl,
    cfg: &'a OpsConfig,
    meta: &'a dyn MetaHooks,
}

impl Exec<'_> {
    fn flag(&self, f: u32) -> bool {
        self.op.req.flags & f != 0
    }

    fn check(&self) -> OpResult {
        match self.op.stopped() {
            Some(s) => Err(StepError::Stop(s).into()),
            None => Ok(()),
        }
    }

    /// The test hook: sleep in small slices, returning early on a stop.
    fn slow(&self) -> OpResult {
        let mut left = self.cfg.slow;
        while !left.is_zero() {
            self.check()?;
            let d = left.min(Duration::from_millis(10));
            thread::sleep(d);
            left -= d;
        }
        self.check()
    }

    /// The pause hook: hold here, alive for the watchdog, until the op is stopped.
    #[cfg(feature = "test-hooks")]
    fn pause(&self, at: PausePoint) -> OpResult {
        if self.cfg.pause_at != Some(at) {
            return Ok(());
        }
        eprintln!("gungnird: TEST HOOK: op paused at {at:?}");
        loop {
            self.op.touch();
            self.check()?;
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(not(feature = "test-hooks"))]
    #[allow(clippy::unused_self)]
    fn pause(&self, _at: PausePoint) -> OpResult {
        Ok(())
    }

    fn copy(&mut self) -> OpResult {
        let src = self.op.req.src.clone();
        let dest = self.op.req.dest.clone();
        let from = if self.flag(FLAG_ALL_METADATA) {
            self.meta.identify(&src)
        } else {
            None
        };
        self.copy_file(&src, &dest, self.op.req.flags, false)?;
        self.op.add_file();
        if let Some(id) = from {
            self.meta.copied(&id, &dest, false);
        }
        Ok(())
    }

    fn mv(&mut self) -> OpResult {
        let src = self.op.req.src.clone();
        let dest = self.op.req.dest.clone();
        let (cs, cd) = (cstr(&src)?, cstr(&dest)?);
        let st = self
            .io
            .statx(self.op, libc::AT_FDCWD, &cs, libc::AT_SYMLINK_NOFOLLOW)?;
        let overwrite = self.flag(FLAG_OVERWRITE);
        let r = if self.cfg.force_exdev {
            Err(StepError::Os(libc::EXDEV))
        } else {
            self.rename(libc::AT_FDCWD, &cs, libc::AT_FDCWD, &cd, overwrite)
        };
        match r {
            Ok(()) => {
                self.op.add_file();
                self.meta.moved(&src, &dest);
                Ok(())
            }
            Err(StepError::Os(libc::EXDEV)) => {
                if self.flag(FLAG_NO_FALLBACK_FOR_MOVE) {
                    return Err(OpError::Os(libc::EXDEV));
                }
                if is_type(&st, libc::S_IFDIR) {
                    return Err(OpError::WouldRecurse);
                }
                let from = self.meta.identify(&src);
                let flags = self.op.req.flags | FLAG_NOFOLLOW_SYMLINKS | FLAG_ALL_METADATA;
                self.copy_file(&src, &dest, flags, true)?;
                // The source goes only once the copy is durable: its data was fsynced
                // before the rename, and the rename itself is made durable here (fsync
                // of the destination directory); otherwise a crash could keep the
                // source's unlink and lose the copy's directory entry.
                let (parent, _) = split(&dest)?;
                let dir = self.io.open(
                    self.op,
                    libc::AT_FDCWD,
                    &parent,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                self.io.fsync(self.op, dir.as_raw_fd())?;
                // And only if it is still the file that was copied, unchanged: a file
                // renamed onto `src` or written to during the copy is kept (EBUSY; the
                // copy stays at `dest`).
                let now = self
                    .io
                    .statx(self.op, libc::AT_FDCWD, &cs, libc::AT_SYMLINK_NOFOLLOW)?;
                if !same_file(&now, &st)
                    || now.stx_size != st.stx_size
                    || (now.stx_mtime.tv_sec, now.stx_mtime.tv_nsec)
                        != (st.stx_mtime.tv_sec, st.stx_mtime.tv_nsec)
                {
                    return Err(OpError::Os(libc::EBUSY));
                }
                self.io.unlink(self.op, libc::AT_FDCWD, &cs, 0)?;
                self.op.add_file();
                match from {
                    Some(id) => self.meta.copied(&id, &dest, true),
                    None => self.meta.removed(&src, false),
                }
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// `renameat2`, with `RENAME_NOREPLACE` unless `overwrite`. A filesystem without
    /// `RENAME_NOREPLACE` (`EINVAL`) gets a check-then-rename (racy, but only there).
    fn rename(
        &mut self,
        od: RawFd,
        old: &CStr,
        nd: RawFd,
        new: &CStr,
        overwrite: bool,
    ) -> Step<()> {
        if overwrite {
            return self.io.rename(self.op, od, old, nd, new, 0);
        }
        match self
            .io
            .rename(self.op, od, old, nd, new, libc::RENAME_NOREPLACE)
        {
            Err(StepError::Os(libc::EINVAL)) => {
                match self.io.statx(self.op, nd, new, libc::AT_SYMLINK_NOFOLLOW) {
                    Ok(_) => Err(StepError::Os(libc::EEXIST)),
                    Err(StepError::Os(libc::ENOENT)) => {
                        self.io.rename(self.op, od, old, nd, new, 0)
                    }
                    Err(e) => Err(e),
                }
            }
            r => r,
        }
    }

    /// Copy one non-directory `src` to `dest` through a temporary file in `dest`'s
    /// directory. `durable`: fsync before the rename (a move's copy; always done when
    /// an existing file is replaced).
    fn copy_file(&mut self, src: &[u8], dest: &[u8], flags: u32, durable: bool) -> OpResult {
        let nofollow = flags & FLAG_NOFOLLOW_SYMLINKS != 0;
        let overwrite = flags & FLAG_OVERWRITE != 0;
        let cs = cstr(src)?;
        let st = self.io.statx(
            self.op,
            libc::AT_FDCWD,
            &cs,
            if nofollow {
                libc::AT_SYMLINK_NOFOLLOW
            } else {
                0
            },
        )?;
        if is_type(&st, libc::S_IFDIR) {
            return Err(OpError::WouldRecurse);
        }
        let symlink = is_type(&st, libc::S_IFLNK);
        if !symlink && !is_type(&st, libc::S_IFREG) {
            return Err(OpError::Os(libc::EOPNOTSUPP)); // FIFOs, devices, sockets
        }
        let (parent, leaf) = split(dest)?;
        let pdir = self.io.open(
            self.op,
            libc::AT_FDCWD,
            &parent,
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )?;
        let existing =
            match self
                .io
                .statx(self.op, pdir.as_raw_fd(), &leaf, libc::AT_SYMLINK_NOFOLLOW)
            {
                Ok(d) => Some(d),
                Err(StepError::Os(libc::ENOENT)) => None,
                Err(e) => return Err(e.into()),
            };
        if let Some(d) = &existing {
            if !overwrite {
                return Err(OpError::Os(libc::EEXIST));
            }
            if is_type(d, libc::S_IFDIR) {
                return Err(OpError::Os(libc::EISDIR));
            }
            if same_file(d, &st) {
                return Err(OpError::Os(libc::EINVAL));
            }
        }
        if symlink {
            return self.copy_symlink(&cs, &st, pdir.as_raw_fd(), &leaf, overwrite);
        }
        let in_fd = self.io.open(
            self.op,
            libc::AT_FDCWD,
            &cs,
            libc::O_RDONLY | libc::O_NOCTTY | if nofollow { libc::O_NOFOLLOW } else { 0 },
            0,
        )?;
        // Re-check what was actually opened (the path may have changed since the statx).
        let fst = self
            .io
            .statx(self.op, in_fd.as_raw_fd(), c"", libc::AT_EMPTY_PATH)?;
        if is_type(&fst, libc::S_IFDIR) {
            return Err(OpError::WouldRecurse);
        }
        if !is_type(&fst, libc::S_IFREG) {
            return Err(OpError::Os(libc::EOPNOTSUPP));
        }
        let mode = if flags & FLAG_TARGET_DEFAULT_PERMS != 0 {
            0o666
        } else {
            0o600
        };
        let (tmp, out) = self.create_temp(pdir.as_raw_fd(), mode)?;
        let r = (|| -> OpResult {
            self.copy_data(in_fd.as_raw_fd(), out.as_raw_fd(), fst.stx_size)?;
            self.finish_attrs(in_fd.as_raw_fd(), out.as_raw_fd(), &fst, flags);
            if durable || existing.is_some() {
                self.io.fsync(self.op, out.as_raw_fd())?;
            }
            self.check()?;
            self.pause(PausePoint::BeforePublish)?;
            self.rename(pdir.as_raw_fd(), &tmp, pdir.as_raw_fd(), &leaf, overwrite)?;
            Ok(())
        })();
        drop(out);
        if r.is_err() {
            // Plain syscall: the engine may be stopped or poisoned by now.
            // SAFETY: valid dir fd and NUL-terminated name.
            unsafe { libc::unlinkat(pdir.as_raw_fd(), tmp.as_ptr(), 0) };
        }
        r
    }

    /// Create `.gungnir-<op id>-<n>.tmp` in `dir` (`O_EXCL`).
    fn create_temp(
        &mut self,
        dir: RawFd,
        mode: u32,
    ) -> std::result::Result<(CString, OwnedFd), OpError> {
        for n in 0..16 {
            let name = cstr(format!(".gungnir-{:016x}-{n}.tmp", self.op.id).as_bytes())?;
            match self.io.open(
                self.op,
                dir,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                mode,
            ) {
                Ok(fd) => return Ok((name, fd)),
                Err(StepError::Os(libc::EEXIST)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(OpError::Os(libc::EEXIST))
    }

    fn copy_symlink(
        &mut self,
        src: &CStr,
        st: &libc::statx,
        dir: RawFd,
        leaf: &CStr,
        overwrite: bool,
    ) -> OpResult {
        let mut buf = vec![0u8; 4096];
        // SAFETY: writes at most buf.len() bytes into `buf`.
        let n = unsafe {
            libc::readlinkat(
                libc::AT_FDCWD,
                src.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(OpError::Os(last_errno()));
        }
        buf.truncate(n as usize);
        let target = cstr(&buf)?;
        for i in 0..16 {
            let tmp = cstr(format!(".gungnir-{:016x}-l{i}.tmp", self.op.id).as_bytes())?;
            match self.io.symlink(self.op, &target, dir, &tmp) {
                Ok(()) => {
                    let times = [ts(&st.stx_atime), ts(&st.stx_mtime)];
                    // SAFETY: valid names and a two-element timespec array.
                    unsafe {
                        libc::utimensat(
                            dir,
                            tmp.as_ptr(),
                            times.as_ptr(),
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    };
                    let r = self.rename(dir, &tmp, dir, leaf, overwrite);
                    if r.is_err() {
                        // SAFETY: valid dir fd and name.
                        unsafe { libc::unlinkat(dir, tmp.as_ptr(), 0) };
                    }
                    return r.map_err(Into::into);
                }
                Err(StepError::Os(libc::EEXIST)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(OpError::Os(libc::EEXIST))
    }

    /// The data of a regular file: reflink, else its data segments (holes skipped) by
    /// `copy_file_range`, else by engine read/write; then the size.
    fn copy_data(&mut self, src: RawFd, dst: RawFd, size: u64) -> OpResult {
        self.op.set_total(size);
        let isize = i64::try_from(size).map_err(|_| OpError::Os(libc::EFBIG))?;
        if size > 0 && !self.cfg.no_clone && !self.cfg.force_exdev {
            self.slow()?;
            // SAFETY: FICLONE takes the source fd as its argument.
            if unsafe { libc::ioctl(dst, libc::FICLONE, src) } == 0 {
                self.op.add_bytes(size);
                return Ok(());
            }
            match last_errno() {
                libc::EXDEV
                | libc::EOPNOTSUPP
                | libc::ENOTTY
                | libc::EINVAL
                | libc::EPERM
                | libc::EBADF
                | libc::ETXTBSY
                | libc::ENOSYS => {}
                e => return Err(OpError::Os(e)),
            }
        }
        let mut cfr = !self.cfg.no_cfr && !self.cfg.force_exdev;
        let mut pos: i64 = 0;
        let mut eof: Option<i64> = None;
        while pos < isize && eof.is_none() {
            self.check()?;
            // SAFETY: plain lseek on an fd.
            let data = unsafe { libc::lseek(src, pos, libc::SEEK_DATA) };
            let data = if data < 0 {
                match last_errno() {
                    libc::ENXIO => isize, // only a hole is left
                    libc::EINVAL | libc::EOPNOTSUPP => pos,
                    e => return Err(OpError::Os(e)),
                }
            } else {
                data.min(isize)
            };
            if data > pos {
                self.op.add_bytes((data - pos) as u64);
            }
            if data >= isize {
                break;
            }
            // SAFETY: plain lseek on an fd.
            let hole = unsafe { libc::lseek(src, data, libc::SEEK_HOLE) };
            let hole = if hole < 0 || hole <= data {
                isize
            } else {
                hole.min(isize)
            };
            eof = self.copy_range(src, dst, data, hole, &mut cfr)?;
            pos = hole;
        }
        let len = eof.unwrap_or(isize);
        // SAFETY: plain ftruncate on our own new file.
        if unsafe { libc::ftruncate(dst, len) } != 0 {
            return Err(OpError::Os(last_errno()));
        }
        Ok(())
    }

    /// Copy `[start, end)`. Returns `Some(offset)` if the source ended early (it shrank
    /// while being copied).
    fn copy_range(
        &mut self,
        src: RawFd,
        dst: RawFd,
        start: i64,
        end: i64,
        cfr: &mut bool,
    ) -> std::result::Result<Option<i64>, OpError> {
        let mut off = start;
        while off < end {
            self.slow()?;
            if off > start {
                self.pause(PausePoint::MidCopy)?;
            }
            let left = (end - off) as u64;
            if *cfr {
                let want = left.min(self.cfg.cfr_chunk.max(4096) as u64) as usize;
                let (mut so, mut doff) = (off, off);
                // SAFETY: valid fds and offset pointers.
                let n =
                    unsafe { libc::copy_file_range(src, &raw mut so, dst, &raw mut doff, want, 0) };
                if n > 0 {
                    off += n as i64;
                    self.op.add_bytes(n as u64);
                    continue;
                }
                if n == 0 {
                    *cfr = false; // EOF here, or a filesystem that copies nothing: read/write decides
                    continue;
                }
                match last_errno() {
                    libc::EINTR => {}
                    // Not possible between these two files: read/write from here on.
                    libc::EXDEV
                    | libc::EINVAL
                    | libc::EOPNOTSUPP
                    | libc::ENOSYS
                    | libc::EBADF
                    | libc::EPERM
                    | libc::ETXTBSY => *cfr = false,
                    e => return Err(OpError::Os(e)),
                }
                continue;
            }
            let want = (left as usize).min(self.io.buf_len());
            let n = self.io.read(self.op, src, want, off as u64)?;
            if n == 0 {
                return Ok(Some(off));
            }
            let mut done = 0usize;
            while done < n {
                let m = self
                    .io
                    .write(self.op, dst, done, n - done, (off as u64) + done as u64)?;
                if m == 0 {
                    return Err(OpError::Os(libc::EIO));
                }
                done += m;
            }
            off += n as i64;
            self.op.add_bytes(n as u64);
        }
        Ok(None)
    }

    /// Mode, extended attributes (`ALL_METADATA`, best effort) and timestamps (last: the
    /// other steps would touch them).
    fn finish_attrs(&mut self, src: RawFd, dst: RawFd, st: &libc::statx, flags: u32) {
        if flags & FLAG_ALL_METADATA != 0 {
            copy_xattrs(src, dst);
        }
        if flags & FLAG_TARGET_DEFAULT_PERMS == 0 {
            // setuid/setgid are not carried over to a copy.
            let mode = u32::from(st.stx_mode) & 0o1777;
            // SAFETY: plain fchmod on our own file.
            unsafe { libc::fchmod(dst, mode) };
        }
        if flags & FLAG_TARGET_DEFAULT_MODIFIED_TIME == 0 {
            let times = [ts(&st.stx_atime), ts(&st.stx_mtime)];
            // SAFETY: a two-element timespec array.
            unsafe { libc::futimens(dst, times.as_ptr()) };
        }
    }

    fn delete(&mut self) -> OpResult {
        let p = self.op.req.src.clone();
        let c = cstr(&p)?;
        let st = self
            .io
            .statx(self.op, libc::AT_FDCWD, &c, libc::AT_SYMLINK_NOFOLLOW)?;
        let flags = if is_type(&st, libc::S_IFDIR) {
            libc::AT_REMOVEDIR
        } else {
            0
        };
        self.io.unlink(self.op, libc::AT_FDCWD, &c, flags)?;
        self.op.add_file();
        self.meta.removed(&p, false);
        Ok(())
    }

    /// Delete `src` and everything below it, without following symlinks or crossing
    /// into another mount (`EXDEV`).
    fn delete_tree(&mut self) -> OpResult {
        let p = self.op.req.src.clone();
        let c = cstr(&p)?;
        let st = self
            .io
            .statx(self.op, libc::AT_FDCWD, &c, libc::AT_SYMLINK_NOFOLLOW)?;
        if !is_type(&st, libc::S_IFDIR) {
            self.io.unlink(self.op, libc::AT_FDCWD, &c, 0)?;
            self.op.add_file();
            self.meta.removed(&p, false);
            return Ok(());
        }
        // A mount point as the root is a crossing too: emptying it would delete files on
        // the other filesystem, then fail with EBUSY on the root itself (DIB-F001).
        if let Some(at) = p.iter().rposition(|&b| b == b'/') {
            let parent = cstr(if at == 0 { b"/" } else { &p[..at] })?;
            let up = self.io.statx(self.op, libc::AT_FDCWD, &parent, 0)?; // the directory, through any link
            if other_mount(&up, &st) {
                return Err(OpError::Os(libc::EXDEV));
            }
        }
        let mut log = Vec::new();
        let r = self.empty_tree(&c, &st, &mut log).and_then(|()| {
            self.io
                .unlink(self.op, libc::AT_FDCWD, &c, libc::AT_REMOVEDIR)
                .map_err(Into::into)
        });
        if r.is_ok() {
            self.op.add_file();
            self.meta.removed(&p, true);
        } else if !log.is_empty() {
            // Failed part-way: what was deleted is gone, everything else is still there
            // and keeps its metadata.
            self.meta.removed_paths(&log);
        }
        r
    }

    /// Delete everything below `root`, logging each deleted entry's path (`true`: a
    /// directory, with its subtree) so a failure can report exactly what went.
    fn empty_tree(
        &mut self,
        root: &CStr,
        root_st: &libc::statx,
        log: &mut Vec<(Vec<u8>, bool)>,
    ) -> OpResult {
        let fd = self.io.open(
            self.op,
            libc::AT_FDCWD,
            root,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )?;
        // The mount every directory below must be on: the opened root's own (by fd, so
        // a directory swapped in after the path statx is what is compared against).
        let base = self
            .io
            .statx(self.op, fd.as_raw_fd(), c"", libc::AT_EMPTY_PATH)?;
        if !same_file(&base, root_st) {
            return Err(OpError::Os(libc::EBUSY)); // replaced since the statx
        }
        let mut cur: Vec<u8> = root.to_bytes().to_vec();
        // (stream, its name in the parent, log length when it was entered)
        let mut stack: Vec<(DirStream, CString, usize)> =
            vec![(DirStream::open(fd)?, CString::default(), 0)];
        let note = |log: &mut Vec<(Vec<u8>, bool)>, cur: &[u8], name: &CStr, tree: bool| {
            if log.len() < DELETED_LOG_MAX {
                log.push(([cur, b"/", name.to_bytes()].concat(), tree));
            }
        };
        loop {
            self.slow()?;
            let Some((top, _, _)) = stack.last_mut() else {
                return Ok(());
            };
            let top_fd = top.fd();
            match top.next()? {
                None => {
                    let Some((_, name, mark)) = stack.pop() else {
                        return Ok(());
                    };
                    let Some((parent, _, _)) = stack.last() else {
                        return Ok(()); // the root itself: removed by the caller
                    };
                    self.io
                        .unlink(self.op, parent.fd(), &name, libc::AT_REMOVEDIR)?;
                    self.op.add_file();
                    // Its whole subtree is gone: one entry instead of its contents.
                    cur.truncate(cur.len() - name.to_bytes().len() - 1);
                    log.truncate(mark);
                    note(log, &cur, &name, true);
                }
                Some((name, ty)) => {
                    let is_dir = match ty {
                        libc::DT_DIR => true,
                        libc::DT_UNKNOWN => {
                            let s =
                                self.io
                                    .statx(self.op, top_fd, &name, libc::AT_SYMLINK_NOFOLLOW)?;
                            is_type(&s, libc::S_IFDIR)
                        }
                        _ => false,
                    };
                    if !is_dir {
                        self.io.unlink(self.op, top_fd, &name, 0)?;
                        self.op.add_file();
                        note(log, &cur, &name, false);
                        continue;
                    }
                    if stack.len() >= MAX_DEPTH {
                        return Err(OpError::Os(libc::ELOOP));
                    }
                    let fd = self.io.open(
                        self.op,
                        top_fd,
                        &name,
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                        0,
                    )?;
                    let s = self
                        .io
                        .statx(self.op, fd.as_raw_fd(), c"", libc::AT_EMPTY_PATH)?;
                    if other_mount(&base, &s) {
                        return Err(OpError::Os(libc::EXDEV)); // a mount point inside the tree
                    }
                    let mark = log.len();
                    cur.push(b'/');
                    cur.extend_from_slice(name.to_bytes());
                    stack.push((DirStream::open(fd)?, name, mark));
                }
            }
        }
    }

    fn fsync(&mut self) -> OpResult {
        let c = cstr(&self.op.req.src)?;
        let fd = self.io.open(
            self.op,
            libc::AT_FDCWD,
            &c,
            libc::O_RDONLY | libc::O_NOCTTY,
            0,
        )?;
        self.io.fsync(self.op, fd.as_raw_fd())?;
        self.op.add_file();
        Ok(())
    }
}

/// Copy every extended attribute we can read and write; errors are skipped.
fn copy_xattrs(src: RawFd, dst: RawFd) {
    let mut names = vec![0u8; XATTR_MAX];
    // SAFETY: writes at most names.len() bytes.
    let n = unsafe { libc::flistxattr(src, names.as_mut_ptr().cast(), names.len()) };
    if n <= 0 {
        return;
    }
    names.truncate(n as usize);
    let mut value = vec![0u8; XATTR_MAX];
    for name in names.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        let Ok(cname) = CString::new(name) else {
            continue;
        };
        // SAFETY: valid name, writes at most value.len() bytes.
        let len =
            unsafe { libc::fgetxattr(src, cname.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
        if len < 0 {
            continue;
        }
        // SAFETY: valid name and `len` readable bytes.
        unsafe { libc::fsetxattr(dst, cname.as_ptr(), value.as_ptr().cast(), len as usize, 0) };
    }
}

/// Bytes of a statx-reported block count (tests).
#[must_use]
pub fn allocated_bytes(st: &libc::statx) -> u64 {
    st.stx_blocks.saturating_mul(512)
}

#[cfg(test)]
mod tests;
