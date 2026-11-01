//! The two I/O engines behind the file operations (milestone 8): [`UringIo`] submits
//! every step that io_uring has an opcode for (open, statx, read, write, fsync, unlink,
//! rename, mkdir, symlink) to a per-worker ring and waits for it in short slices, so a
//! cancel or a deadline is noticed even while the kernel is stuck on a hung mount;
//! [`SyncIo`] makes the same calls as plain syscalls (the fallback when io_uring is
//! disabled, refused by seccomp or a container, or `GUNGNIR_NO_URING=1`).
//!
//! Memory the kernel may still write after an abandoned io_uring request (the data
//! buffer, the statx buffer, the path copies) belongs to the engine, never to the caller.
//! An engine that had to abandon a request is poisoned: its ring and buffers move to a
//! graveyard (the kernel may complete the request at any later time) and the worker
//! builds a new one. A graveyard ring is freed once its request's completion shows up;
//! while [`GRAVEYARD_MAX`] are still waiting, new workers get plain syscalls instead.

use std::{
    ffi::{CStr, CString},
    io, mem,
    os::fd::{FromRawFd, OwnedFd, RawFd},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use io_uring::{IoUring, Probe, opcode, register::Restriction, types};

/// Which engine runs the steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Uring,
    Threads,
}

/// Why a step stopped early: the caller's cancel or deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Cancelled,
    TimedOut,
}

/// A step failed: an errno, or a stop request seen while it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepError {
    Os(i32),
    Stop(Stop),
}

impl From<io::Error> for StepError {
    fn from(e: io::Error) -> Self {
        StepError::Os(e.raw_os_error().unwrap_or(libc::EIO))
    }
}

pub type Step<T> = std::result::Result<T, StepError>;

/// What a step polls while it waits: has the op been cancelled or run out of time?
pub trait Watch {
    fn stopped(&self) -> Option<Stop>;
}

/// The steps an operation is made of. Path arguments are relative to `dir`
/// (`libc::AT_FDCWD` for absolute paths).
pub trait Io: Send {
    fn kind(&self) -> EngineKind;
    /// False once the engine abandoned a request; the worker replaces it.
    fn healthy(&self) -> bool {
        true
    }
    fn open(
        &mut self,
        w: &dyn Watch,
        dir: RawFd,
        path: &CStr,
        flags: i32,
        mode: u32,
    ) -> Step<OwnedFd>;
    /// `statx` with `flags` (`AT_SYMLINK_NOFOLLOW`, `AT_EMPTY_PATH`, ...).
    fn statx(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, flags: i32) -> Step<libc::statx>;
    /// Read up to `len` bytes at `off` into the engine's buffer; returns how many.
    fn read(&mut self, w: &dyn Watch, fd: RawFd, len: usize, off: u64) -> Step<usize>;
    /// Write the engine buffer's `[start, start + len)` at `off`; returns how many bytes
    /// were written.
    fn write(
        &mut self,
        w: &dyn Watch,
        fd: RawFd,
        start: usize,
        len: usize,
        off: u64,
    ) -> Step<usize>;
    /// The engine's data buffer (filled by `read`, drained by `write`).
    fn buf_len(&self) -> usize;
    fn fsync(&mut self, w: &dyn Watch, fd: RawFd) -> Step<()>;
    fn unlink(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, flags: i32) -> Step<()>;
    #[allow(clippy::too_many_arguments)]
    fn rename(
        &mut self,
        w: &dyn Watch,
        old_dir: RawFd,
        old: &CStr,
        new_dir: RawFd,
        new: &CStr,
        flags: u32,
    ) -> Step<()>;
    fn mkdir(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, mode: u32) -> Step<()>;
    fn symlink(&mut self, w: &dyn Watch, target: &CStr, dir: RawFd, path: &CStr) -> Step<()>;
}

fn errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn check(w: &dyn Watch) -> Step<()> {
    match w.stopped() {
        Some(s) => Err(StepError::Stop(s)),
        None => Ok(()),
    }
}

/// Retry a syscall returning -1/errno on `EINTR`.
fn sys(mut f: impl FnMut() -> libc::c_long) -> Step<libc::c_long> {
    loop {
        let r = f();
        if r >= 0 {
            return Ok(r);
        }
        let e = errno();
        if e != libc::EINTR {
            return Err(StepError::Os(e));
        }
    }
}

/// An all-zero `statx` buffer.
#[must_use]
pub fn zero_statx() -> libc::statx {
    // SAFETY: statx is plain old data; all-zero is a valid value.
    unsafe { mem::zeroed() }
}

/// Mask every `statx` call asks for.
pub const STATX_WANT: u32 = libc::STATX_TYPE
    | libc::STATX_MODE
    | libc::STATX_INO
    | libc::STATX_SIZE
    | libc::STATX_BLOCKS
    | libc::STATX_ATIME
    | libc::STATX_MTIME
    | libc::STATX_MNT_ID;

// ---------------------------------------------------------------------------------------
// Plain syscalls

/// The thread-pool fallback: every step is a direct syscall on the worker thread. A
/// step stuck in the kernel keeps its thread; the scheduler's watchdog answers for it.
pub struct SyncIo {
    buf: Vec<u8>,
}

impl SyncIo {
    #[must_use]
    pub fn new(buf_size: usize) -> Self {
        Self {
            buf: vec![0u8; buf_size.max(4096)],
        }
    }
}

impl Io for SyncIo {
    fn kind(&self) -> EngineKind {
        EngineKind::Threads
    }

    fn open(
        &mut self,
        w: &dyn Watch,
        dir: RawFd,
        path: &CStr,
        flags: i32,
        mode: u32,
    ) -> Step<OwnedFd> {
        check(w)?;
        // SAFETY: `path` is NUL-terminated and outlives the call.
        let fd = sys(|| unsafe {
            libc::c_long::from(libc::openat(
                dir,
                path.as_ptr(),
                flags | libc::O_CLOEXEC,
                mode,
            ))
        })?;
        // SAFETY: a fresh fd returned by openat, owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    fn statx(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, flags: i32) -> Step<libc::statx> {
        check(w)?;
        let mut st = zero_statx();
        // SAFETY: valid path and output buffer.
        sys(|| unsafe {
            libc::c_long::from(libc::statx(
                dir,
                path.as_ptr(),
                flags | libc::AT_STATX_SYNC_AS_STAT,
                STATX_WANT,
                &raw mut st,
            ))
        })?;
        Ok(st)
    }

    fn read(&mut self, w: &dyn Watch, fd: RawFd, len: usize, off: u64) -> Step<usize> {
        check(w)?;
        let len = len.min(self.buf.len());
        let off = i64::try_from(off).map_err(|_| StepError::Os(libc::EFBIG))?;
        let p = self.buf.as_mut_ptr();
        // SAFETY: writes at most `len` bytes into our own buffer.
        let n = sys(|| unsafe { libc::pread(fd, p.cast(), len, off) as libc::c_long })?;
        Ok(n as usize)
    }

    fn write(
        &mut self,
        w: &dyn Watch,
        fd: RawFd,
        start: usize,
        len: usize,
        off: u64,
    ) -> Step<usize> {
        check(w)?;
        let data = self.buf.get(start..).ok_or(StepError::Os(libc::EINVAL))?;
        let len = len.min(data.len());
        let off = i64::try_from(off).map_err(|_| StepError::Os(libc::EFBIG))?;
        let p = data.as_ptr();
        // SAFETY: reads at most `len` bytes from our own buffer.
        let n = sys(|| unsafe { libc::pwrite(fd, p.cast(), len, off) as libc::c_long })?;
        Ok(n as usize)
    }

    fn buf_len(&self) -> usize {
        self.buf.len()
    }

    fn fsync(&mut self, w: &dyn Watch, fd: RawFd) -> Step<()> {
        check(w)?;
        // SAFETY: plain syscall on an fd.
        sys(|| unsafe { libc::c_long::from(libc::fsync(fd)) }).map(drop)
    }

    fn unlink(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, flags: i32) -> Step<()> {
        check(w)?;
        // SAFETY: valid NUL-terminated path.
        sys(|| unsafe { libc::c_long::from(libc::unlinkat(dir, path.as_ptr(), flags)) }).map(drop)
    }

    fn rename(
        &mut self,
        w: &dyn Watch,
        old_dir: RawFd,
        old: &CStr,
        new_dir: RawFd,
        new: &CStr,
        flags: u32,
    ) -> Step<()> {
        check(w)?;
        // SAFETY: valid NUL-terminated paths.
        sys(|| unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_dir,
                old.as_ptr(),
                new_dir,
                new.as_ptr(),
                flags,
            )
        })
        .map(drop)
    }

    fn mkdir(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, mode: u32) -> Step<()> {
        check(w)?;
        // SAFETY: valid NUL-terminated path.
        sys(|| unsafe { libc::c_long::from(libc::mkdirat(dir, path.as_ptr(), mode)) }).map(drop)
    }

    fn symlink(&mut self, w: &dyn Watch, target: &CStr, dir: RawFd, path: &CStr) -> Step<()> {
        check(w)?;
        // SAFETY: valid NUL-terminated strings.
        sys(|| unsafe { libc::c_long::from(libc::symlinkat(target.as_ptr(), dir, path.as_ptr())) })
            .map(drop)
    }
}

// ---------------------------------------------------------------------------------------
// io_uring

/// How long one wait for a completion lasts before the stop flags are re-checked.
const SLICE: Duration = Duration::from_millis(50);
/// How long an `ASYNC_CANCEL` may take before the request is abandoned.
const CANCEL_WAIT: Duration = Duration::from_millis(100);
const RING_ENTRIES: u32 = 8;
const USER_OP: u64 = 1;
const USER_CANCEL: u64 = 2;

/// Opcodes [`UringIo`] needs; a kernel missing any of them gets the thread pool.
const NEEDED: [u8; 10] = [
    opcode::Nop::CODE,
    opcode::OpenAt::CODE,
    opcode::Statx::CODE,
    opcode::Read::CODE,
    opcode::Write::CODE,
    opcode::Fsync::CODE,
    opcode::UnlinkAt::CODE,
    opcode::RenameAt::CODE,
    opcode::MkDirAt::CODE,
    opcode::AsyncCancel::CODE,
];

/// Opcodes a ring accepts: [`NEEDED`] plus `TIMEOUT` (tests). Every ring is created
/// disabled, restricted to these, then enabled, so a sandboxed daemon's rings cannot be
/// driven to do anything else (D-044 item 1).
/// `IORING_REGISTER_ENABLE_RINGS` (uapi io_uring.h): the only register rule a ring gets.
const REGISTER_ENABLE_RINGS: u8 = 12;

const ALLOWED: [u8; 11] = [
    opcode::Nop::CODE,
    opcode::OpenAt::CODE,
    opcode::Statx::CODE,
    opcode::Read::CODE,
    opcode::Write::CODE,
    opcode::Fsync::CODE,
    opcode::UnlinkAt::CODE,
    opcode::RenameAt::CODE,
    opcode::MkDirAt::CODE,
    opcode::AsyncCancel::CODE,
    opcode::Timeout::CODE,
];

/// A ring that accepts only [`ALLOWED`] opcodes, no SQE flags and no registrations:
/// created with `IORING_SETUP_R_DISABLED`, restricted, then enabled.
///
/// # Errors
/// The kernel cannot create, restrict or enable it (restrictions need Linux 5.10).
pub fn restricted_ring() -> io::Result<IoUring> {
    let ring = IoUring::builder().setup_r_disabled().build(RING_ENTRIES)?;
    let mut res: Vec<Restriction> = ALLOWED.iter().map(|&op| Restriction::sqe_op(op)).collect();
    res.push(Restriction::sqe_flags_allowed(0));
    // Newer kernels (seen on 7.2, not on 6.12) police io_uring_register only when a
    // register rule exists. Name the one op that is spent by the enable just below, so
    // nothing can be registered on an enabled ring, on old kernels and new alike.
    res.push(Restriction::register_op(REGISTER_ENABLE_RINGS));
    ring.submitter().register_restrictions(&mut res)?;
    ring.submitter().register_enable_rings()?;
    Ok(ring)
}

/// Rings created before the seccomp filter is installed, for workers started after it
/// (the filter refuses `io_uring_setup`). Once [`prepare_sandbox_rings`] has run, rings
/// come only from here; when it is empty, new workers use plain syscalls.
static POOL: Mutex<Vec<IoUring>> = Mutex::new(Vec::new());
static POOL_ONLY: AtomicBool = AtomicBool::new(false);

/// Create `n` restricted rings for workers started after the sandbox is installed, and
/// make the pool the only ring source from now on.
///
/// # Errors
/// A ring could not be created; the pool is left empty and ring creation unchanged.
pub fn prepare_sandbox_rings(n: usize) -> io::Result<()> {
    let mut rings = Vec::with_capacity(n);
    for _ in 0..n {
        rings.push(restricted_ring()?);
    }
    *POOL.lock().unwrap_or_else(PoisonError::into_inner) = rings;
    POOL_ONLY.store(true, Ordering::SeqCst);
    Ok(())
}

/// Whether rings come only from the pool: a sandboxed daemon, which cannot make new ones.
#[must_use]
pub fn sandbox_rings_only() -> bool {
    POOL_ONLY.load(Ordering::SeqCst)
}

fn new_ring() -> io::Result<IoUring> {
    if POOL_ONLY.load(Ordering::SeqCst) {
        return POOL
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .ok_or_else(|| io::Error::other("no pre-created io_uring ring left (sandboxed)"));
    }
    restricted_ring()
}

/// Abandoned engines still waiting for the kernel to complete their request.
static GRAVEYARD: Mutex<Vec<(IoUring, Box<Owned>)>> = Mutex::new(Vec::new());
/// Most abandoned rings kept waiting; beyond, new workers use plain syscalls (a mount
/// stuck that often would only keep pinning 1 MiB buffers).
pub const GRAVEYARD_MAX: usize = 16;

/// Free every abandoned ring whose request has completed: the kernel no longer
/// references its buffers. Returns how many are still waiting.
pub fn reap() -> usize {
    let mut late = Vec::new();
    let left = {
        let mut g = GRAVEYARD.lock().unwrap_or_else(PoisonError::into_inner);
        g.retain_mut(|(ring, owned)| {
            let Some(c) = ring.completion().find(|c| c.user_data() == USER_OP) else {
                return true;
            };
            // An open that finished after all: nobody is left to own its descriptor.
            if owned.opening && c.result() >= 0 {
                late.push(c.result());
            }
            false
        });
        g.len()
    };
    close_late(late);
    left
}

/// Descriptors waiting for the one closing thread, and whether it is running.
static LATE: Mutex<(Vec<RawFd>, bool)> = Mutex::new((Vec::new(), false));

/// A close can block for as long as the mount does (FUSE flushes on close): never on the
/// caller, who may hold the scheduler. One thread does them all, so a mount that hangs
/// every close costs that one thread and a list of numbers, not a thread each. With no
/// thread to be had they wait for the next call.
fn close_late(fds: Vec<RawFd>) {
    let mut g = LATE.lock().unwrap_or_else(PoisonError::into_inner);
    g.0.extend(fds);
    if g.1 || g.0.is_empty() {
        return;
    }
    let started = std::thread::Builder::new()
        .name("gungnir-close".into())
        .spawn(|| {
            loop {
                let fd = {
                    let mut g = LATE.lock().unwrap_or_else(PoisonError::into_inner);
                    let Some(fd) = g.0.pop() else {
                        g.1 = false;
                        return;
                    };
                    fd
                };
                // SAFETY: a fresh descriptor nothing else has seen.
                drop(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        });
    g.1 = started.is_ok();
}

/// Memory a request may reference until the kernel completes it.
struct Owned {
    buf: Vec<u8>,
    st: libc::statx,
    path_a: CString,
    path_b: CString,
    /// The request in flight returns a descriptor.
    opening: bool,
}

pub struct UringIo {
    ring: Option<IoUring>,
    owned: Option<Box<Owned>>,
    buf_size: usize,
}

/// Check that io_uring is usable here: the ring can be created (not `ENOSYS` from an
/// old kernel or seccomp, not `EPERM` from `io_uring_disabled` or a container policy),
/// every opcode the engine uses is supported, and a NOP completes within 1 s (some
/// sandboxes allow `io_uring_setup` but not `io_uring_enter`), on a restricted ring
/// like the ones the engine uses.
///
/// # Errors
/// Why it is not usable.
pub fn probe() -> io::Result<()> {
    let ring = IoUring::new(RING_ENTRIES)?;
    let mut p = Probe::new();
    ring.submitter().register_probe(&mut p)?;
    if let Some(op) = NEEDED.iter().find(|&&op| !p.is_supported(op)) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("io_uring opcode {op} not supported"),
        ));
    }
    drop(ring);
    let mut ring = restricted_ring()?;
    let nop = opcode::Nop::new().build().user_data(USER_OP);
    // SAFETY: a NOP references no memory.
    unsafe { ring.submission().push(&nop) }.map_err(|_| io::Error::other("sq full"))?;
    let ts = types::Timespec::new().sec(1);
    let args = types::SubmitArgs::new().timespec(&ts);
    match ring.submitter().submit_with_args(1, &args) {
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(libc::ETIME) => {}
        Err(e) => return Err(e),
    }
    match ring.completion().next() {
        Some(c) if c.result() >= 0 => Ok(()),
        Some(c) => Err(io::Error::from_raw_os_error(-c.result())),
        None => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "io_uring NOP did not complete",
        )),
    }
}

/// Set (to anything but "" or "0") where io_uring must work, e.g. the CI job that tests
/// the io_uring engine: tests then fail instead of skipping when it is unavailable.
pub const REQUIRE_URING_ENV: &str = "GUNGNIR_REQUIRE_URING";

/// Whether a test may use the io_uring engine here: `true` if [`probe`] passes. If it
/// fails, `Err` with the reason when [`REQUIRE_URING_ENV`] is set (the test must fail),
/// else `Ok(false)` after a skip note on stderr. `require` is the variable's value.
///
/// # Errors
/// io_uring is unavailable and required.
pub fn uring_for_tests(what: &str, require: Option<&std::ffi::OsStr>) -> Result<bool, String> {
    match probe() {
        Ok(()) => Ok(true),
        Err(e) if require.is_some_and(|v| !v.is_empty() && v != "0") => Err(format!(
            "{REQUIRE_URING_ENV} is set but io_uring is unavailable here ({e}): {what}"
        )),
        Err(e) => {
            eprintln!("note: io_uring unavailable here ({e}): {what} skipped");
            Ok(false)
        }
    }
}

/// [`uring_for_tests`] with the environment's [`REQUIRE_URING_ENV`]; panics (fails the
/// test) when io_uring is required but unavailable.
///
/// # Panics
/// As described.
#[must_use]
pub fn uring_for_tests_env(what: &str) -> bool {
    uring_for_tests(what, std::env::var_os(REQUIRE_URING_ENV).as_deref())
        .unwrap_or_else(|e| panic!("{e}"))
}

impl UringIo {
    /// # Errors
    /// The ring could not be created.
    pub fn new(buf_size: usize) -> io::Result<Self> {
        if reap() >= GRAVEYARD_MAX {
            return Err(io::Error::other(
                "too many io_uring requests still stuck in the kernel",
            ));
        }
        Ok(Self {
            ring: Some(new_ring()?),
            owned: Some(Box::new(Owned {
                buf: vec![0u8; buf_size.max(4096)],
                st: zero_statx(),
                path_a: CString::default(),
                path_b: CString::default(),
                opening: false,
            })),
            buf_size: buf_size.max(4096),
        })
    }

    fn parts(&mut self) -> Step<(&mut IoUring, &mut Owned)> {
        match (self.ring.as_mut(), self.owned.as_deref_mut()) {
            (Some(r), Some(o)) => Ok((r, o)),
            _ => Err(StepError::Os(libc::EIO)),
        }
    }

    /// Retire the ring and every buffer to the graveyard: a request is still in the
    /// kernel. Without both (never the case) the part left is leaked, never freed.
    fn poison(&mut self) {
        match (self.ring.take(), self.owned.take()) {
            (Some(r), Some(o)) => {
                GRAVEYARD
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((r, o));
                reap();
            }
            (r, o) => {
                mem::forget(r);
                mem::forget(o);
            }
        }
    }

    /// Submit one prepared entry and wait for its completion, re-checking `w` every
    /// [`SLICE`]. Returns the raw result (`>= 0`) or the errno.
    fn run(&mut self, w: &dyn Watch, entry: &io_uring::squeue::Entry) -> Step<i32> {
        check(w)?;
        let (ring, _) = self.parts()?;
        // SAFETY: every pointer in `entry` points into `self.owned` (or is a caller fd),
        // which stays alive until the completion or is leaked by `poison`.
        unsafe { ring.submission().push(entry) }.map_err(|_| StepError::Os(libc::EBUSY))?;
        let mut stop: Option<(Stop, Instant)> = None;
        loop {
            let (ring, _) = self.parts()?;
            let ts = types::Timespec::from(SLICE);
            let args = types::SubmitArgs::new().timespec(&ts);
            match ring.submitter().submit_with_args(1, &args) {
                Ok(_) => {}
                Err(e) if matches!(e.raw_os_error(), Some(libc::ETIME | libc::EINTR)) => {}
                Err(e) => {
                    // Nothing can be known about the request any more.
                    self.poison();
                    return Err(e.into());
                }
            }
            let mut result = None;
            for c in ring.completion() {
                if c.user_data() == USER_OP {
                    result = Some(c.result());
                }
            }
            if let Some(r) = result {
                if let Some((s, _)) = stop {
                    // Finished (or was cancelled) after the stop request: report the stop.
                    if r == -libc::ECANCELED || r == -libc::EINTR {
                        return Err(StepError::Stop(s));
                    }
                }
                return if r >= 0 {
                    Ok(r)
                } else {
                    Err(StepError::Os(-r))
                };
            }
            match stop {
                None => {
                    if let Some(s) = w.stopped() {
                        let cancel = opcode::AsyncCancel::new(USER_OP)
                            .build()
                            .user_data(USER_CANCEL);
                        // SAFETY: references no memory.
                        if unsafe { ring.submission().push(&cancel) }.is_err() {
                            self.poison();
                            return Err(StepError::Stop(s));
                        }
                        stop = Some((s, Instant::now()));
                    }
                }
                Some((s, since)) if since.elapsed() >= CANCEL_WAIT => {
                    // Stuck in the kernel (a hung mount): give up on it, keep the thread.
                    self.poison();
                    return Err(StepError::Stop(s));
                }
                Some(_) => {}
            }
        }
    }
}

impl Io for UringIo {
    fn kind(&self) -> EngineKind {
        EngineKind::Uring
    }

    fn healthy(&self) -> bool {
        self.ring.is_some()
    }

    fn open(
        &mut self,
        w: &dyn Watch,
        dir: RawFd,
        path: &CStr,
        flags: i32,
        mode: u32,
    ) -> Step<OwnedFd> {
        let (_, o) = self.parts()?;
        o.path_a = path.to_owned();
        let e = opcode::OpenAt::new(types::Fd(dir), o.path_a.as_ptr())
            .flags(flags | libc::O_CLOEXEC)
            .mode(mode)
            .build()
            .user_data(USER_OP);
        o.opening = true;
        let r = self.run(w, &e);
        if let Ok((_, o)) = self.parts() {
            o.opening = false;
        }
        let fd = r?;
        // SAFETY: a fresh fd from the kernel, owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn statx(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, flags: i32) -> Step<libc::statx> {
        let (_, o) = self.parts()?;
        o.path_a = path.to_owned();
        o.st = zero_statx();
        let e = opcode::Statx::new(
            types::Fd(dir),
            o.path_a.as_ptr(),
            (&raw mut o.st).cast::<types::statx>(),
        )
        .flags(flags | libc::AT_STATX_SYNC_AS_STAT)
        .mask(STATX_WANT)
        .build()
        .user_data(USER_OP);
        self.run(w, &e)?;
        let (_, o) = self.parts()?;
        Ok(o.st)
    }

    fn read(&mut self, w: &dyn Watch, fd: RawFd, len: usize, off: u64) -> Step<usize> {
        let (_, o) = self.parts()?;
        let len = u32::try_from(len.min(o.buf.len())).unwrap_or(u32::MAX);
        let e = opcode::Read::new(types::Fd(fd), o.buf.as_mut_ptr(), len)
            .offset(off)
            .build()
            .user_data(USER_OP);
        self.run(w, &e).map(|n| n as usize)
    }

    fn write(
        &mut self,
        w: &dyn Watch,
        fd: RawFd,
        start: usize,
        len: usize,
        off: u64,
    ) -> Step<usize> {
        let (_, o) = self.parts()?;
        let data = o.buf.get(start..).ok_or(StepError::Os(libc::EINVAL))?;
        let len = u32::try_from(len.min(data.len())).unwrap_or(u32::MAX);
        let e = opcode::Write::new(types::Fd(fd), data.as_ptr(), len)
            .offset(off)
            .build()
            .user_data(USER_OP);
        self.run(w, &e).map(|n| n as usize)
    }

    fn buf_len(&self) -> usize {
        self.buf_size
    }

    fn fsync(&mut self, w: &dyn Watch, fd: RawFd) -> Step<()> {
        let e = opcode::Fsync::new(types::Fd(fd)).build().user_data(USER_OP);
        self.run(w, &e).map(drop)
    }

    fn unlink(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, flags: i32) -> Step<()> {
        let (_, o) = self.parts()?;
        o.path_a = path.to_owned();
        let e = opcode::UnlinkAt::new(types::Fd(dir), o.path_a.as_ptr())
            .flags(flags)
            .build()
            .user_data(USER_OP);
        self.run(w, &e).map(drop)
    }

    fn rename(
        &mut self,
        w: &dyn Watch,
        old_dir: RawFd,
        old: &CStr,
        new_dir: RawFd,
        new: &CStr,
        flags: u32,
    ) -> Step<()> {
        let (_, o) = self.parts()?;
        o.path_a = old.to_owned();
        o.path_b = new.to_owned();
        let e = opcode::RenameAt::new(
            types::Fd(old_dir),
            o.path_a.as_ptr(),
            types::Fd(new_dir),
            o.path_b.as_ptr(),
        )
        .flags(flags)
        .build()
        .user_data(USER_OP);
        self.run(w, &e).map(drop)
    }

    fn mkdir(&mut self, w: &dyn Watch, dir: RawFd, path: &CStr, mode: u32) -> Step<()> {
        let (_, o) = self.parts()?;
        o.path_a = path.to_owned();
        let e = opcode::MkDirAt::new(types::Fd(dir), o.path_a.as_ptr())
            .mode(mode)
            .build()
            .user_data(USER_OP);
        self.run(w, &e).map(drop)
    }

    fn symlink(&mut self, w: &dyn Watch, target: &CStr, dir: RawFd, path: &CStr) -> Step<()> {
        // SymlinkAt is newer than the rest (5.11); keep it a plain syscall so the probe
        // does not have to require it. It never touches file data.
        SyncIo { buf: Vec::new() }.symlink(w, target, dir, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An abandoned ring is kept until its request completes, then freed (it used to be
    /// leaked for good: 1 MiB buffer, ring fd and mappings per stuck request).
    #[test]
    fn abandoned_rings_are_freed_once_the_kernel_completes_their_request() -> io::Result<()> {
        if std::env::var_os("GUNGNIR_NO_URING").is_some_and(|v| v != "0") {
            eprintln!("note: io_uring disabled: skipped");
            return Ok(());
        }
        if !uring_for_tests_env("abandoned ring test") {
            return Ok(());
        }
        let mut u = UringIo::new(4096)?;
        let ts = types::Timespec::new().nsec(200_000_000);
        let e = opcode::Timeout::new(&ts).build().user_data(USER_OP);
        let (ring, _) = u.parts().map_err(|_| io::Error::other("parts"))?;
        // SAFETY: the timespec is copied by the kernel when the request is submitted.
        unsafe { ring.submission().push(&e) }.map_err(|_| io::Error::other("sq full"))?;
        ring.submit()?;
        u.poison();
        assert!(!u.healthy());
        assert!(reap() >= 1, "the abandoned ring waits in the graveyard");
        let t0 = std::time::Instant::now();
        while reap() > 0 {
            assert!(t0.elapsed() < Duration::from_secs(5), "never freed");
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    /// GUNGNIR_REQUIRE_URING turns the skip into a failure (D-061); unset or "0" keeps the
    /// skip. Checked against this machine's probe result either way.
    #[test]
    fn require_uring_turns_a_skip_into_a_failure() {
        use std::ffi::OsStr;
        let up = probe().is_ok();
        for (req, fails) in [
            (None, false),
            (Some(OsStr::new("")), false),
            (Some(OsStr::new("0")), false),
            (Some(OsStr::new("1")), true),
        ] {
            let got = uring_for_tests("switch test", req);
            match (up, fails) {
                (true, _) => assert_eq!(got, Ok(true), "{req:?}"),
                (false, false) => assert_eq!(got, Ok(false), "{req:?}"),
                (false, true) => assert!(
                    got.as_ref().is_err_and(|e| e.contains(REQUIRE_URING_ENV)),
                    "{req:?}: {got:?}"
                ),
            }
        }
    }

    /// A restricted ring runs an allowed opcode, refuses any other with `EACCES` and
    /// refuses registrations (D-044 item 1).
    #[test]
    fn a_restricted_ring_refuses_opcodes_outside_the_allowlist() -> io::Result<()> {
        if !uring_for_tests_env("io_uring test") {
            return Ok(());
        }
        let mut ring = restricted_ring()?;
        let run = |ring: &mut IoUring, e: io_uring::squeue::Entry| -> io::Result<i32> {
            // SAFETY: neither entry references memory.
            unsafe { ring.submission().push(&e) }.map_err(|_| io::Error::other("sq full"))?;
            ring.submit_and_wait(1)?;
            ring.completion()
                .next()
                .map(|c| c.result())
                .ok_or_else(|| io::Error::other("no completion"))
        };
        assert_eq!(run(&mut ring, opcode::Nop::new().build())?, 0);
        // ACCEPT on fd -1 would fail with EBADF if it were allowed.
        let accept = opcode::Accept::new(types::Fd(-1), std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(run(&mut ring, accept.build())?, -libc::EACCES);
        let close = opcode::Close::new(types::Fd(-1));
        assert_eq!(run(&mut ring, close.build())?, -libc::EACCES);
        let nop_linked = opcode::Nop::new()
            .build()
            .flags(io_uring::squeue::Flags::IO_LINK);
        assert_eq!(run(&mut ring, nop_linked)?, -libc::EACCES);
        let mut p = Probe::new();
        let err = ring.submitter().register_probe(&mut p).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
        Ok(())
    }

    /// Closing a ring interrupts the closing thread once, a little later, without a
    /// signal. A frame receive with a timeout (what every client does) must not fail
    /// with EINTR because of it; the file-ops itest hid this by retrying the whole
    /// connection.
    #[test]
    fn closing_a_ring_does_not_fail_a_timed_frame_receive() -> io::Result<()> {
        use crate::ipc::{self, Frame};
        use std::os::unix::net::UnixStream;
        if !uring_for_tests_env("io_uring test") {
            return Ok(());
        }
        for _ in 0..20 {
            let (a, b) = UnixStream::pair()?;
            a.set_read_timeout(Some(Duration::from_secs(5)))?;
            probe()?; // sets up, uses and closes a ring on this thread
            let peer = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                std::io::Write::write_all(&mut &b, &Frame::hello().encode())
            });
            let got = ipc::recv_with_fd(&a);
            peer.join().expect("peer")?;
            if let Err(e) = got {
                panic!("receive failed after closing a ring: {e:?}");
            }
        }
        Ok(())
    }
}
