//! Control plane, protocol v2 (AGENTS.md §1.B "Handshake protocol"): an `AF_UNIX`
//! stream socket for setup, one memfd holding an SPSC ring pair, process-shared futex
//! wakeups. The layout is mirrored in `src/client-zig/src/ipc.zig`; keep both in sync.
//! v2 (milestone 5) widened the slots to carry metadata requests (`md.rs`).

use std::{
    ffi::OsStr,
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    ptr::{self, NonNull},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{Error, Result};

/// `b"GNGR"` read as a little-endian u32. Starts every frame and the shared-memory header.
pub const MAGIC: u32 = 0x5247_4E47;
/// Bumped for every layout change; a client speaking another version gets a reject
/// frame with [`STATUS_BAD_VERSION`] and no ring.
pub const VERSION: u16 = 2;
pub const KIND_HELLO: u16 = 1;
pub const KIND_ACK: u16 = 2;
pub const KIND_REJECT: u16 = 3;
pub const STATUS_OK: u32 = 0;
pub const STATUS_BAD_MAGIC: u32 = 1;
pub const STATUS_BAD_VERSION: u32 = 2;
pub const STATUS_BAD_KIND: u32 = 3;
pub const FRAME_LEN: usize = 16;

pub const SLOT_COUNT: u32 = 32;
pub const SLOT_SIZE: usize = 4096;
/// Slot header: kind u32 | len u32 | seq u64.
pub const SLOT_HEADER: usize = 16;
pub const PAYLOAD_MAX: usize = SLOT_SIZE - SLOT_HEADER;
pub const SHM_SIZE: usize = 4096 + 2 * SLOT_COUNT as usize * SLOT_SIZE;
pub const MSG_PING: u32 = 1;
pub const MSG_PONG: u32 = 2;

/// Byte offsets of one ring inside the shared memory. `head` is written only by the
/// producer, `tail` only by the consumer; both are free-running u32 counters.
#[derive(Clone, Copy, Debug)]
pub struct Ring {
    head: usize,
    tail: usize,
    slots: usize,
}

/// Client -> daemon.
pub const RING_C2D: Ring = Ring {
    head: 64,
    tail: 128,
    slots: 4096,
};
/// Daemon -> client.
pub const RING_D2C: Ring = Ring {
    head: 192,
    tail: 256,
    slots: 4096 + SLOT_COUNT as usize * SLOT_SIZE,
};

/// The 16-byte setup frame, both directions (little-endian):
/// magic u32 | version u16 | kind u16 | status u32 | shm_size u32.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub magic: u32,
    pub version: u16,
    pub kind: u16,
    pub status: u32,
    pub shm_size: u32,
}

impl Frame {
    #[must_use]
    pub fn hello() -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            kind: KIND_HELLO,
            status: STATUS_OK,
            shm_size: 0,
        }
    }

    #[must_use]
    pub fn encode(&self) -> [u8; FRAME_LEN] {
        let mut b = [0u8; FRAME_LEN];
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..6].copy_from_slice(&self.version.to_le_bytes());
        b[6..8].copy_from_slice(&self.kind.to_le_bytes());
        b[8..12].copy_from_slice(&self.status.to_le_bytes());
        b[12..16].copy_from_slice(&self.shm_size.to_le_bytes());
        b
    }

    #[must_use]
    pub fn decode(b: &[u8; FRAME_LEN]) -> Self {
        Self {
            magic: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            version: u16::from_le_bytes([b[4], b[5]]),
            kind: u16::from_le_bytes([b[6], b[7]]),
            status: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            shm_size: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        }
    }
}

/// Socket path, first match wins (only absolute values count):
/// `$GUNGNIR_SOCKET`, `$XDG_RUNTIME_DIR/gungnir/gungnird.sock`,
/// `$HOME/.cache/gungnir/gungnird.sock`. Never under /tmp.
///
/// # Errors
/// [`Error::NoSocketPath`] if none applies, [`Error::SocketPathTooLong`] if the path
/// does not fit `sun_path`.
pub fn socket_path(
    override_path: Option<&OsStr>,
    runtime_dir: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf> {
    fn abs(v: Option<&OsStr>) -> Option<&Path> {
        v.map(Path::new).filter(|p| p.is_absolute())
    }
    let path = if let Some(p) = abs(override_path) {
        p.to_path_buf()
    } else if let Some(d) = abs(runtime_dir) {
        d.join("gungnir/gungnird.sock")
    } else if let Some(h) = abs(home) {
        h.join(".cache/gungnir/gungnird.sock")
    } else {
        return Err(Error::NoSocketPath);
    };
    // sun_path is 108 bytes including the terminating NUL.
    if path.as_os_str().len() >= 108 {
        return Err(Error::SocketPathTooLong(path));
    }
    Ok(path)
}

/// [`socket_path`] from the process environment.
///
/// # Errors
/// See [`socket_path`].
pub fn socket_path_from_env() -> Result<PathBuf> {
    socket_path(
        std::env::var_os("GUNGNIR_SOCKET").as_deref(),
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// Upper bound on concurrently served clients; further connections are closed at once.
pub const MAX_CLIENTS: usize = 64;

fn os_err<T>() -> Result<T> {
    Err(Error::Io(io::Error::last_os_error()))
}

fn futex_wait(word: &AtomicU32, expected: u32, timeout: Duration) {
    let ts = libc::timespec {
        tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
    };
    // Process-shared: FUTEX_WAIT without FUTEX_PRIVATE_FLAG (AGENTS.md §1.B).
    // EAGAIN (value changed), EINTR and ETIMEDOUT are all handled by the caller's re-check.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr(),
            libc::FUTEX_WAIT,
            expected,
            &raw const ts,
            0usize,
            0u32,
        );
    }
}

/// Wakes every waiter: since milestone 7 a client may have two threads on its reply ring
/// (a request waiting for its answer and the health-event reader), and waking only one
/// of them could leave the request asleep until its next liveness slice.
fn futex_wake(word: &AtomicU32) {
    unsafe {
        libc::syscall(libc::SYS_futex, word.as_ptr(), libc::FUTEX_WAKE, i32::MAX);
    }
}

/// One message slot: kind u32 | len u32 | seq u64 | payload[`PAYLOAD_MAX`].
#[derive(Clone, Copy, Debug)]
pub struct Msg {
    pub kind: u32,
    pub seq: u64,
    len: usize,
    buf: [u8; PAYLOAD_MAX],
}

impl Msg {
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// A mapping of the shared ring memory. The peer can write anything into it, so every
/// index and length read from it is validated before use.
pub struct Shm {
    ptr: NonNull<u8>,
}

// The mapping is plain shared memory; every access to it (header, indices and slot
// bytes) goes through atomics, so it may be moved to and shared between threads.
unsafe impl Send for Shm {}
unsafe impl Sync for Shm {}

impl Shm {
    /// Daemon side: create the sealed memfd, map it, write the header.
    ///
    /// # Errors
    /// Any failing syscall.
    pub fn create() -> Result<(Self, OwnedFd)> {
        let raw = unsafe {
            libc::memfd_create(
                c"gungnir-ring".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if raw < 0 {
            return os_err();
        }
        let file = fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        file.set_len(SHM_SIZE as u64)?;
        let fd = OwnedFd::from(file);
        // The client maps this fd: sealing the size means neither side can make the
        // other's mapping SIGBUS by truncating it.
        let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return os_err();
        }
        let shm = Self::mmap(fd.as_raw_fd())?;
        shm.word(4).store(u32::from(VERSION), Ordering::Relaxed);
        shm.word(8).store(SLOT_COUNT, Ordering::Relaxed);
        shm.word(12).store(SLOT_SIZE as u32, Ordering::Relaxed);
        shm.word(0).store(MAGIC, Ordering::Release);
        Ok((shm, fd))
    }

    /// Client side: check size, seals and header of a received memfd, then map it.
    ///
    /// # Errors
    /// [`Error::Protocol`] if the memfd is not a sealed ring region of this version.
    pub fn map(fd: RawFd) -> Result<Self> {
        let mut st: libc::stat = unsafe { mem::zeroed() };
        if unsafe { libc::fstat(fd, &raw mut st) } < 0 {
            return os_err();
        }
        if usize::try_from(st.st_size).ok() != Some(SHM_SIZE) {
            return Err(Error::Protocol("shared memory has the wrong size"));
        }
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        let need = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
        if seals < 0 || seals & need != need {
            return Err(Error::Protocol("shared memory is not size-sealed"));
        }
        let shm = Self::mmap(fd)?;
        let ok = shm.word(0).load(Ordering::Acquire) == MAGIC
            && shm.word(4).load(Ordering::Relaxed) == u32::from(VERSION)
            && shm.word(8).load(Ordering::Relaxed) == SLOT_COUNT
            && shm.word(12).load(Ordering::Relaxed) == SLOT_SIZE as u32;
        if !ok {
            return Err(Error::Protocol("bad shared memory header"));
        }
        Ok(shm)
    }

    fn mmap(fd: RawFd) -> Result<Self> {
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                SHM_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return os_err();
        }
        NonNull::new(p.cast::<u8>())
            .map(|ptr| Self { ptr })
            .ok_or(Error::Protocol("mmap returned NULL"))
    }

    fn word(&self, off: usize) -> &AtomicU32 {
        debug_assert!(off.is_multiple_of(4) && off + 4 <= SHM_SIZE);
        // In bounds and 4-aligned (the mapping is page-aligned); only ever accessed atomically.
        unsafe { &*self.ptr.as_ptr().add(off).cast::<AtomicU32>() }
    }

    /// One slot as `SLOT_SIZE / 8` atomic words. The peer is another process that may write
    /// the slot at any time (a buggy or hostile client), so slot bytes are only ever
    /// accessed atomically: a racing write yields garbage that is then validated, never UB.
    fn slot(&self, ring: Ring, index: u32) -> &[AtomicU64; SLOT_SIZE / 8] {
        let off = ring.slots + (index % SLOT_COUNT) as usize * SLOT_SIZE;
        debug_assert!(off.is_multiple_of(8) && off + SLOT_SIZE <= SHM_SIZE);
        // In bounds and 8-aligned (slot offsets are multiples of 64 in a page-aligned map).
        unsafe {
            &*self
                .ptr
                .as_ptr()
                .add(off)
                .cast::<[AtomicU64; SLOT_SIZE / 8]>()
        }
    }

    /// Producer: append one message and wake the consumer.
    ///
    /// # Errors
    /// [`Error::RingFull`], or [`Error::Protocol`] for corrupt indices or an oversized payload.
    pub fn push(&self, ring: Ring, kind: u32, seq: u64, payload: &[u8]) -> Result<()> {
        if payload.len() > PAYLOAD_MAX {
            return Err(Error::Protocol("payload too large"));
        }
        let head_w = self.word(ring.head);
        let head = head_w.load(Ordering::Relaxed);
        let used = head.wrapping_sub(self.word(ring.tail).load(Ordering::Acquire));
        if used > SLOT_COUNT {
            return Err(Error::Protocol("ring indices are corrupt"));
        }
        if used == SLOT_COUNT {
            return Err(Error::RingFull);
        }
        let mut slot = [0u8; SLOT_SIZE];
        slot[0..4].copy_from_slice(&kind.to_le_bytes());
        slot[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        slot[8..16].copy_from_slice(&seq.to_le_bytes());
        slot[SLOT_HEADER..SLOT_HEADER + payload.len()].copy_from_slice(payload);
        // Only the words that hold the header and payload are written.
        let words = (SLOT_HEADER + payload.len()).div_ceil(8);
        for (i, w) in self.slot(ring, head).iter().take(words).enumerate() {
            w.store(
                u64::from_le_bytes(std::array::from_fn(|j| slot[i * 8 + j])),
                Ordering::Relaxed,
            );
        }
        head_w.store(head.wrapping_add(1), Ordering::Release);
        futex_wake(head_w);
        Ok(())
    }

    /// Consumer: take one message, `None` if the ring is empty.
    ///
    /// # Errors
    /// [`Error::Protocol`] for corrupt indices or lengths.
    pub fn pop(&self, ring: Ring) -> Result<Option<Msg>> {
        let tail_w = self.word(ring.tail);
        let tail = tail_w.load(Ordering::Relaxed);
        let used = self
            .word(ring.head)
            .load(Ordering::Acquire)
            .wrapping_sub(tail);
        if used > SLOT_COUNT {
            return Err(Error::Protocol("ring indices are corrupt"));
        }
        if used == 0 {
            return Ok(None);
        }
        let words = self.slot(ring, tail);
        let mut slot = [0u8; SLOT_SIZE];
        for (i, w) in words.iter().take(SLOT_HEADER / 8).enumerate() {
            slot[i * 8..i * 8 + 8].copy_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
        }
        // Validate the length (read once, from the local copy) before copying the payload.
        let len = u32::from_le_bytes([slot[4], slot[5], slot[6], slot[7]]) as usize;
        if len > PAYLOAD_MAX {
            return Err(Error::Protocol("message length out of range"));
        }
        let n = (SLOT_HEADER + len).div_ceil(8);
        for (i, w) in words.iter().enumerate().take(n).skip(SLOT_HEADER / 8) {
            slot[i * 8..i * 8 + 8].copy_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
        }
        let mut buf = [0u8; PAYLOAD_MAX];
        buf.copy_from_slice(&slot[SLOT_HEADER..]);
        tail_w.store(tail.wrapping_add(1), Ordering::Release);
        Ok(Some(Msg {
            kind: u32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]),
            seq: u64::from_le_bytes([
                slot[8], slot[9], slot[10], slot[11], slot[12], slot[13], slot[14], slot[15],
            ]),
            len,
            buf,
        }))
    }

    /// Free slots in `ring` right now (`None` if its indices are corrupt). Only the
    /// producer can rely on it staying at least this large.
    #[must_use]
    pub fn free_slots(&self, ring: Ring) -> Option<u32> {
        let head = self.word(ring.head).load(Ordering::Relaxed);
        let used = head.wrapping_sub(self.word(ring.tail).load(Ordering::Acquire));
        SLOT_COUNT.checked_sub(used)
    }

    /// Consumer: wait (futex, bounded by `timeout`) until the ring is non-empty.
    #[must_use]
    pub fn wait_readable(&self, ring: Ring, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let head_w = self.word(ring.head);
        loop {
            let head = head_w.load(Ordering::Acquire);
            if head != self.word(ring.tail).load(Ordering::Relaxed) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            futex_wait(head_w, head, deadline - now);
        }
    }
}

impl Drop for Shm {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), SHM_SIZE) };
    }
}

/// The daemon side of one connection's reply ring. The ring is single-producer as far as
/// the shared memory is concerned; inside the daemon the ring thread and the database
/// thread both answer, so every push goes through `lock` (held for one slot copy only,
/// never across SQLite or a syscall that can block).
pub struct Port {
    shm: Shm,
    lock: Mutex<()>,
    /// Set when a reply did not fit: the client stopped reading. The ring thread then
    /// drops the connection.
    broken: AtomicBool,
    /// Requests handed to another thread and not answered yet.
    inflight: AtomicUsize,
}

/// Most requests a connection may have queued on other threads; the ring thread stops
/// reading requests at this many. Below `SLOT_COUNT`, so their replies always fit.
pub const MAX_INFLIGHT: usize = SLOT_COUNT as usize / 2;

impl Port {
    fn new(shm: Shm) -> Self {
        Self {
            shm,
            lock: Mutex::new(()),
            broken: AtomicBool::new(false),
            inflight: AtomicUsize::new(0),
        }
    }

    /// Push one reply; a full or corrupt ring marks the connection broken.
    pub fn reply(&self, kind: u32, seq: u64, payload: &[u8]) {
        let _g = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if self.shm.push(RING_D2C, kind, seq, payload).is_err() {
            self.broken.store(true, Ordering::Release);
        }
    }

    /// Push unsolicited messages (milestone 7 health events, `seq` 0) all or none, and
    /// only if at least `reserve` slots stay free for replies afterwards. Never marks the
    /// connection broken for lack of room: the caller retries later. Returns whether
    /// they were pushed.
    pub fn push_unsolicited(&self, kind: u32, payloads: &[Vec<u8>], reserve: usize) -> bool {
        let _g = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if self.broken.load(Ordering::Acquire) {
            return false;
        }
        match self.shm.free_slots(RING_D2C) {
            Some(free) if free as usize >= payloads.len() + reserve => {}
            _ => return false,
        }
        for p in payloads {
            if self.shm.push(RING_D2C, kind, 0, p).is_err() {
                self.broken.store(true, Ordering::Release);
                return false;
            }
        }
        true
    }

    /// Count a request handed to another thread; the guard un-counts it when dropped
    /// (after the reply is pushed, or if the job is dropped unanswered).
    #[must_use]
    pub fn begin(self: &Arc<Self>) -> Inflight {
        self.inflight.fetch_add(1, Ordering::AcqRel);
        Inflight(Arc::clone(self))
    }

    fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }
}

/// See [`Port::begin`].
pub struct Inflight(Arc<Port>);

impl Inflight {
    #[must_use]
    pub fn port(&self) -> &Port {
        &self.0
    }
}

impl Drop for Inflight {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serves the requests of one connection other than ping, on its ring thread. Must not
/// block on anything unbounded: hand slow work to another thread and answer from there
/// through the [`Port`].
pub trait Session: Send {
    fn request(&mut self, port: &Arc<Port>, msg: &Msg);
}

/// Creates a [`Session`] per connection.
pub trait Handler: Send + Sync + 'static {
    fn session(&self) -> Box<dyn Session>;
}

/// Answers every request with [`crate::md::ST_UNSUPPORTED`] (pings still work).
pub struct NoService;

struct NoSession;

impl Session for NoSession {
    fn request(&mut self, port: &Arc<Port>, msg: &Msg) {
        port.reply(
            crate::md::MSG_MD_REPLY,
            msg.seq,
            &crate::md::reply_payload(crate::md::ST_UNSUPPORTED, &[]),
        );
    }
}

impl Handler for NoService {
    fn session(&self) -> Box<dyn Session> {
        Box::new(NoSession)
    }
}

/// Timeouts for one client connection.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// A client must complete its hello within this time, or it is dropped.
    pub handshake_timeout: Duration,
    /// How often an idle connection checks whether the client hung up.
    pub idle_poll: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(2),
            idle_poll: Duration::from_millis(200),
        }
    }
}

/// The bound control socket and the lock file that makes this daemon its only owner.
/// Dropping it releases the lock; the socket file is left behind and is stale from then on.
pub struct Listener {
    pub socket: UnixListener,
    _lock: fs::File,
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// The socket directory must be a real directory owned by us and not world-writable; an
/// existing directory is checked, never silently trusted (`DirBuilder::mode` only applies
/// to directories it creates). Group write is tolerated for umask-002 setups: peers are
/// authenticated with `SO_PEERCRED` on both ends anyway.
fn check_socket_dir(dir: &Path) -> Result<()> {
    let md = fs::symlink_metadata(dir)?;
    if !md.is_dir() || md.uid() != euid() || md.mode() & 0o002 != 0 {
        return Err(Error::InsecureSocketDir(dir.to_path_buf()));
    }
    Ok(())
}

/// Non-blocking `connect()` to `path`: the socket and `None` if connected, or the errno.
fn connect_nonblocking(path: &Path) -> Result<(OwnedFd, Option<i32>)> {
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return os_err();
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(Error::SocketPathTooLong(path.to_path_buf()));
    }
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const addr).cast(),
            mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    let err = if rc == 0 {
        None
    } else {
        io::Error::last_os_error().raw_os_error()
    };
    Ok((fd, err))
}

/// Liveness probe of an existing socket file, never blocking: a blocking `connect()`
/// hangs forever on a live daemon whose listen backlog is full.
fn socket_is_live(path: &Path) -> Result<bool> {
    match connect_nonblocking(path)?.1 {
        // Connected, or backlog full (EAGAIN): someone is listening.
        None | Some(libc::EAGAIN | libc::EINPROGRESS) => Ok(true),
        Some(libc::ECONNREFUSED | libc::ENOENT) => Ok(false),
        Some(e) => Err(io::Error::from_raw_os_error(e).into()),
    }
}

/// Bind the control socket, creating its directory (0700) and checking an existing one.
/// An exclusive `flock` on `<socket>.lock` serialises daemon start-up, so two daemons
/// starting at once can never unlink each other's socket. A stale socket left by a dead
/// daemon is replaced; a live one is an error. The socket itself is made 0600.
///
/// # Errors
/// [`Error::AlreadyRunning`], [`Error::NotASocket`], [`Error::InsecureSocketDir`], or I/O
/// errors.
pub fn bind(path: &Path) -> Result<Listener> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => return Err(Error::NoSocketPath),
    };
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    check_socket_dir(dir)?;

    let mut lock_path = OsString::from(path.as_os_str());
    lock_path.push(".lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::WouldBlock {
            Err(Error::AlreadyRunning(path.to_path_buf()))
        } else {
            Err(e.into())
        };
    }

    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() => {
            if socket_is_live(path)? {
                return Err(Error::AlreadyRunning(path.to_path_buf()));
            }
            fs::remove_file(path)?;
        }
        Ok(_) => return Err(Error::NotASocket(path.to_path_buf())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let socket = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(Listener {
        socket,
        _lock: lock,
    })
}

/// Decrements the active-client count when a client thread ends (or fails to start).
struct ClientSlot(Arc<AtomicUsize>);

impl Drop for ClientSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Accept clients forever, one thread per connection, at most [`MAX_CLIENTS`] at once.
///
/// # Errors
/// Never returns on its own; accept errors are logged and retried.
pub fn serve(listener: &UnixListener, cfg: Config, handler: &Arc<dyn Handler>) -> Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if active.fetch_add(1, Ordering::AcqRel) >= MAX_CLIENTS {
                    active.fetch_sub(1, Ordering::AcqRel);
                    drop(stream); // the client sees EOF and falls back to the local VFS
                    continue;
                }
                let slot = ClientSlot(Arc::clone(&active));
                let handler = Arc::clone(handler);
                let spawned =
                    thread::Builder::new()
                        .name("gungnird-client".into())
                        .spawn(move || {
                            let _slot = slot;
                            if let Err(e) = handle_client(stream, cfg, handler.as_ref()) {
                                eprintln!("gungnird: client: {e}");
                            }
                        });
                if let Err(e) = spawned {
                    eprintln!("gungnird: cannot spawn client thread: {e}");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                // e.g. EMFILE: back off instead of spinning.
                eprintln!("gungnird: accept: {e}");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Uid of the process on the other end of a connected `AF_UNIX` socket.
///
/// # Errors
/// I/O errors from `getsockopt(SO_PEERCRED)`.
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc < 0 {
        return os_err();
    }
    if len as usize != mem::size_of::<libc::ucred>() {
        return Err(Error::Protocol("short SO_PEERCRED"));
    }
    Ok(cred.uid)
}

/// Read one hello frame within `timeout` in total (a per-read timeout alone would let a
/// client trickling one byte at a time hold the thread for 16 timeouts).
/// `Ok(None)`: the peer hung up before sending anything (e.g. a liveness probe).
fn read_hello(stream: &mut UnixStream, timeout: Duration) -> Result<Option<[u8; FRAME_LEN]>> {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; FRAME_LEN];
    let mut got = 0;
    while got < FRAME_LEN {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Protocol("handshake timed out"));
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut buf[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(Error::Protocol("client hung up mid-hello")),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Some(buf))
}

/// One client: hello, ring setup (memfd via `SCM_RIGHTS`), then answer pings and hand
/// every other request to the handler's session, until the client closes the socket.
///
/// # Errors
/// Handshake timeout, a rejected hello, ring corruption, a client that stopped reading
/// replies, or I/O errors.
pub fn handle_client(mut stream: UnixStream, cfg: Config, handler: &dyn Handler) -> Result<()> {
    // Only our own user gets a ring: the socket mode and directory are the first line of
    // defence, this is the one that does not depend on umask or a pre-existing directory.
    if peer_uid(&stream)? != euid() {
        return Err(Error::Protocol("peer runs as another user"));
    }
    stream.set_write_timeout(Some(cfg.handshake_timeout))?;
    // Hung up before saying hello (e.g. a liveness probe): nothing to report.
    let Some(buf) = read_hello(&mut stream, cfg.handshake_timeout)? else {
        return Ok(());
    };
    let hello = Frame::decode(&buf);
    let status = if hello.magic != MAGIC {
        STATUS_BAD_MAGIC
    } else if hello.version != VERSION {
        STATUS_BAD_VERSION
    } else if hello.kind != KIND_HELLO {
        STATUS_BAD_KIND
    } else {
        STATUS_OK
    };
    let mut reply = Frame {
        magic: MAGIC,
        version: VERSION,
        kind: KIND_REJECT,
        status,
        shm_size: 0,
    };
    if status != STATUS_OK {
        stream.write_all(&reply.encode())?;
        return Err(Error::Protocol("rejected client hello"));
    }
    let (shm, memfd) = Shm::create()?;
    reply.kind = KIND_ACK;
    reply.shm_size = SHM_SIZE as u32;
    send_with_fd(&stream, &reply.encode(), memfd.as_raw_fd())?;
    drop(memfd);

    stream.set_nonblocking(true)?;
    let port = Arc::new(Port::new(shm));
    let mut session = handler.session();
    loop {
        if port.broken.load(Ordering::Acquire) {
            return Err(Error::Protocol("client stopped reading replies"));
        }
        if port.inflight() >= MAX_INFLIGHT {
            // Back-pressure: leave requests in the ring until answers drain.
            thread::sleep(Duration::from_millis(1));
        } else if port.shm.wait_readable(RING_C2D, cfg.idle_poll) {
            while port.inflight() < MAX_INFLIGHT
                && let Some(msg) = port.shm.pop(RING_C2D)?
            {
                if msg.kind == MSG_PING {
                    port.reply(MSG_PONG, msg.seq, msg.payload());
                } else {
                    session.request(&port, &msg);
                }
            }
        }
        let mut b = [0u8; 1];
        match stream.read(&mut b) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(Error::Protocol("unexpected data on the control socket")),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// Control-message buffer for exactly one fd, aligned for `cmsghdr`.
#[repr(C, align(8))]
struct FdCmsg([u8; 32]);

fn send_with_fd(stream: &UnixStream, data: &[u8], fd: RawFd) -> Result<()> {
    let mut cbuf = FdCmsg([0u8; 32]);
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.0.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null() {
            return Err(Error::Protocol("no room for SCM_RIGHTS"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
    }
    loop {
        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, libc::MSG_NOSIGNAL) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        return if usize::try_from(n).ok() == Some(data.len()) {
            Ok(())
        } else {
            Err(Error::Protocol("short write on the control socket"))
        };
    }
}

/// Receive one frame plus at most one passed fd (`MSG_CMSG_CLOEXEC`). Every fd the kernel
/// installed is taken into an `OwnedFd` first, so none leaks when the message is rejected.
///
/// # Errors
/// I/O errors, a short frame, a truncated control message, or more than one fd.
pub fn recv_with_fd(stream: &UnixStream) -> Result<(Frame, Option<OwnedFd>)> {
    let mut data = [0u8; FRAME_LEN];
    let mut cbuf = FdCmsg([0u8; 32]);
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.0.as_mut_ptr().cast();
    msg.msg_controllen = cbuf.0.len() as _;
    // EINTR is retried: with a receive timeout set the kernel does not restart the call
    // itself, and a thread that closed an io_uring is interrupted once shortly afterwards
    // (the ring's teardown queues task work on it) without any signal.
    let n = loop {
        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break n;
        }
    };
    if n < 0 {
        return os_err();
    }
    let mut fds: Vec<OwnedFd> = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg);
                let header = data.offset_from(cmsg.cast::<u8>()).unsigned_abs();
                let n =
                    ((*cmsg).cmsg_len as usize).saturating_sub(header) / mem::size_of::<RawFd>();
                for i in 0..n {
                    let raw = ptr::read_unaligned(data.cast::<RawFd>().add(i));
                    fds.push(OwnedFd::from_raw_fd(raw));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }
    if fds.len() > 1 {
        return Err(Error::Protocol("more than one fd passed"));
    }
    let fd = fds.pop();
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(Error::Protocol("control message truncated"));
    }
    if usize::try_from(n).ok() != Some(FRAME_LEN) {
        return Err(Error::Protocol("short frame"));
    }
    Ok((Frame::decode(&data), fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    /// Socket path in a fresh private (0700) directory of its own under <repo>/.build/tmp
    /// (never /tmp); the directory, socket and lock file are removed on drop.
    struct TestSock(PathBuf, #[allow(dead_code)] TestDir);

    impl TestSock {
        fn new(name: &str) -> Result<Self> {
            let dir = TestDir::new(&format!("gd-{name}"))?;
            Ok(Self(dir.join("gungnird.sock"), dir))
        }
    }

    fn start_server(sock: &TestSock, cfg: Config) -> Result<()> {
        let listener = bind(&sock.0)?;
        let handler: Arc<dyn Handler> = Arc::new(NoService);
        thread::spawn(move || serve(&listener.socket, cfg, &handler));
        Ok(())
    }

    /// Number of open fds of this process that refer to `target` (parallel-test safe).
    fn fds_open_on(target: &Path) -> Result<usize> {
        let mut n = 0;
        for e in fs::read_dir("/proc/self/fd")? {
            if fs::read_link(e?.path()).is_ok_and(|l| l == target) {
                n += 1;
            }
        }
        Ok(n)
    }

    /// A heap-backed `Shm` for Miri, which cannot model memfd or mmap. The mapping is
    /// never unmapped (`ManuallyDrop`); the caller frees the heap block with `free_heap`.
    fn heap_shm() -> (*mut [AtomicU64; SHM_SIZE / 8], mem::ManuallyDrop<Shm>) {
        let raw = Box::into_raw(Box::new(std::array::from_fn(|_| AtomicU64::new(0))));
        let shm = Shm {
            // Box::into_raw never returns null.
            ptr: unsafe { NonNull::new_unchecked(raw.cast::<u8>()) },
        };
        (raw, mem::ManuallyDrop::new(shm))
    }

    fn free_heap(raw: *mut [AtomicU64; SHM_SIZE / 8]) {
        drop(unsafe { Box::from_raw(raw) });
    }

    /// Pure-memory SPSC check (runs under Miri): a producer thread and a consumer thread,
    /// futex wakeups, u32 wraparound, every message delivered once and in order.
    #[test]
    fn ring_spsc_two_threads_in_memory() -> Result<()> {
        let (raw, shm) = heap_shm();
        let start = u32::MAX - 5;
        shm.word(RING_C2D.head).store(start, Ordering::Relaxed);
        shm.word(RING_C2D.tail).store(start, Ordering::Relaxed);
        let n: u64 = if cfg!(miri) { 150 } else { 20_000 };
        let r = thread::scope(|sc| -> Result<()> {
            let producer = sc.spawn(|| -> Result<()> {
                let mut i = 0;
                while i < n {
                    match shm.push(RING_C2D, MSG_PING, i, &i.to_le_bytes()) {
                        Ok(()) => i += 1,
                        Err(Error::RingFull) => thread::yield_now(),
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            });
            let mut next = 0;
            while next < n {
                if !shm.wait_readable(RING_C2D, Duration::from_secs(10)) {
                    return Err(Error::Protocol("consumer starved"));
                }
                while let Some(m) = shm.pop(RING_C2D)? {
                    assert_eq!((m.seq, m.payload()), (next, &next.to_le_bytes()[..]));
                    next += 1;
                }
            }
            producer
                .join()
                .map_err(|_| Error::Protocol("producer panicked"))?
        });
        free_heap(raw);
        r
    }

    #[test]
    fn frame_roundtrip() {
        let f = Frame {
            magic: MAGIC,
            version: 7,
            kind: KIND_ACK,
            status: 3,
            shm_size: 12288,
        };
        assert_eq!(Frame::decode(&f.encode()), f);
        assert_eq!(&Frame::hello().encode()[0..4], b"GNGR");
    }

    #[test]
    fn socket_path_precedence() -> Result<()> {
        fn s(v: &str) -> Option<&OsStr> {
            Some(OsStr::new(v))
        }
        assert_eq!(
            socket_path(s("/o/g.sock"), s("/run/user/1"), s("/h"))?,
            PathBuf::from("/o/g.sock")
        );
        assert_eq!(
            socket_path(s(""), s("/run/user/1"), s("/h"))?,
            PathBuf::from("/run/user/1/gungnir/gungnird.sock")
        );
        assert_eq!(
            socket_path(None, s("relative"), s("/h"))?,
            PathBuf::from("/h/.cache/gungnir/gungnird.sock")
        );
        assert!(matches!(
            socket_path(None, None, s("")),
            Err(Error::NoSocketPath)
        ));
        let long = format!("/{}", "a".repeat(120));
        assert!(matches!(
            socket_path(s(&long), None, None),
            Err(Error::SocketPathTooLong(_))
        ));
        Ok(())
    }

    #[test]
    fn ring_fills_wraps_and_rejects_corruption() -> Result<()> {
        let (shm, fd) = Shm::create()?;
        let peer = Shm::map(fd.as_raw_fd())?;
        for round in 0..3u64 {
            for i in 0..u64::from(SLOT_COUNT) {
                shm.push(RING_C2D, MSG_PING, round * 100 + i, b"x")?;
            }
            assert!(matches!(
                shm.push(RING_C2D, MSG_PING, 0, b"x"),
                Err(Error::RingFull)
            ));
            for i in 0..u64::from(SLOT_COUNT) {
                let m = peer.pop(RING_C2D)?.ok_or(Error::Protocol("empty"))?;
                assert_eq!(
                    (m.kind, m.seq, m.payload()),
                    (MSG_PING, round * 100 + i, &b"x"[..])
                );
            }
            assert!(peer.pop(RING_C2D)?.is_none());
        }
        assert!(
            shm.push(RING_C2D, MSG_PING, 0, &[0u8; PAYLOAD_MAX + 1])
                .is_err()
        );
        shm.word(RING_D2C.head).store(1000, Ordering::Release);
        assert!(matches!(peer.pop(RING_D2C), Err(Error::Protocol(_))));
        Ok(())
    }

    #[test]
    fn ring_indices_wrap_past_u32_max() -> Result<()> {
        let (shm, fd) = Shm::create()?;
        let peer = Shm::map(fd.as_raw_fd())?;
        let start = u32::MAX - 20;
        shm.word(RING_C2D.head).store(start, Ordering::Release);
        shm.word(RING_C2D.tail).store(start, Ordering::Release);
        for i in 0..3 * u64::from(SLOT_COUNT) {
            shm.push(RING_C2D, MSG_PING, i, &i.to_le_bytes())?;
            let m = peer.pop(RING_C2D)?.ok_or(Error::Protocol("empty"))?;
            assert_eq!((m.seq, m.payload()), (i, &i.to_le_bytes()[..]));
        }
        for i in 0..u64::from(SLOT_COUNT) {
            shm.push(RING_C2D, MSG_PING, i, b"f")?;
        }
        assert!(matches!(
            shm.push(RING_C2D, MSG_PING, 0, b"x"),
            Err(Error::RingFull)
        ));
        assert!(shm.word(RING_C2D.head).load(Ordering::Acquire) < start);
        Ok(())
    }

    #[test]
    fn full_size_payload_round_trips_and_lying_len_is_refused() -> Result<()> {
        let (shm, fd) = Shm::create()?;
        let peer = Shm::map(fd.as_raw_fd())?;
        let big: Vec<u8> = (0..PAYLOAD_MAX).map(|i| (i * 31) as u8).collect();
        shm.push(RING_C2D, 18, 7, &big)?;
        let m = peer.pop(RING_C2D)?.ok_or(Error::Protocol("empty"))?;
        assert_eq!((m.kind, m.seq, m.payload()), (18, 7, &big[..]));
        shm.push(RING_C2D, 18, 8, b"x")?;
        // Rewrite the queued slot's len (low half of its first word) past PAYLOAD_MAX.
        let w = &shm.slot(RING_C2D, 1)[0];
        let v = w.load(Ordering::Relaxed);
        w.store(
            (v & 0xffff_ffff) | ((PAYLOAD_MAX as u64 + 1) << 32),
            Ordering::Relaxed,
        );
        assert!(matches!(peer.pop(RING_C2D), Err(Error::Protocol(_))));
        Ok(())
    }

    #[test]
    fn unsealed_memfd_is_rejected() -> Result<()> {
        let raw = unsafe { libc::memfd_create(c"t".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(raw >= 0);
        let file = fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        file.set_len(SHM_SIZE as u64)?;
        assert!(matches!(
            Shm::map(file.as_raw_fd()),
            Err(Error::Protocol(_))
        ));
        Ok(())
    }

    #[test]
    fn handshake_and_ping_roundtrip() -> Result<()> {
        let sock = TestSock::new("ping")?;
        start_server(&sock, Config::default())?;
        let mut s = UnixStream::connect(&sock.0)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        s.write_all(&Frame::hello().encode())?;
        let (reply, fd) = recv_with_fd(&s)?;
        assert_eq!((reply.kind, reply.status), (KIND_ACK, STATUS_OK));
        assert_eq!(reply.shm_size as usize, SHM_SIZE);
        let fd = fd.ok_or(Error::Protocol("no fd"))?;
        let shm = Shm::map(fd.as_raw_fd())?;
        for seq in 1..=200u64 {
            shm.push(RING_C2D, MSG_PING, seq, b"ping")?;
            assert!(shm.wait_readable(RING_D2C, Duration::from_secs(5)));
            let m = shm.pop(RING_D2C)?.ok_or(Error::Protocol("no pong"))?;
            assert_eq!((m.kind, m.seq, m.payload()), (MSG_PONG, seq, &b"ping"[..]));
        }
        Ok(())
    }

    #[test]
    fn bad_version_is_rejected_without_fd() -> Result<()> {
        let sock = TestSock::new("badver")?;
        start_server(&sock, Config::default())?;
        let mut s = UnixStream::connect(&sock.0)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut hello = Frame::hello();
        hello.version = 99;
        s.write_all(&hello.encode())?;
        let (reply, fd) = recv_with_fd(&s)?;
        assert_eq!(
            (reply.kind, reply.status),
            (KIND_REJECT, STATUS_BAD_VERSION)
        );
        assert!(fd.is_none());
        let mut rest = Vec::new();
        s.read_to_end(&mut rest)?;
        assert!(rest.is_empty());
        Ok(())
    }

    #[test]
    fn silent_client_is_dropped_in_bounded_time() -> Result<()> {
        let sock = TestSock::new("silent")?;
        let cfg = Config {
            handshake_timeout: Duration::from_millis(100),
            ..Config::default()
        };
        start_server(&sock, cfg)?;
        let mut s = UnixStream::connect(&sock.0)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        let t0 = Instant::now();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest)?;
        assert!(rest.is_empty());
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "took {:?}",
            t0.elapsed()
        );
        Ok(())
    }

    #[test]
    fn stale_socket_is_replaced_and_live_one_refused() -> Result<()> {
        let sock = TestSock::new("stale")?;
        drop(bind(&sock.0)?); // listener closed, socket file stays: stale
        let live = bind(&sock.0)?;
        assert!(matches!(bind(&sock.0), Err(Error::AlreadyRunning(_))));
        let mode = fs::symlink_metadata(&sock.0)?.mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(live);
        Ok(())
    }

    #[test]
    fn concurrent_starts_never_orphan_a_listener() -> Result<()> {
        let sock = TestSock::new("race")?;
        for _ in 0..50 {
            drop(bind(&sock.0)?); // leave a stale socket behind
            let a = sock.0.clone();
            let b = sock.0.clone();
            let ta = thread::spawn(move || bind(&a));
            let tb = thread::spawn(move || bind(&b));
            let ra = ta.join().map_err(|_| Error::Protocol("thread panicked"))?;
            let rb = tb.join().map_err(|_| Error::Protocol("thread panicked"))?;
            let won: Vec<Listener> = [ra, rb].into_iter().filter_map(|r| r.ok()).collect();
            assert_eq!(won.len(), 1, "exactly one daemon may own the socket");
            // The winner is reachable through the path, i.e. its socket was not unlinked.
            assert!(socket_is_live(&sock.0)?);
        }
        Ok(())
    }

    #[test]
    fn live_listener_with_full_backlog_is_refused_without_hanging() -> Result<()> {
        let sock = TestSock::new("backlog")?;
        drop(bind(&sock.0)?);
        fs::remove_file(&sock.0)?;
        // A listener that never accepts, its backlog filled up: a hung daemon.
        let listener = UnixListener::bind(&sock.0)?;
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let mut fill = Vec::new();
        loop {
            let (fd, err) = connect_nonblocking(&sock.0)?;
            match err {
                None => fill.push(fd),
                Some(libc::EAGAIN) => break,
                Some(e) => return Err(io::Error::from_raw_os_error(e).into()),
            }
            assert!(fill.len() < 64, "backlog never filled");
        }
        let t0 = Instant::now();
        assert!(matches!(bind(&sock.0), Err(Error::AlreadyRunning(_))));
        assert!(t0.elapsed() < Duration::from_secs(1), "bind() blocked");
        Ok(())
    }

    #[test]
    fn insecure_socket_dir_is_refused() -> Result<()> {
        let tmp = TestDir::new("gd-dir")?;
        let dir = tmp.join("d");
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let path = dir.join("s.sock");
        // World-writable (what a umask-0000 checkout produces): refused, nothing created.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777))?;
        assert!(matches!(bind(&path), Err(Error::InsecureSocketDir(_))));
        assert!(fs::read_dir(&dir)?.next().is_none());
        // Sticky + world-writable (a /tmp lookalike) is refused too.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1777))?;
        assert!(matches!(bind(&path), Err(Error::InsecureSocketDir(_))));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        drop(bind(&path)?);
        Ok(())
    }

    #[test]
    fn peer_uid_is_ours() -> Result<()> {
        let (a, _b) = UnixStream::pair()?;
        assert_eq!(peer_uid(&a)?, euid());
        Ok(())
    }

    #[test]
    fn trickling_hello_is_dropped_by_the_total_deadline() -> Result<()> {
        let sock = TestSock::new("trickle")?;
        let cfg = Config {
            handshake_timeout: Duration::from_millis(300),
            ..Config::default()
        };
        start_server(&sock, cfg)?;
        let mut s = UnixStream::connect(&sock.0)?;
        let t0 = Instant::now();
        let hello = Frame::hello().encode();
        let mut dropped = false;
        for b in &hello[..FRAME_LEN - 1] {
            thread::sleep(Duration::from_millis(100));
            if s.write_all(std::slice::from_ref(b)).is_err() {
                dropped = true;
                break;
            }
        }
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut rest = Vec::new();
        let _ = s.read_to_end(&mut rest);
        assert!(rest.is_empty());
        // A per-read timeout would only fire ~300 ms after the 15th byte (about 1.8 s).
        assert!(dropped, "server kept reading a trickled hello");
        assert!(
            t0.elapsed() < Duration::from_millis(1000),
            "took {:?}",
            t0.elapsed()
        );
        Ok(())
    }

    #[test]
    fn extra_passed_fds_are_closed() -> Result<()> {
        let (a, b) = UnixStream::pair()?;
        let target = TestSock::new("fdleak")?;
        fs::write(&target.0, b"")?;
        let target_path = fs::canonicalize(&target.0)?;
        let x = fs::File::open(&target_path)?;
        let y = fs::File::open(&target_path)?;
        assert_eq!(fds_open_on(&target_path)?, 2);
        // Send a frame with two fds attached.
        #[repr(C, align(8))]
        struct Two([u8; 32]);
        let mut cbuf = Two([0u8; 32]);
        let data = Frame::hello().encode();
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.0.as_mut_ptr().cast();
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(8) } as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            assert!(!cmsg.is_null());
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(8) as _;
            let p = libc::CMSG_DATA(cmsg).cast::<RawFd>();
            ptr::write_unaligned(p, x.as_raw_fd());
            ptr::write_unaligned(p.add(1), y.as_raw_fd());
            assert_eq!(libc::sendmsg(a.as_raw_fd(), &raw const msg, 0), 16);
        }
        assert!(matches!(recv_with_fd(&b), Err(Error::Protocol(_))));
        assert_eq!(fds_open_on(&target_path)?, 2, "a received fd leaked");
        Ok(())
    }
}
