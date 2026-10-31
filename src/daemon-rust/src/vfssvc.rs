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
//!
//! Statuses beyond the metadata ones: 15 OS error (body `errno i32`), 17 a mount inside
//! the item, 18 items remain. Empty reports the first item error, else 18 if items
//! remain, else 4 (suspect mount) naming the skipped volumes.

use std::{
    ffi::OsStr,
    fs,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    ipc::{Handler, Msg, PAYLOAD_MAX, Port, Session},
    md::{
        MSG_MD_REPLY, ST_BAD_REQUEST, ST_BUSY, ST_IO_ERROR, ST_NOT_FOUND, ST_OK, ST_SUSPECT_MOUNT,
        ST_TIMEOUT, reply_payload,
    },
    ops::{Done, OpError, OpKind, OpRequest, Ops, Progress, ST_CANCELLED, ST_OS_ERROR, Sink},
    recent,
    trash::{self, Item, TrashDir},
};

pub const MSG_VFS_LIST: u32 = 40;
pub const MSG_VFS_DELETE: u32 = 41;
pub const MSG_VFS_RESTORE: u32 = 42;
pub const MSG_TRASH_EMPTY: u32 = 43;

pub const SCHEME_TRASH: u8 = 0;
pub const SCHEME_RECENT: u8 = 1;

pub const ST_MOUNT_INSIDE: u32 = 17;
pub const ST_NOT_EMPTY: u32 = 18;

/// Request threads that may exist at once; the next request gets `busy`.
pub const MAX_WAITERS: usize = 4;
/// Longest one item's op is waited for; then it is cancelled and answered `timeout`.
const OP_DEADLINE: Duration = Duration::from_secs(60);
const CANCEL_WAIT: Duration = Duration::from_secs(2);
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

/// What the service works on.
pub struct Svc {
    ops: Arc<Ops>,
    home: Option<TrashDir>,
    xbel: Option<PathBuf>,
    uid: u32,
    /// Volumes beyond the mount table (the test hook).
    extra_tops: Vec<PathBuf>,
    in_flight: AtomicUsize,
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

/// Mount points of a `/proc/self/mountinfo` text that could hold a trash directory.
fn mount_points(text: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let Some(raw) = left.split(' ').nth(4) else {
            continue;
        };
        let fstype = right.split(' ').next().unwrap_or("");
        if NO_TRASH_TYPES.contains(&fstype) {
            continue;
        }
        let p = PathBuf::from(std::ffi::OsString::from_vec(unescape(raw.as_bytes())));
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// mountinfo's octal escapes.
fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\'
            && let Some(o) = s.get(i + 1..i + 4)
            && let Ok(v) = u8::from_str_radix(std::str::from_utf8(o).unwrap_or("x"), 8)
        {
            out.push(v);
            i += 4;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

impl Svc {
    /// A service with paths from the environment's values.
    #[must_use]
    pub fn new(ops: Arc<Ops>, xdg_data: Option<&OsStr>, home: Option<&OsStr>) -> Arc<Self> {
        let trash_home = trash::home_dir(xdg_data, home);
        let xbel = trash_home
            .as_ref()
            .map(|d| d.top.join("recently-used.xbel"));
        #[cfg(feature = "test-hooks")]
        let extra_tops = std::env::var_os(TEST_TOP_ENV)
            .map(PathBuf::from)
            .into_iter()
            .collect();
        #[cfg(not(feature = "test-hooks"))]
        let extra_tops = Vec::new();
        Arc::new(Self {
            ops,
            home: trash_home,
            xbel,
            // SAFETY: plain getter.
            uid: unsafe { libc::geteuid() },
            extra_tops,
            in_flight: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
        })
    }

    fn blocked(&self, p: &Path) -> bool {
        self.ops.blocked(p.as_os_str().as_bytes()).is_some()
    }

    /// Every trash directory reachable now, and the volumes skipped as hung or gone.
    fn dirs(&self) -> (Vec<TrashDir>, Vec<PathBuf>) {
        let mut dirs: Vec<TrashDir> = Vec::new();
        let mut skipped = Vec::new();
        if let Some(h) = &self.home {
            if self.blocked(&h.dir) {
                skipped.push(h.dir.clone());
            } else {
                dirs.push(h.clone());
            }
        }
        let mut tops = fs::read_to_string("/proc/self/mountinfo")
            .map(|t| mount_points(&t))
            .unwrap_or_default();
        tops.extend(self.extra_tops.iter().cloned());
        for top in tops {
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
        (dirs, skipped)
    }

    fn snapshot_trash(&self) -> Vec<Item> {
        let (dirs, _) = self.dirs();
        let mut items = Vec::new();
        for d in dirs.iter().filter(|d| trash::sound(d, self.uid)) {
            match trash::scan(d) {
                Ok(i) => items.extend(i),
                // The home trash not existing yet is the normal case.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => eprintln!("gungnird: trash {}: {e}", d.dir.display()),
            }
            if items.len() >= SNAPSHOT_MAX {
                items.truncate(SNAPSHOT_MAX);
                break;
            }
        }
        items
    }

    fn snapshot_recent(&self) -> Result<Vec<Item>, Failure> {
        let path = self.xbel.as_ref().ok_or(Failure::st(ST_IO_ERROR))?;
        let text = recent::load(path).map_err(|e| io_failure(&e))?;
        let mut items = Vec::new();
        for e in recent::parse(&text).into_iter().take(SNAPSHOT_MAX) {
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
            items.push(Item {
                name: hex(&e.uri).into_bytes(),
                entry: Vec::new(),
                orig: e.uri,
                target,
                kind,
                size,
                mtime,
                deleted: Vec::new(),
            });
        }
        Ok(items)
    }

    /// Run one op to its end, within the deadline.
    fn run(&self, req: OpRequest) -> Result<(), Failure> {
        let w = Arc::new(Wait::default());
        let ctl = self.ops.submit(req, w.clone())?;
        if let Some(r) = w.until(Instant::now() + OP_DEADLINE) {
            return r.map_err(Failure::from);
        }
        self.ops.cancel(&ctl);
        match w.until(Instant::now() + CANCEL_WAIT) {
            Some(r) => r.map_err(Failure::from),
            None => Err(Failure::st(ST_TIMEOUT)),
        }
    }

    /// Delete one item: the info entry is checked first and removed last, so a failure
    /// leaves it listed and retryable.
    fn delete_item(&self, d: &TrashDir, entry: &[u8]) -> Result<(), Failure> {
        if !trash::sound(d, self.uid) {
            return Err(Failure::os(libc::ENOTDIR));
        }
        trash::check_info_removable(d, entry).map_err(Failure::os)?;
        let payload = d.files().join(OsStr::from_bytes(entry));
        match fs::symlink_metadata(&payload) {
            Ok(_) => self.run(OpRequest {
                kind: OpKind::DeleteTree,
                flags: 0,
                timeout_ms: 0,
                src: payload.as_os_str().as_bytes().to_vec(),
                dest: Vec::new(),
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Failure::st(ST_NOT_FOUND));
            }
            Err(e) => return Err(io_failure(&e)),
        }
        trash::remove_info(d, entry).map_err(|e| io_failure(&e))
    }

    fn delete(&self, scheme: u8, name: &[u8]) -> Result<(), Failure> {
        if scheme == SCHEME_RECENT {
            let uri = unhex(name).ok_or(Failure::st(ST_BAD_REQUEST))?;
            let path = self.xbel.as_ref().ok_or(Failure::st(ST_IO_ERROR))?;
            return recent::forget(path, &uri).map_err(|e| match e {
                recent::ForgetError::Busy => Failure::st(ST_BUSY),
                recent::ForgetError::NotFound => Failure::st(ST_NOT_FOUND),
                recent::ForgetError::Io(e) => io_failure(&e),
            });
        }
        let (dirs, _) = self.dirs();
        let (d, entry) = trash::resolve(&dirs, name).ok_or(Failure::st(ST_NOT_FOUND))?;
        self.delete_item(d, &entry)
    }

    fn restore(&self, name: &[u8], dest: &[u8]) -> Result<(), Failure> {
        let (dirs, _) = self.dirs();
        let (d, entry) = trash::resolve(&dirs, name).ok_or(Failure::st(ST_NOT_FOUND))?;
        if !trash::sound(d, self.uid) {
            return Err(Failure::os(libc::ENOTDIR));
        }
        let item = trash::read_item(d, &entry);
        let to = if dest.is_empty() {
            item.orig
        } else {
            dest.to_vec()
        };
        if to.first() != Some(&b'/') {
            return Err(Failure::st(ST_BAD_REQUEST));
        }
        trash::check_info_removable(d, &entry).map_err(Failure::os)?;
        self.run(OpRequest {
            kind: OpKind::Move,
            flags: 0,
            timeout_ms: 0,
            src: item.target,
            dest: to,
        })?;
        trash::remove_info(d, &entry).map_err(|e| io_failure(&e))
    }

    /// Empty what can be reached. Returns the reply status and body.
    fn empty(&self) -> (u32, Vec<u8>) {
        let (dirs, skipped) = self.dirs();
        let (mut deleted, mut failed) = (0u32, 0u32);
        let mut first: Option<Failure> = None;
        for d in dirs.iter().filter(|d| trash::sound(d, self.uid)) {
            let items = match trash::scan(d) {
                Ok(i) => i,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    first.get_or_insert(io_failure(&e));
                    continue;
                }
            };
            for item in items {
                match self.delete_item(d, &item.entry) {
                    Ok(()) => deleted += 1,
                    Err(f) => {
                        failed += 1;
                        first.get_or_insert(f);
                    }
                }
            }
            let _ = trash::remove_orphans(d);
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
        let status = match first {
            Some(f) => f.status,
            None if failed > 0 => ST_NOT_EMPTY,
            None if !skipped.is_empty() => ST_SUSPECT_MOUNT,
            None => ST_OK,
        };
        (status, body)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

fn put16(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s);
}

/// Encoded size of an item, if it can ever fit one reply.
fn encoded(i: &Item) -> usize {
    8 + i.name.len() + i.orig.len() + i.target.len() + i.deleted.len() + 17
}

/// One page of `items` from `cursor`: the reply body. An item too big for a reply is
/// listed with its long strings dropped, never skipped: it can still be deleted by name.
#[must_use]
pub fn page(items: &[Item], cursor: usize) -> Vec<u8> {
    let max = PAYLOAD_MAX - 4;
    let mut body = vec![0u8; 6];
    let (mut at, mut count) = (cursor, 0u16);
    while let Some(i) = items.get(at) {
        let degraded;
        let it = if encoded(i) > max - 6 {
            degraded = Item {
                orig: Vec::new(),
                target: Vec::new(),
                deleted: Vec::new(),
                ..i.clone()
            };
            &degraded
        } else {
            i
        };
        if body.len() + encoded(it) > max {
            break;
        }
        put16(&mut body, &it.name);
        put16(&mut body, &it.orig);
        put16(&mut body, &it.target);
        put16(&mut body, &it.deleted);
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
            snapshot: Arc::new(Mutex::new(Vec::new())),
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
    snapshot: Arc<Mutex<Vec<Item>>>,
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
        job: impl FnOnce(&Svc) -> (u32, Vec<u8>) + Send + 'static,
    ) {
        let busy = || port.reply(MSG_MD_REPLY, seq, &reply_payload(ST_BUSY, &[]));
        if self.svc.draining.load(Ordering::SeqCst) {
            return busy();
        }
        let n = self.svc.in_flight.fetch_add(1, Ordering::SeqCst);
        let slot = Slot(Arc::clone(&self.svc));
        if n >= MAX_WAITERS {
            drop(slot);
            return busy();
        }
        let p = Arc::clone(port);
        let spawned = thread::Builder::new()
            .name("gungnir-vfs".into())
            .spawn(move || {
                let (st, body) = job(&slot.0);
                p.reply(MSG_MD_REPLY, seq, &reply_payload(st, &body));
                drop(slot);
            });
        if spawned.is_err() {
            busy();
        }
    }

    fn list(&self, port: &Arc<Port>, msg: &Msg) {
        let p = msg.payload();
        let bad = || port.reply(MSG_MD_REPLY, msg.seq, &reply_payload(ST_BAD_REQUEST, &[]));
        let [scheme, a, b, c, d] = *p else {
            return bad();
        };
        if scheme > SCHEME_RECENT {
            return bad();
        }
        let cursor = u32::from_le_bytes([a, b, c, d]) as usize;
        if cursor > 0 {
            let s = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
            let body = page(&s, cursor);
            return port.reply(MSG_MD_REPLY, msg.seq, &reply_payload(ST_OK, &body));
        }
        let snap = Arc::clone(&self.snapshot);
        self.spawn(port, msg.seq, move |svc| {
            let items = if scheme == SCHEME_TRASH {
                Ok(svc.snapshot_trash())
            } else {
                svc.snapshot_recent()
            };
            match items {
                Ok(items) => {
                    let body = page(&items, 0);
                    *snap.lock().unwrap_or_else(PoisonError::into_inner) = items;
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
        let bad = || port.reply(MSG_MD_REPLY, msg.seq, &reply_payload(ST_BAD_REQUEST, &[]));
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
                self.spawn(port, msg.seq, move |svc| outcome(svc.delete(scheme, &name)));
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
                self.spawn(port, msg.seq, move |svc| outcome(svc.restore(&name, &dest)));
            }
            MSG_TRASH_EMPTY => self.spawn(port, msg.seq, Svc::empty),
            _ => self.inner.request(port, msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let b = page(&items, cursor);
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
        let b = page(&items, 0);
        assert!(b.len() + 4 <= PAYLOAD_MAX);
        assert_eq!(count(&b), (0, 2));
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
            mount_points(t),
            [PathBuf::from("/"), PathBuf::from("/mnt/my disk")]
        );
    }
}
