//! Filesystem identity (milestone 4): resolve a path or fd to the metadata key
//! `(fs_uuid, subvol_id, inode_num, generation)` plus `btime` (AGENTS.md §1.B).
//!
//! - `inode_num`, `subvol_id` (`STATX_SUBVOL`; on btrfs before Linux 6.10
//!   `BTRFS_IOC_INO_LOOKUP`; else 0), `btime` (`STATX_BTIME`, else 0) and the mount id
//!   (`STATX_MNT_ID`) come from one `statx` on an `O_PATH | O_NOFOLLOW` fd.
//! - `generation` is `FS_IOC_GETVERSION` (0 if unsupported, never ctime).
//! - `fs_uuid` is resolved once per mount and cached by mount id: `FS_IOC_GETFSUUID`, else
//!   `/proc/self/mountinfo` + `/dev/disk/by-uuid`, else `synth-<BLAKE3>` by `statfs` class.
//!
//! Non-blocking rule: every syscall on the target runs on a [`Resolver`] worker. The
//! caller waits at most the deadline, gets [`FsidError::Timeout`], and the mount is marked
//! suspect so later requests for it fail fast instead of tying up more workers.

use std::{
    collections::HashMap,
    ffi::{CString, OsString},
    fmt, fs,
    io::{self, Read, Seek},
    mem,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{FileTypeExt, MetadataExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU8, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use crate::synth_fs_id;

/// `_IOR(0x15, 0, struct fsuuid2)`; `struct fsuuid2 { __u8 len; __u8 uuid[16]; }` (17 bytes).
pub const FS_IOC_GETFSUUID: u32 = (2 << 30) | (17 << 16) | (0x15 << 8);

/// `statfs` magics (normalised to the low 32 bits of `f_type`).
pub mod magic {
    pub const TMPFS: u32 = 0x0102_1994;
    pub const RAMFS: u32 = 0x8584_58f6;
    pub const NFS: u32 = 0x6969;
    pub const CIFS: u32 = 0xFF53_4D42;
    pub const SMB2: u32 = 0xFE53_4D42;
    pub const SMB: u32 = 0x517B;
    pub const FUSE: u32 = 0x6573_5546;
    pub const BTRFS: u32 = 0x9123_683E;
}

/// `_IOWR(0x94, 18, struct btrfs_ioctl_ino_lookup_args)` (4096 bytes) from <linux/btrfs.h>.
pub const BTRFS_IOC_INO_LOOKUP: u32 = (3 << 30) | (4096 << 16) | (0x94 << 8) | 18;
/// `BTRFS_FIRST_FREE_OBJECTID`: every subvolume's root directory; the unprivileged form
/// of `BTRFS_IOC_INO_LOOKUP` (treeid 0, this objectid) returns the fd's subvolume id.
const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// The metadata key of one file (AGENTS.md table schema), plus its staleness `btime`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub fs_uuid: String,
    pub subvol_id: u64,
    pub inode_num: u64,
    pub generation: u64,
    /// `stx_btime` when `STATX_BTIME` is reported, else 0 (not part of the key).
    pub btime_sec: i64,
    pub btime_nsec: u32,
    /// Which step of the fallback chain produced `fs_uuid` (diagnostics only).
    pub fs_uuid_source: UuidSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidSource {
    Ioctl,
    ByUuid,
    Synthetic,
}

/// Hash class for synthetic ids, from `statfs` `f_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsClass {
    /// tmpfs, ramfs: `f_type || mount_point || boot_id` (must not survive a reboot).
    Volatile,
    /// nfs, nfs4, cifs, smb3: `f_type || mount_source` (independent of the mount point).
    Network,
    /// FUSE and everything else: `f_type || mount_source || mount_point`.
    Other,
}

#[must_use]
pub fn classify(f_type: u32) -> FsClass {
    match f_type {
        magic::TMPFS | magic::RAMFS => FsClass::Volatile,
        magic::NFS | magic::CIFS | magic::SMB2 | magic::SMB => FsClass::Network,
        _ => FsClass::Other,
    }
}

/// Synthetic id for a UUID-less filesystem. `f_type` is hashed as a little-endian u64
/// (the 32-bit magic, zero-extended), so the id does not depend on the architecture.
#[must_use]
pub fn synth_id(f_type: u32, mount_point: &[u8], source: &[u8], boot_id: &[u8]) -> String {
    let ft = u64::from(f_type).to_le_bytes();
    match classify(f_type) {
        FsClass::Volatile => synth_fs_id(&[&ft, mount_point, boot_id]),
        FsClass::Network => synth_fs_id(&[&ft, source]),
        FsClass::Other => synth_fs_id(&[&ft, source, mount_point]),
    }
}

#[derive(Debug)]
pub enum FsidError {
    Io(io::Error),
    /// Paths must be absolute (the suspect-mount check is lexical).
    NotAbsolute(PathBuf),
    /// The worker did not answer within the deadline; the mount is now suspect.
    Timeout(Duration),
    /// The mount (by its mount point) timed out recently; not retried until it expires.
    SuspectMount(PathBuf),
    /// Every worker is busy (or stuck) and the request never started.
    Busy,
    /// The mount the target lives on is not in `/proc/self/mountinfo`.
    UnknownMount {
        major: u32,
        minor: u32,
    },
    /// A volatile filesystem needs `/proc/sys/kernel/random/boot_id` for its synthetic id.
    NoBootId,
    /// btrfs without `STATX_SUBVOL` (Linux < 6.10) and a file that cannot be opened for
    /// `BTRFS_IOC_INO_LOOKUP` (symlink, FIFO, device): subvolume 0 would collide.
    NoSubvol,
    Shutdown,
}

impl fmt::Display for FsidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsidError::Io(e) => write!(f, "io: {e}"),
            FsidError::NotAbsolute(p) => write!(f, "not an absolute path: {}", p.display()),
            FsidError::Timeout(d) => write!(f, "identity lookup timed out after {d:?}"),
            FsidError::SuspectMount(p) => write!(f, "mount {} is suspect (hung)", p.display()),
            FsidError::Busy => write!(f, "all identity workers are busy"),
            FsidError::UnknownMount { major, minor } => {
                write!(f, "device {major}:{minor} is not in /proc/self/mountinfo")
            }
            FsidError::NoBootId => write!(f, "cannot read the boot id for a volatile filesystem"),
            FsidError::NoSubvol => write!(
                f,
                "btrfs subvolume unknown (no STATX_SUBVOL, no readable fd)"
            ),
            FsidError::Shutdown => write!(f, "identity resolver is shut down"),
        }
    }
}

impl std::error::Error for FsidError {}

impl From<io::Error> for FsidError {
    fn from(e: io::Error) -> Self {
        FsidError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, FsidError>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------------------
// mountinfo

/// One line of `/proc/self/mountinfo` (proc(5)); paths are unescaped raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub mnt_id: u64,
    pub parent_id: u64,
    pub major: u32,
    pub minor: u32,
    pub root: Vec<u8>,
    pub mount_point: Vec<u8>,
    pub fstype: Vec<u8>,
    pub source: Vec<u8>,
}

impl MountEntry {
    #[must_use]
    pub fn mount_point_path(&self) -> PathBuf {
        PathBuf::from(OsString::from_vec(self.mount_point.clone()))
    }
}

/// Undo the kernel's `\ooo` octal escaping (space, tab, newline, backslash).
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\'
            && let Some(oct) = field.get(i + 1..i + 4)
            && oct.iter().all(|b| (b'0'..=b'7').contains(b))
        {
            let v = oct.iter().fold(0u32, |a, b| a * 8 + u32::from(b - b'0'));
            if let Ok(byte) = u8::try_from(v) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(field[i]);
        i += 1;
    }
    out
}

fn parse_line(line: &[u8]) -> Option<MountEntry> {
    fn num<T: std::str::FromStr>(b: &[u8]) -> Option<T> {
        std::str::from_utf8(b).ok()?.parse().ok()
    }
    // Fields are separated by exactly one space (the kernel escapes spaces inside them);
    // an empty field is real, e.g. the source of `mount -t tmpfs "" /mnt` (proc(5)).
    let mut it = line.split(|&b| b == b' ');
    let mnt_id = num(it.next()?)?;
    let parent_id = num(it.next()?)?;
    let (maj, min) = {
        let dev = it.next()?;
        let colon = dev.iter().position(|&b| b == b':')?;
        (num(&dev[..colon])?, num(&dev[colon + 1..])?)
    };
    let root = unescape(it.next()?);
    let mount_point = unescape(it.next()?);
    let _opts = it.next()?;
    // Zero or more optional fields, terminated by a single "-".
    loop {
        if it.next()? == b"-" {
            break;
        }
    }
    let fstype = unescape(it.next()?);
    let source = unescape(it.next()?);
    Some(MountEntry {
        mnt_id,
        parent_id,
        major: maj,
        minor: min,
        root,
        mount_point,
        fstype,
        source,
    })
}

/// Parse mountinfo text; malformed lines are skipped, never a panic.
#[must_use]
pub fn parse_mountinfo(text: &[u8]) -> Vec<MountEntry> {
    text.split(|&b| b == b'\n').filter_map(parse_line).collect()
}

/// Lexically normalise an absolute path (`.` dropped, `..` pops). Only used to guess
/// the mount for the suspect check, never to open anything.
fn lexical(path: &Path) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => parts.push(s.as_bytes()),
            Component::ParentDir => {
                parts.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    let mut out = Vec::new();
    for p in parts {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

fn under(path: &[u8], mount_point: &[u8]) -> bool {
    mount_point == b"/"
        || path == mount_point
        || (path.starts_with(mount_point) && path.get(mount_point.len()) == Some(&b'/'))
}

/// The mount a path would be on by its longest mount-point prefix (later lines win ties:
/// they are mounted on top). Lexical only: a symlink crossing mounts can fool it.
#[must_use]
pub fn mount_for_path<'a>(table: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    let p = lexical(path);
    let mut best: Option<&MountEntry> = None;
    for e in table.iter().filter(|e| under(&p, &e.mount_point)) {
        if best.is_none_or(|b| e.mount_point.len() >= b.mount_point.len()) {
            best = Some(e);
        }
    }
    best
}

/// Cached mount table plus the per-mount `fs_uuid` cache, keyed by mount id.
pub struct MountCache {
    file: Option<fs::File>,
    table: Vec<MountEntry>,
    uuids: HashMap<u64, CachedMount>,
    /// `poll` consumed a change notification but the re-read has not succeeded yet.
    stale: bool,
}

/// What is resolved once per mount: its `fs_uuid` and `statfs` `f_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedMount {
    entry: MountEntry,
    uuid: String,
    source: UuidSource,
    f_type: u32,
}

impl MountCache {
    /// Open and read `/proc/self/mountinfo` (procfs: does not touch other filesystems).
    ///
    /// # Errors
    /// I/O errors opening or reading it.
    pub fn open() -> io::Result<Self> {
        let mut file = fs::File::open("/proc/self/mountinfo")?;
        let mut text = Vec::new();
        file.read_to_end(&mut text)?;
        Ok(Self {
            file: Some(file),
            table: parse_mountinfo(&text),
            uuids: HashMap::new(),
            stale: false,
        })
    }

    /// A fixed table that never refreshes (tests, or when procfs is missing).
    #[must_use]
    pub fn from_text(text: &[u8]) -> Self {
        Self {
            file: None,
            table: parse_mountinfo(text),
            uuids: HashMap::new(),
            stale: false,
        }
    }

    #[must_use]
    pub fn table(&self) -> &[MountEntry] {
        &self.table
    }

    /// Has the mount table changed since the last read? A zero-timeout `poll` for
    /// `POLLPRI` (proc(5)), so it never waits.
    fn changed(&self) -> bool {
        let Some(f) = &self.file else { return false };
        let mut p = libc::pollfd {
            fd: f.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        // SAFETY: one valid pollfd, zero timeout.
        let r = unsafe { libc::poll(&raw mut p, 1, 0) };
        r != 0 && (r < 0 || p.revents & (libc::POLLPRI | libc::POLLERR) != 0)
    }

    /// Re-read the table if it changed. Returns whether it was re-read.
    ///
    /// # Errors
    /// I/O errors re-reading the file (the old table is kept).
    pub fn refresh(&mut self) -> io::Result<bool> {
        // The kernel clears the change flag in `poll` itself (mounts_poll), not on read:
        // remember it until a re-read succeeds, or a failed read would lose the change.
        if !self.stale && !self.changed() {
            return Ok(false);
        }
        let Some(f) = &mut self.file else {
            return Ok(false);
        };
        self.stale = true;
        f.rewind()?;
        let mut text = Vec::new();
        f.read_to_end(&mut text)?;
        self.apply(parse_mountinfo(&text));
        self.stale = false;
        Ok(true)
    }

    /// Install a new table, dropping cached uuids whose mount is gone or was replaced
    /// by a different mount reusing the same id.
    pub fn apply(&mut self, table: Vec<MountEntry>) {
        self.uuids
            .retain(|id, c| table.iter().any(|e| e.mnt_id == *id && *e == c.entry));
        self.table = table;
    }

    fn by_id(&self, mnt_id: u64) -> Option<&MountEntry> {
        self.table.iter().rev().find(|e| e.mnt_id == mnt_id)
    }

    fn by_dev(&self, major: u32, minor: u32) -> Option<&MountEntry> {
        self.table
            .iter()
            .rev()
            .find(|e| e.major == major && e.minor == minor)
    }

    fn cached(&self, e: &MountEntry) -> Option<&CachedMount> {
        self.uuids.get(&e.mnt_id).filter(|c| c.entry == *e)
    }

    #[cfg(test)]
    fn cached_uuid(&self, e: &MountEntry) -> Option<(String, UuidSource)> {
        self.cached(e).map(|c| (c.uuid.clone(), c.source))
    }
}

// ---------------------------------------------------------------------------------------
// fs_uuid fallback chain

/// Format a `struct fsuuid2` payload: 16 bytes as a lowercase RFC 4122 string, shorter
/// ones as plain hex. Empty, oversized or all-zero ids are rejected (they would collide).
#[must_use]
pub fn format_fsuuid(len: u8, bytes: &[u8; 16]) -> Option<String> {
    let id = bytes.get(..usize::from(len))?;
    if id.is_empty() || id.iter().all(|&b| b == 0) {
        return None;
    }
    let mut s = String::with_capacity(36);
    for (i, b) in id.iter().enumerate() {
        if len == 16 && matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{b:02x}"));
    }
    Some(s)
}

fn unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOTTY | libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

/// `FS_IOC_GETFSUUID` on a readable (non-`O_PATH`) fd. `Ok(None)` if unsupported.
///
/// # Errors
/// Any other ioctl failure.
pub fn ioctl_fsuuid(fd: BorrowedFd<'_>) -> io::Result<Option<String>> {
    let mut buf = [0u8; 17];
    // SAFETY: the kernel writes at most size_of(struct fsuuid2) = 17 bytes into `buf`.
    let r = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_GETFSUUID as libc::Ioctl,
            buf.as_mut_ptr(),
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        return if unsupported(&e) { Ok(None) } else { Err(e) };
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&buf[1..]);
    Ok(format_fsuuid(buf[0], &id))
}

/// `FS_IOC_GETVERSION` (the inode generation) on a readable fd; 0 if unsupported.
///
/// # Errors
/// Any other ioctl failure (a transient error must not silently change the key).
pub fn ioctl_generation(fd: BorrowedFd<'_>) -> io::Result<u64> {
    Ok(ioctl_generation_opt(fd)?.unwrap_or(0))
}

/// `FS_IOC_GETVERSION`, with "unsupported" (`None`) kept apart from a real 0 (ext4's
/// root directory has generation 0).
fn ioctl_generation_opt(fd: BorrowedFd<'_>) -> io::Result<Option<u64>> {
    // Filesystems store an `int` at the start of the argument (ext4, btrfs, xfs); a
    // zeroed 8-byte buffer covers a `long` writer too.
    let mut buf = [0u8; 8];
    // SAFETY: the kernel writes at most sizeof(long) = 8 bytes into `buf`.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FS_IOC_GETVERSION, buf.as_mut_ptr()) };
    if r < 0 {
        let e = io::Error::last_os_error();
        return if unsupported(&e) { Ok(None) } else { Err(e) };
    }
    Ok(Some(u64::from(u32::from_ne_bytes([
        buf[0], buf[1], buf[2], buf[3],
    ]))))
}

#[repr(C)]
struct BtrfsInoLookupArgs {
    treeid: u64,
    objectid: u64,
    name: [u8; 4080],
}

/// The btrfs subvolume (tree id) an fd lives in, for kernels without `STATX_SUBVOL`.
/// Same value `STATX_SUBVOL` reports, so a kernel upgrade does not re-key anything.
///
/// # Errors
/// The ioctl's error (it needs a readable, non-`O_PATH` fd on btrfs).
pub fn btrfs_subvol(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let mut args = BtrfsInoLookupArgs {
        treeid: 0,
        objectid: BTRFS_FIRST_FREE_OBJECTID,
        name: [0; 4080],
    };
    // SAFETY: `args` is the 4096-byte `struct btrfs_ioctl_ino_lookup_args` the request
    // number encodes; the kernel reads and writes only that.
    let r = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            BTRFS_IOC_INO_LOOKUP as libc::Ioctl,
            &raw mut args,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(args.treeid)
}

/// Step 2: the `/dev/disk/by-uuid` link whose device is the mount's `major:minor`, or
/// (for anonymous devices such as btrfs's `0:N`) whose target is the mount source.
#[must_use]
pub fn by_uuid(dir: &Path, major: u32, minor: u32, source: &[u8]) -> Option<String> {
    let mut links: Vec<(String, PathBuf)> = fs::read_dir(dir)
        .ok()?
        .filter_map(|e| {
            let e = e.ok()?;
            // Lowercase, like the ioctl's formatting, so steps 1 and 2 agree.
            let name = e.file_name().into_string().ok()?.to_ascii_lowercase();
            Some((name, e.path()))
        })
        .collect();
    links.sort();
    if major != 0 {
        let want = libc::makedev(major, minor);
        for (name, p) in &links {
            if let Ok(md) = fs::metadata(p)
                && (md.file_type().is_block_device() || md.file_type().is_char_device())
                && md.rdev() == want
            {
                return Some(name.clone());
            }
        }
    }
    if source.starts_with(b"/dev/") {
        let src = fs::canonicalize(Path::new(std::ffi::OsStr::from_bytes(source))).ok()?;
        for (name, p) in &links {
            if fs::canonicalize(p).is_ok_and(|t| t == src) {
                return Some(name.clone());
            }
        }
    }
    None
}

/// What the fallback chain needs from the system, so each step can be tested alone.
pub trait UuidProbe {
    /// Step 1, `FS_IOC_GETFSUUID`.
    fn ioctl_uuid(&self) -> Option<String>;
    /// Step 2, mountinfo + `/dev/disk/by-uuid`.
    fn by_uuid(&self, mount: &MountEntry) -> Option<String>;
    /// `/proc/sys/kernel/random/boot_id` (only read for volatile filesystems).
    fn boot_id(&self) -> Option<Vec<u8>>;
}

/// Run the `fs_uuid` chain in AGENTS.md order.
///
/// # Errors
/// [`FsidError::NoBootId`] for a UUID-less volatile filesystem without a boot id.
pub fn fs_uuid_chain(
    probe: &impl UuidProbe,
    f_type: u32,
    mount: &MountEntry,
) -> Result<(String, UuidSource)> {
    if let Some(u) = probe.ioctl_uuid() {
        return Ok((u, UuidSource::Ioctl));
    }
    if let Some(u) = probe.by_uuid(mount) {
        return Ok((u, UuidSource::ByUuid));
    }
    let boot = if classify(f_type) == FsClass::Volatile {
        probe.boot_id().ok_or(FsidError::NoBootId)?
    } else {
        Vec::new()
    };
    Ok((
        synth_id(f_type, &mount.mount_point, &mount.source, &boot),
        UuidSource::Synthetic,
    ))
}

// ---------------------------------------------------------------------------------------
// The synchronous resolver (runs on workers only)

const STATX_MASK: u32 =
    libc::STATX_BASIC_STATS | libc::STATX_BTIME | libc::STATX_MNT_ID | libc::STATX_SUBVOL;

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn open_raw(dirfd: i32, path: &CString, flags: i32) -> io::Result<OwnedFd> {
    // SAFETY: `path` is NUL-terminated and outlives the call.
    let fd = unsafe { libc::openat(dirfd, path.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh fd owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn statx_fd(fd: BorrowedFd<'_>) -> io::Result<libc::statx> {
    // SAFETY: statx is plain old data; all-zero is a valid value.
    let mut stx: libc::statx = unsafe { mem::zeroed() };
    // Cached attributes are enough for identity and avoid a network round trip.
    let flags = libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC;
    // SAFETY: valid fd, empty NUL-terminated path, `stx` is writable.
    let r = unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            flags,
            STATX_MASK,
            &raw mut stx,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stx)
}

fn fstatfs_type(fd: BorrowedFd<'_>) -> io::Result<u32> {
    // SAFETY: statfs is plain old data; all-zero is a valid value.
    let mut st: libc::statfs = unsafe { mem::zeroed() };
    // SAFETY: valid fd (O_PATH is allowed since Linux 3.12), writable `st`.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &raw mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Magics are 32-bit; f_type is a signed word whose width varies by architecture.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    Ok(st.f_type as u32)
}

fn is_opath(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: F_GETFL on a valid fd.
    let fl = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    fl < 0 || fl & libc::O_PATH != 0
}

/// A readable fd for ioctls on the same inode: the fd itself unless it is `O_PATH`, else
/// a reopen through `/proc/self/fd` (no path walk, so it cannot reach another file).
/// Only for regular files and directories: opening a device or FIFO has side effects.
///
/// Every failure is returned: `EACCES`, `EMFILE` or a missing procfs must never quietly
/// become `generation = 0`, a different key for the same file.
fn readable(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    if !is_opath(fd) {
        return fd.try_clone_to_owned();
    }
    let p = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY;
    open_raw(libc::AT_FDCWD, &p, flags)
}

fn denied(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM))
}

/// The mount's root directory, opened readable, if it is still that mount (not
/// over-mounted). Never a FIFO or device (`O_DIRECTORY`).
fn open_mount_root(mount: &MountEntry, mnt_id: u64) -> Option<OwnedFd> {
    let dir = open_raw(
        libc::AT_FDCWD,
        &cpath(&mount.mount_point_path()).ok()?,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
    )
    .ok()?;
    let stx = statx_fd(dir.as_fd()).ok()?;
    (stx.stx_mask & libc::STATX_MNT_ID != 0 && stx.stx_mnt_id == mnt_id).then_some(dir)
}

struct SysProbe<'a> {
    file: Option<BorrowedFd<'a>>,
    mount: &'a MountEntry,
    mnt_id: Option<u64>,
    f_type: u32,
    by_uuid_dir: &'a Path,
    boot_id_path: &'a Path,
}

impl SysProbe<'_> {
    fn mount_root_uuid(&self) -> Option<String> {
        // The mount's root directory gives the same superblock even when the file itself
        // is unreadable, so a mount's fs_uuid does not depend on which file came first.
        // Without a mount id there is no way to tell it is still the same mount: skip.
        // FUSE never has an s_uuid (the VFS answers ENOTTY): don't open its root (a
        // FUSE_OPENDIR round trip to the server) for nothing.
        if self.f_type == magic::FUSE {
            return None;
        }
        let dir = open_mount_root(self.mount, self.mnt_id?)?; // None if over-mounted
        ioctl_fsuuid(dir.as_fd()).ok().flatten()
    }
}

impl UuidProbe for SysProbe<'_> {
    fn ioctl_uuid(&self) -> Option<String> {
        if let Some(fd) = self.file
            && let Ok(Some(u)) = ioctl_fsuuid(fd)
        {
            return Some(u);
        }
        self.mount_root_uuid()
    }
    fn by_uuid(&self, m: &MountEntry) -> Option<String> {
        by_uuid(self.by_uuid_dir, m.major, m.minor, &m.source)
    }
    fn boot_id(&self) -> Option<Vec<u8>> {
        let mut b = fs::read(self.boot_id_path).ok()?;
        while b.last().is_some_and(u8::is_ascii_whitespace) {
            b.pop();
        }
        (!b.is_empty()).then_some(b)
    }
}

/// Where a lookup is aimed: an absolute path (opened `O_PATH | O_NOFOLLOW`, so a symlink
/// is identified as itself) or an fd the caller already holds.
#[derive(Debug)]
pub enum Target {
    Path(PathBuf),
    Fd(OwnedFd),
}

/// The real, blocking backend. Call it only from a [`Resolver`] worker.
pub struct SysBackend {
    cache: Mutex<MountCache>,
    by_uuid_dir: PathBuf,
    boot_id_path: PathBuf,
}

impl SysBackend {
    /// # Errors
    /// I/O errors reading `/proc/self/mountinfo`.
    pub fn new() -> io::Result<Self> {
        Ok(Self::with_cache(MountCache::open()?))
    }

    #[must_use]
    pub fn with_cache(cache: MountCache) -> Self {
        Self {
            cache: Mutex::new(cache),
            by_uuid_dir: PathBuf::from("/dev/disk/by-uuid"),
            boot_id_path: PathBuf::from("/proc/sys/kernel/random/boot_id"),
        }
    }

    /// Resolve a path, synchronously. Blocks as long as the filesystem does.
    ///
    /// # Errors
    /// I/O errors from `open`/`statx`/`statfs`/ioctls, or chain errors.
    pub fn identify_path(&self, path: &Path) -> Result<FileIdentity> {
        let fd = open_raw(
            libc::AT_FDCWD,
            &cpath(path)?,
            libc::O_PATH | libc::O_NOFOLLOW,
        )?;
        self.identify_fd(fd.as_fd())
    }

    /// Resolve an open fd (any open mode, `O_PATH` included), synchronously.
    ///
    /// # Errors
    /// As [`SysBackend::identify_path`]; also [`FsidError::NoSubvol`], and the reopen
    /// error (e.g. `EACCES`) when the file is unreadable on a filesystem that has
    /// generations: a key with `generation = 0` would be a different key.
    pub fn identify_fd(&self, fd: BorrowedFd<'_>) -> Result<FileIdentity> {
        let stx = statx_fd(fd)?;
        let mnt_id = (stx.stx_mask & libc::STATX_MNT_ID != 0).then_some(stx.stx_mnt_id);
        let (mount, cached) = self.mount_of(mnt_id, (stx.stx_dev_major, stx.stx_dev_minor))?;
        // f_type is per superblock: one statfs per mount (statfs is a server round trip on
        // NFS and FUSE, AT_STATX_DONT_SYNC notwithstanding).
        let f_type = match &cached {
            Some(c) => c.f_type,
            None => fstatfs_type(fd)?,
        };
        let kind = u32::from(stx.stx_mode) & libc::S_IFMT;
        // FUSE forwards FS_IOC_GETVERSION to the userspace server (not a stable key) and
        // has no s_uuid, so its files are never opened.
        let file = if (kind == libc::S_IFREG || kind == libc::S_IFDIR) && f_type != magic::FUSE {
            match readable(fd) {
                Ok(f) => Some(f),
                // Unreadable, but the filesystem has no generations at all: 0 is the
                // answer a readable fd would give, so the key is the same.
                Err(e) if denied(&e) && generation_unsupported(&mount, mnt_id) => None,
                Err(e) => return Err(e.into()),
            }
        } else {
            None
        };
        let generation = match &file {
            Some(f) => ioctl_generation(f.as_fd())?,
            None => 0,
        };
        let subvol_id = if stx.stx_mask & libc::STATX_SUBVOL != 0 {
            stx.stx_subvol
        } else if f_type == magic::BTRFS {
            // Linux < 6.10: AGENTS.md's second source. Subvolume 0 would merge every
            // subvolume and snapshot (same inode numbers, same generations).
            match &file {
                Some(f) => btrfs_subvol(f.as_fd())?,
                None => return Err(FsidError::NoSubvol),
            }
        } else {
            0
        };
        let (fs_uuid, src) = match cached {
            Some(c) => (c.uuid, c.source),
            None => self.resolve_uuid(&mount, mnt_id, f_type, file.as_ref().map(AsFd::as_fd))?,
        };
        let (btime_sec, btime_nsec) = if stx.stx_mask & libc::STATX_BTIME != 0 {
            (stx.stx_btime.tv_sec, stx.stx_btime.tv_nsec)
        } else {
            (0, 0)
        };
        Ok(FileIdentity {
            fs_uuid,
            subvol_id,
            inode_num: stx.stx_ino,
            generation,
            btime_sec,
            btime_nsec,
            fs_uuid_source: src,
        })
    }

    /// The target's mount (by mount id, else by device) and what is cached for it.
    fn mount_of(
        &self,
        mnt_id: Option<u64>,
        (major, minor): (u32, u32),
    ) -> Result<(MountEntry, Option<CachedMount>)> {
        let mut c = lock(&self.cache);
        // A failed re-read keeps the previous table (and retries next time); stale
        // entries are revalidated against the cached MountEntry before use.
        let _ = c.refresh();
        let m = mnt_id
            .and_then(|id| c.by_id(id))
            .or_else(|| c.by_dev(major, minor))
            .cloned()
            .ok_or(FsidError::UnknownMount { major, minor })?;
        let hit = c.cached(&m).cloned();
        Ok((m, hit))
    } // never hold the lock across probes: they may block on this mount

    fn resolve_uuid(
        &self,
        mount: &MountEntry,
        mnt_id: Option<u64>,
        f_type: u32,
        file: Option<BorrowedFd<'_>>,
    ) -> Result<(String, UuidSource)> {
        let probe = SysProbe {
            file,
            mount,
            mnt_id,
            f_type,
            by_uuid_dir: &self.by_uuid_dir,
            boot_id_path: &self.boot_id_path,
        };
        let (uuid, src) = fs_uuid_chain(&probe, f_type, mount)?;
        if mnt_id.is_some() {
            lock(&self.cache).uuids.insert(
                mount.mnt_id,
                CachedMount {
                    entry: mount.clone(),
                    uuid: uuid.clone(),
                    source: src,
                    f_type,
                },
            );
        }
        Ok((uuid, src))
    }
}

/// Does this mount's filesystem lack `FS_IOC_GETVERSION` altogether? Asked of its root
/// directory (same mount id only); `false` whenever that cannot be shown.
fn generation_unsupported(mount: &MountEntry, mnt_id: Option<u64>) -> bool {
    mnt_id
        .and_then(|id| open_mount_root(mount, id))
        .is_some_and(|root| matches!(ioctl_generation_opt(root.as_fd()), Ok(None)))
}

/// A mount, as far as the suspect list is concerned.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MountHint {
    pub mnt_id: u64,
    pub mount_point: PathBuf,
}

/// The blocking side of a [`Resolver`].
pub trait Backend: Send + Sync + 'static {
    /// Resolve the target. May block for as long as the filesystem does.
    ///
    /// # Errors
    /// Whatever the lookup fails with.
    fn identify(&self, target: &Target) -> Result<FileIdentity>;
    /// Which mount the target is on, WITHOUT touching it (it may be hung). `None` if
    /// unknown or if finding out could wait.
    fn mount_hint(&self, target: &Target) -> Option<MountHint>;
}

impl Backend for SysBackend {
    fn identify(&self, target: &Target) -> Result<FileIdentity> {
        match target {
            Target::Path(p) => self.identify_path(p),
            Target::Fd(fd) => self.identify_fd(fd.as_fd()),
        }
    }

    fn mount_hint(&self, target: &Target) -> Option<MountHint> {
        let path = match target {
            Target::Path(p) => p.clone(),
            // procfs readlink: d_path only, never calls into the file's filesystem.
            Target::Fd(fd) => fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()?,
        };
        let c = self.cache.try_lock().ok()?; // a worker is refreshing: skip, don't wait
        let m = mount_for_path(c.table(), &path)?;
        Some(MountHint {
            mnt_id: m.mnt_id,
            mount_point: m.mount_point_path(),
        })
    }
}

// ---------------------------------------------------------------------------------------
// The bounded, deadline-driven resolver

#[derive(Debug, Clone, Copy)]
pub struct ResolverConfig {
    /// Workers started up front.
    pub workers: usize,
    /// Hard cap on worker threads, counting ones stuck in a hung syscall (each timeout
    /// that left a worker stuck spawns one replacement until this cap).
    pub max_threads: usize,
    /// Requests that may wait for a worker; beyond this, [`FsidError::Busy`].
    pub queue: usize,
    /// How long a caller waits for an answer.
    pub deadline: Duration,
    /// How long a mount stays suspect after a timeout.
    pub suspect_for: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            workers: 4,
            max_threads: 16,
            queue: 64,
            deadline: Duration::from_millis(250),
            suspect_for: Duration::from_secs(30),
        }
    }
}

const QUEUED: u8 = 0;
const STARTED: u8 = 1;
const CANCELLED: u8 = 2;

struct Job {
    target: Arc<Target>,
    state: Arc<AtomicU8>,
    reply: SyncSender<Result<FileIdentity>>,
}

struct Shared<B> {
    backend: B,
    rx: Mutex<Receiver<Job>>,
    threads: AtomicUsize,
    max_threads: usize,
}

/// Resolves identities on bounded worker threads; the caller never waits longer than
/// the deadline, whatever state the filesystem is in.
pub struct Resolver<B: Backend> {
    shared: Arc<Shared<B>>,
    tx: SyncSender<Job>,
    cfg: ResolverConfig,
    /// Suspect until the instant, or until cleared (`None`: the configured span overflowed).
    suspects: Mutex<HashMap<MountHint, Option<Instant>>>,
}

fn spawn_worker<B: Backend>(shared: &Arc<Shared<B>>) -> bool {
    let n = shared.threads.fetch_add(1, Ordering::AcqRel);
    if n >= shared.max_threads {
        shared.threads.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    let s = Arc::clone(shared);
    let ok = thread::Builder::new()
        .name("gungnir-fsid".into())
        .spawn(move || worker(&s))
        .is_ok();
    if !ok {
        shared.threads.fetch_sub(1, Ordering::AcqRel);
    }
    ok
}

fn worker<B: Backend>(s: &Shared<B>) {
    loop {
        let job = lock(&s.rx).recv();
        let Ok(job) = job else { break }; // resolver dropped
        if job
            .state
            .compare_exchange(QUEUED, STARTED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue; // the caller gave up before we started
        }
        let r = s.backend.identify(&job.target);
        let _ = job.reply.try_send(r);
    }
    s.threads.fetch_sub(1, Ordering::AcqRel);
}

impl<B: Backend> Resolver<B> {
    /// # Errors
    /// [`FsidError::Io`] if not even one worker thread can be started.
    pub fn new(backend: B, cfg: ResolverConfig) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel(cfg.queue.max(1));
        let shared = Arc::new(Shared {
            backend,
            rx: Mutex::new(rx),
            threads: AtomicUsize::new(0),
            max_threads: cfg.max_threads.max(1),
        });
        let mut started = 0;
        for _ in 0..cfg.workers.max(1) {
            started += usize::from(spawn_worker(&shared));
        }
        if started == 0 {
            return Err(io::Error::other("cannot start an identity worker").into());
        }
        Ok(Self {
            shared,
            tx,
            cfg,
            suspects: Mutex::new(HashMap::new()),
        })
    }

    /// Live worker threads (including stuck ones).
    #[must_use]
    pub fn threads(&self) -> usize {
        self.shared.threads.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn is_suspect(&self, hint: &MountHint) -> bool {
        let mut s = lock(&self.suspects);
        match s.get(hint) {
            Some(None) => true,
            Some(Some(until)) if Instant::now() < *until => true,
            Some(_) => {
                s.remove(hint);
                false
            }
            None => false,
        }
    }

    pub fn clear_suspect(&self, hint: &MountHint) {
        lock(&self.suspects).remove(hint);
    }

    /// Resolve `target`, waiting at most the configured deadline.
    ///
    /// # Errors
    /// [`FsidError::Timeout`] (mount now suspect), [`FsidError::SuspectMount`],
    /// [`FsidError::Busy`], [`FsidError::NotAbsolute`], or the backend's error.
    pub fn resolve(&self, target: Target) -> Result<FileIdentity> {
        let start = Instant::now();
        if let Target::Path(p) = &target
            && !p.is_absolute()
        {
            return Err(FsidError::NotAbsolute(p.clone()));
        }
        let hint = self.shared.backend.mount_hint(&target);
        if let Some(h) = &hint
            && self.is_suspect(h)
        {
            return Err(FsidError::SuspectMount(h.mount_point.clone()));
        }
        let target = Arc::new(target);
        let state = Arc::new(AtomicU8::new(QUEUED));
        let (reply, rx) = mpsc::sync_channel(1);
        let job = Job {
            target: Arc::clone(&target),
            state: Arc::clone(&state),
            reply,
        };
        match self.tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(FsidError::Busy),
            Err(TrySendError::Disconnected(_)) => return Err(FsidError::Shutdown),
        }
        let left = self.cfg.deadline.saturating_sub(start.elapsed());
        match rx.recv_timeout(left) {
            Ok(r) => return r,
            Err(RecvTimeoutError::Disconnected) => return Err(FsidError::Shutdown),
            Err(RecvTimeoutError::Timeout) => {}
        }
        if state
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Never reached a worker: the pool is busy, not necessarily this mount.
            return Err(FsidError::Busy);
        }
        if let Ok(r) = rx.try_recv() {
            return r; // finished right at the deadline
        }
        // A worker is stuck on this target: mark its mount and keep the pool's capacity.
        // The first hint may have been skipped (cache busy): ask again, still lock-free.
        if let Some(h) = hint.or_else(|| self.shared.backend.mount_hint(&target)) {
            let until = Instant::now().checked_add(self.cfg.suspect_for);
            lock(&self.suspects).insert(h, until);
        }
        spawn_worker(&self.shared);
        Err(FsidError::Timeout(self.cfg.deadline))
    }
}

#[cfg(test)]
mod tests;
