//! The user's trash (milestone 9): the FreeDesktop Trash specification 1.0, read and
//! emptied by the daemon; putting files in is GLocalFile's own `g_file_trash`.
//!
//! Trash directories: the home trash (`$XDG_DATA_HOME/Trash`), and on each other mount
//! `$top/.Trash/$uid` (`.Trash` must be a real, sticky directory) and `$top/.Trash-$uid`.
//! Mounts the health monitor reports hung or gone are never touched.
//!
//! An item is `info/<e>.trashinfo` plus `files/<e>`. The rules here all serve one
//! promise, that no operation can lose track of a file:
//! - A bad entry never fails a page: unreadable or malformed info, a relative `Path=`, a
//!   payload that cannot be examined: the item is listed degraded and can be deleted.
//! - A delete checks that the info entry can be removed BEFORE touching the payload, and
//!   removes it AFTER the payload is gone: a failed delete leaves the item listed and
//!   retryable, and no payload ever vanishes while its failure has no record.
//! - A crash between the two leaves an orphan `.trashinfo`: not listed, removed by empty.
//! - The trash directories themselves must be real directories, never symlinks, so a
//!   `Trash/files` symlink cannot aim a delete at anything else.
//!
//! Restoring takes an absolute `Path=` only from the home trash; on another volume the
//! path must stay inside that volume.

use std::{
    ffi::{CStr, CString, OsStr},
    fs::{self, File},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::{Mutex, MutexGuard, TryLockError},
    thread,
    time::{Duration, Instant},
};

/// Longest `.trashinfo` read; anything bigger is listed degraded.
const INFO_MAX: u64 = 64 * 1024;
/// Longest `Path=` taken: no real path is longer, and a volume could ship thousands of
/// hard links to one huge info file.
const PATH_LEN_MAX: usize = libc::PATH_MAX as usize;
/// Longest `DeletionDate=` taken; a real one is 19 bytes.
const DATE_LEN_MAX: usize = 64;
/// Text one listing holds across every trash, on top of [`SCAN_MAX`]: subvolumes make
/// trash directories cheap, so the bound cannot be per directory.
pub const SCAN_BYTES_MAX: usize = 64 << 20;
/// How old an info file with no payload must be to count as an orphan: `g_file_trash`
/// writes the info first, and in between it is a file on its way in.
const ORPHAN_AGE_SECS: i64 = 10;
const HOME_VOLUME: &str = "h";
/// Entries read from one trash directory: a volume is foreign media, and its list is not
/// allowed to grow the daemon without bound.
pub const SCAN_MAX: usize = 1 << 17;
/// Largest `directorysizes` rewritten; a bigger one is left alone, it is only a cache.
const SIZES_MAX: u64 = 1 << 20;
/// Request threads delete at the same time; each rewrite must see the last one's result.
static SIZES: Mutex<()> = Mutex::new(());
/// How long a delete waits for that turn. The cache may go stale, a request must not stick.
const SIZES_WAIT: Duration = Duration::from_secs(1);

/// The two directories of a trash, held open.
#[derive(Debug)]
pub struct Pins {
    pub files: OwnedFd,
    pub info: OwnedFd,
}

/// One trash directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashDir {
    /// The directory holding `files` and `info`.
    pub dir: PathBuf,
    /// What a relative `Path=` is relative to.
    pub top: PathBuf,
    /// The home trash takes absolute paths anywhere.
    pub home: bool,
}

/// Kinds of payload, as on the wire.
pub const KIND_FILE: u8 = 1;
pub const KIND_DIR: u8 = 2;
pub const KIND_SYMLINK: u8 = 3;
pub const KIND_SPECIAL: u8 = 4;

/// One listed item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The URI name: `<volume>-<entry>`.
    pub name: Vec<u8>,
    /// The name in `files/`.
    pub entry: Vec<u8>,
    /// Where it came from, empty if its info is unusable.
    pub orig: Vec<u8>,
    /// Absolute path of the payload.
    pub target: Vec<u8>,
    pub kind: u8,
    pub size: u64,
    pub mtime: i64,
    /// `DeletionDate=` as written, empty if none.
    pub deleted: Vec<u8>,
    /// A symlink payload's target.
    pub link: Vec<u8>,
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

impl TrashDir {
    fn volume(&self) -> String {
        if self.home {
            HOME_VOLUME.into()
        } else {
            hex(self.dir.as_os_str().as_bytes())
        }
    }

    #[must_use]
    pub fn files(&self) -> PathBuf {
        self.dir.join("files")
    }

    #[must_use]
    pub fn info(&self) -> PathBuf {
        self.dir.join("info")
    }

    /// Open a directory of this trash, walking down from `top` without following any
    /// link. Everything done through the descriptor stays in the directory that was
    /// checked: replacing a component with a symlink afterwards changes nothing.
    fn pin(&self, sub: Option<&str>) -> io::Result<OwnedFd> {
        let rel = self
            .dir
            .strip_prefix(&self.top)
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let mut cur = open_at(
            libc::AT_FDCWD,
            &c_path(self.top.as_os_str().as_bytes())?,
            DIR,
        )?;
        for part in rel.components() {
            let Component::Normal(n) = part else {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            };
            cur = open_at(
                cur.as_raw_fd(),
                &c_path(n.as_bytes())?,
                DIR | libc::O_NOFOLLOW,
            )?;
        }
        if let Some(n) = sub {
            cur = open_at(
                cur.as_raw_fd(),
                &c_path(n.as_bytes())?,
                DIR | libc::O_NOFOLLOW,
            )?;
        }
        mine(&cur)?;
        Ok(cur)
    }

    /// `files/` and `info/`, for one operation on one item: both are then the same trash
    /// from its first check to its last step.
    ///
    /// # Errors
    /// See [`Self::pin_files`].
    pub fn pins(&self) -> io::Result<Pins> {
        // Both from one held `dir`: two walks could land in two different trashes.
        let base = self.pin(None)?;
        let sub = |n: &CStr| {
            let fd = open_at(base.as_raw_fd(), n, DIR | libc::O_NOFOLLOW)?;
            mine(&fd)?;
            Ok::<_, io::Error>(fd)
        };
        Ok(Pins {
            files: sub(c"files")?,
            info: sub(c"info")?,
        })
    }

    /// `files/`, pinned for operations on the payloads.
    ///
    /// # Errors
    /// A component is missing, a symlink, or someone else's.
    pub fn pin_files(&self) -> io::Result<OwnedFd> {
        self.pin(Some("files"))
    }

    fn payload(&self, entry: &[u8]) -> PathBuf {
        self.files().join(OsStr::from_bytes(entry))
    }
}

/// A file name of one component.
#[must_use]
pub fn valid_entry(e: &[u8]) -> bool {
    !e.is_empty() && e != b"." && e != b".." && !e.contains(&b'/') && !e.contains(&0)
}

/// Split a URI name into its trash directory's volume and the entry.
fn split_name(name: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = name.iter().position(|&b| b == b'-')?;
    let (v, e) = (&name[..at], &name[at + 1..]);
    valid_entry(e).then_some((v, e))
}

/// The directory a URI name's volume part names; `None` for the home trash or a bad name.
#[must_use]
pub fn volume_of(name: &[u8]) -> Option<PathBuf> {
    let (v, _) = split_name(name)?;
    if v == HOME_VOLUME.as_bytes() {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(&unhex(v)?)))
}

const DIR: i32 = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;

/// A trash directory is the user's own, however it was reached.
fn mine(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: plain getter.
    if stat_at(fd.as_raw_fd(), c"")?.st_uid != unsafe { libc::geteuid() } {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}

fn c_path(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn open_at(dir: RawFd, name: &CStr, flags: i32) -> io::Result<OwnedFd> {
    // SAFETY: valid NUL-terminated name; the result is checked before it is owned.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `lstat` relative to `dir`; an empty name is `dir` itself.
fn stat_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: an all-zero stat is valid, and the kernel only writes to it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let flags = libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
    // SAFETY: valid name and out pointer.
    if unsafe { libc::fstatat(dir, name.as_ptr(), &raw mut st, flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn unlink_at(dir: RawFd, name: &CStr, flags: i32) -> io::Result<()> {
    // SAFETY: valid NUL-terminated name.
    if unsafe { libc::unlinkat(dir, name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The way to list a pinned directory: `std` can only open a directory by path.
fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn info_name(entry: &[u8]) -> io::Result<CString> {
    c_path(&[entry, b".trashinfo"].concat())
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// The trash directory a URI name belongs to, among those known. A volume is matched
/// against the list, so a name can never point at a directory of its own choosing.
#[must_use]
pub fn resolve<'a>(dirs: &'a [TrashDir], name: &[u8]) -> Option<(&'a TrashDir, Vec<u8>)> {
    let (v, e) = split_name(name)?;
    let wanted = if v == HOME_VOLUME.as_bytes() {
        None
    } else {
        Some(unhex(v)?)
    };
    dirs.iter()
        .find(|d| match &wanted {
            None => d.home,
            Some(p) => !d.home && d.dir.as_os_str().as_bytes() == p.as_slice(),
        })
        .map(|d| (d, e.to_vec()))
}

/// `path` is a real directory (no symlink) owned by `uid`.
fn own_dir(path: &Path, uid: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir() && m.uid() == uid)
}

/// The home trash directory, from the environment's values.
#[must_use]
pub fn home_dir(xdg_data: Option<&OsStr>, home: Option<&OsStr>) -> Option<TrashDir> {
    let data = xdg_data
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            home.map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|h| h.join(".local/share"))
        })?;
    Some(TrashDir {
        dir: data.join("Trash"),
        top: data,
        home: true,
    })
}

/// The trash directories below mount point `top`: those that exist and pass the
/// specification's checks. Nothing is created.
#[must_use]
pub fn volume_dirs(top: &Path, uid: u32) -> Vec<TrashDir> {
    let mut out = Vec::new();
    let shared = top.join(".Trash");
    // The shared directory must be sticky and no symlink; its $uid part must be ours.
    let sticky = fs::symlink_metadata(&shared)
        .is_ok_and(|m| m.file_type().is_dir() && m.mode() & 0o1000 != 0);
    if sticky {
        let d = shared.join(uid.to_string());
        if own_dir(&d, uid) {
            out.push(TrashDir {
                dir: d,
                top: top.to_path_buf(),
                home: false,
            });
        }
    }
    let d = top.join(format!(".Trash-{uid}"));
    if own_dir(&d, uid) {
        out.push(TrashDir {
            dir: d,
            top: top.to_path_buf(),
            home: false,
        });
    }
    out
}

/// `files/` and `info/` are real directories owned by `uid` (a symlink is refused).
#[must_use]
pub fn sound(d: &TrashDir, uid: u32) -> bool {
    own_dir(&d.dir, uid) && own_dir(&d.files(), uid) && own_dir(&d.info(), uid)
}

/// Whether `d` is a trash that exists but cannot be used. Absent directories are simply
/// nothing to list; anything else that is not [`sound`] may hide items, so it can never
/// count as empty.
#[must_use]
pub fn unusable(d: &TrashDir, uid: u32) -> bool {
    // Only "no such file" is absence: a stat that fails any other way cannot say so.
    let absent =
        |p: &Path| matches!(fs::symlink_metadata(p), Err(e) if e.kind() == io::ErrorKind::NotFound);
    !absent(&d.dir) && (!absent(&d.files()) || !own_dir(&d.dir, uid)) && !sound(d, uid)
}

/// A restore to `dest` stays where `d` allows it: on a volume, the directory it lands in
/// must really be on that volume, or foreign media could steer a file into, say, the
/// user's autostart directory. (The home trash is the user's own and needs no such check.)
/// The path is walked one component at a time from a held top, reading each link instead
/// of following it: a link that stays on the volume works, even an absolute one, and one
/// that leaves it is refused without ever touching what it points at (that may be a hung
/// mount). A link planted mid-walk fails `O_NOFOLLOW`. The result goes on meaning that
/// directory whatever happens to the path.
#[must_use]
pub fn restore_parent(d: &TrashDir, dest: &[u8]) -> Option<OwnedFd> {
    const LINKS_MAX: usize = 40; // the kernel's own limit
    let parent = Path::new(OsStr::from_bytes(dest)).parent()?;
    let mut left: Vec<Vec<u8>> = parts(parent.strip_prefix(&d.top).ok()?);
    left.reverse();
    let top = c_path(d.top.as_os_str().as_bytes()).ok()?;
    let top = open_at(libc::AT_FDCWD, &top, DIR).ok()?;
    // One descriptor and the way there: `..` walks down again from the top, so depth costs
    // no descriptors and `..` can never rise past where the walk came from.
    let mut cur: Option<OwnedFd> = None;
    let mut at: Vec<Vec<u8>> = Vec::new();
    let mut links = 0;
    while let Some(part) = left.pop() {
        if part == b".." {
            at.pop()?;
            cur = None;
            for name in &at {
                let from = cur.as_ref().unwrap_or(&top).as_raw_fd();
                let name = c_path(name).ok()?;
                cur = Some(open_at(from, &name, DIR | libc::O_NOFOLLOW).ok()?);
            }
            continue;
        }
        let from = cur.as_ref().unwrap_or(&top).as_raw_fd();
        let name = c_path(&part).ok()?;
        if stat_at(from, &name).ok()?.st_mode & libc::S_IFMT != libc::S_IFLNK {
            cur = Some(open_at(from, &name, DIR | libc::O_NOFOLLOW).ok()?);
            at.push(part);
            continue;
        }
        links += 1;
        if links > LINKS_MAX {
            return None;
        }
        let to = read_link_at(from, &name).ok()?;
        let to = Path::new(OsStr::from_bytes(&to));
        let mut more = if to.is_absolute() {
            cur = None;
            at.clear();
            parts(to.strip_prefix(&d.top).ok()?)
        } else {
            parts(to)
        };
        more.reverse();
        left.append(&mut more);
    }
    Some(cur.unwrap_or(top))
}

/// A relative path's components; `.` means nothing here.
fn parts(p: &Path) -> Vec<Vec<u8>> {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.as_bytes().to_vec()),
            Component::ParentDir => Some(b"..".to_vec()),
            _ => None,
        })
        .collect()
}

fn read_link_at(dir: RawFd, name: &CStr) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: writes at most buf.len() bytes into `buf`.
    let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// The parsed content of a `.trashinfo`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Info {
    /// Percent-decoded `Path=`.
    pub path: Vec<u8>,
    pub deleted: Vec<u8>,
}

fn percent_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let h = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    (!out.contains(&0)).then_some(out)
}

/// Parse a `.trashinfo`; `None` unless it has the group and a usable `Path=`.
#[must_use]
pub fn parse_info(text: &[u8]) -> Option<Info> {
    let mut in_group = false;
    let mut info = Info::default();
    for line in text.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.first() == Some(&b'[') {
            in_group = line == b"[Trash Info]";
        } else if in_group {
            if let Some(v) = line.strip_prefix(b"Path=") {
                info.path = percent_decode(v)?;
            } else if let Some(v) = line.strip_prefix(b"DeletionDate=") {
                info.deleted = v.to_vec();
            }
        }
    }
    if info.deleted.len() > DATE_LEN_MAX {
        info.deleted.clear();
    }
    (!info.path.is_empty() && info.path.len() <= PATH_LEN_MAX).then_some(info)
}

/// Read a small regular file without following a link, blocking on a FIFO, taking a
/// terminal or reading more than `max` bytes, whatever its metadata claims.
fn read_capped(dir: RawFd, name: &CStr, max: u64) -> io::Result<Vec<u8>> {
    let flags =
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    let f = File::from(open_at(dir, name, flags)?);
    if !f.metadata()?.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut out = Vec::new();
    f.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    Ok(out)
}

/// The absolute path an info's `Path=` means in `d`, `None` if it has no safe meaning.
/// Outside the home trash an absolute path must lie on the volume itself.
#[must_use]
pub fn original_path(d: &TrashDir, path: &[u8]) -> Option<Vec<u8>> {
    // One spelling for a path: what clients send back has been through GFile, and every
    // comparison with it has to mean the same place.
    let body = path.strip_prefix(b"/").unwrap_or(path);
    if body
        .split(|&b| b == b'/')
        .any(|c| c.is_empty() || c == b"." || c == b"..")
    {
        return None;
    }
    let top = d.top.as_os_str().as_bytes();
    if path.first() == Some(&b'/') {
        if d.home {
            return Some(path.to_vec());
        }
        let under = path.strip_prefix(top)?;
        return (top == b"/" || under.first() == Some(&b'/')).then(|| path.to_vec());
    }
    let mut out = top.to_vec();
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(path);
    Some(out)
}

fn kind_of(st: &libc::stat) -> u8 {
    match st.st_mode & libc::S_IFMT {
        libc::S_IFLNK => KIND_SYMLINK,
        libc::S_IFDIR => KIND_DIR,
        libc::S_IFREG => KIND_FILE,
        _ => KIND_SPECIAL,
    }
}

/// One item from its entry name.
#[must_use]
pub fn read_item(d: &TrashDir, entry: &[u8]) -> Item {
    let (files, info) = (d.pin_files().ok(), d.pin(Some("info")).ok());
    item_at(d, files.as_ref(), info.as_ref(), entry)
}

/// One item through a held pair.
#[must_use]
pub fn item_in(d: &TrashDir, pins: &Pins, entry: &[u8]) -> Item {
    item_at(d, Some(&pins.files), Some(&pins.info), entry)
}

/// One item through its pinned directories; one that could not be pinned degrades it.
fn item_at(d: &TrashDir, files: Option<&OwnedFd>, info: Option<&OwnedFd>, entry: &[u8]) -> Item {
    let payload = d.payload(entry);
    // A payload that cannot be examined is still an item (A-T005-1).
    let st = files.and_then(|f| stat_at(f.as_raw_fd(), &c_path(entry).ok()?).ok());
    let (kind, size, mtime) = match st {
        Some(s) => (kind_of(&s), s.st_size as u64, s.st_mtime),
        None => (KIND_SPECIAL, 0, 0),
    };
    let link = (kind == KIND_SYMLINK)
        .then(|| read_link_at(files?.as_raw_fd(), &c_path(entry).ok()?).ok())
        .flatten()
        .unwrap_or_default();
    let info = info
        .and_then(|f| read_capped(f.as_raw_fd(), &info_name(entry).ok()?, INFO_MAX).ok())
        .and_then(|t| parse_info(&t));
    let (orig, deleted) = match info {
        Some(i) => (
            original_path(d, &i.path).unwrap_or_default(),
            i.deleted.clone(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    let mut name = d.volume().into_bytes();
    name.push(b'-');
    name.extend_from_slice(entry);
    Item {
        name,
        entry: entry.to_vec(),
        orig,
        target: payload.as_os_str().as_bytes().to_vec(),
        kind,
        size,
        mtime,
        deleted,
        link,
    }
}

/// List a trash directory. Per-entry trouble degrades that entry; only an unusable
/// directory is an error. An info file with no payload is an orphan: not listed.
///
/// # Errors
/// `files/` cannot be read.
pub fn scan(d: &TrashDir) -> io::Result<Vec<Item>> {
    scan_capped(d, &mut SCAN_BYTES_MAX.clone())
}

/// [`scan`] out of a budget of text shared with other directories; it runs out to 0.
///
/// # Errors
/// `files/` cannot be read.
pub fn scan_capped(d: &TrashDir, left: &mut usize) -> io::Result<Vec<Item>> {
    let files = d.pin_files()?;
    let info = d.pin(Some("info")).ok();
    let mut items = Vec::new();
    for e in fs::read_dir(fd_path(&files))?.take(SCAN_MAX) {
        if *left == 0 {
            break;
        }
        let name = e?.file_name();
        let it = item_at(d, Some(&files), info.as_ref(), name.as_bytes());
        let bytes =
            it.name.len() + it.orig.len() + it.target.len() + it.deleted.len() + it.link.len();
        *left = left.saturating_sub(bytes);
        items.push(it);
    }
    Ok(items)
}

/// Directories right below `root` on another device with no mount needed: subvolumes.
/// `skip` says which must not be looked at (a mount point known hung). Mount points turn
/// up here too; they are volumes as well, and the caller drops duplicates.
#[must_use]
pub fn subvolume_tops(root: &Path, skip: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
    const ENTRIES_MAX: usize = 4096;
    let Ok(dev) = fs::symlink_metadata(root).map(|m| m.dev()) else {
        return Vec::new();
    };
    let Ok(it) = fs::read_dir(root) else {
        return Vec::new();
    };
    it.take(ENTRIES_MAX)
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        // Btrfs answers for itself, snapshots told apart (`btrfs.rs`).
        .filter(|p| {
            !skip(p)
                && fs::symlink_metadata(p).is_ok_and(|m| m.dev() != dev)
                && !crate::btrfs::is_btrfs(p)
        })
        .collect()
}

/// Clear the orphans of a trash whose `files/` is empty: what `gio trash --empty` and file
/// managers leave, as they delete item by item and never send the daemon's empty.
///
/// Returns whether an orphan that should have gone is still there: nothing lists one, so
/// this is the only way a client can hear of it.
pub fn sweep_if_empty(d: &TrashDir) -> bool {
    let Ok(Pins { files, info }) = d.pins() else {
        return false;
    };
    if !fs::read_dir(fd_path(&files)).is_ok_and(|mut it| it.next().is_none()) {
        return false;
    }
    let _ = remove_orphans(d);
    // Unreadable: nothing says it is clean.
    let Ok(it) = fs::read_dir(fd_path(&info)) else {
        return true;
    };
    it.flatten().any(|e| {
        let name = e.file_name();
        name.as_bytes()
            .strip_suffix(b".trashinfo")
            .is_some_and(|n| valid_entry(n) && settled(&info, n))
    })
}

/// Whether `d` holds an orphan that should have gone, with `items` its listing. An orphan
/// is on no list, so this is the only way a client can hear of one. Clears what it can.
#[must_use]
pub fn stuck_orphans(d: &TrashDir, items: &[Item]) -> bool {
    let Ok(pins) = d.pins() else {
        return false;
    };
    let listed: std::collections::HashSet<&[u8]> =
        items.iter().map(|i| i.entry.as_slice()).collect();
    let orphan = || -> io::Result<bool> {
        let mut seen = 0;
        for e in fs::read_dir(fd_path(&pins.info))? {
            // No end of it in sight: nothing says the rest is clean.
            seen += 1;
            if seen > SCAN_MAX {
                return Ok(true);
            }
            let name = e?.file_name();
            let Some(entry) = name.as_bytes().strip_suffix(b".trashinfo") else {
                continue;
            };
            if valid_entry(entry)
                && !listed.contains(entry)
                && settled(&pins.info, entry)
                && matches!(stat_payload(&pins.files, entry), Err(e) if e.kind() == io::ErrorKind::NotFound)
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    match orphan() {
        Ok(false) => false,
        Ok(true) => {
            let _ = remove_orphans(d);
            orphan().unwrap_or(true)
        }
        // Unreadable: nothing says it is clean.
        Err(_) => true,
    }
}

/// Whether anything is left now: what an empty asks once it has finished. A payload, or
/// an info entry that could not be removed.
///
/// # Errors
/// `files/` or `info/` cannot be read.
pub fn has_items(d: &TrashDir) -> io::Result<bool> {
    let pins = d.pins()?;
    if fs::read_dir(fd_path(&pins.files))?.next().is_some() {
        return Ok(true);
    }
    for e in fs::read_dir(fd_path(&pins.info))? {
        let name = e?.file_name();
        // Only the info of a possible item: `.trashinfo` alone names none.
        if name
            .as_bytes()
            .strip_suffix(b".trashinfo")
            .is_some_and(valid_entry)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `entry`'s payload in a pinned `files/`, for its existence and nothing else.
///
/// # Errors
/// It is absent, or cannot be examined.
pub fn stat_payload(files: &OwnedFd, entry: &[u8]) -> io::Result<()> {
    stat_at(files.as_raw_fd(), &c_path(entry)?).map(|_| ())
}

/// No info entry: absent, or a payload name with no room for the `.trashinfo` suffix.
fn no_such_info(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENAMETOOLONG)
}

/// Check that the info entry of `entry` can be removed, before the payload is touched
/// (BC-T005-F1): `info/` is writable, and what is there is removable. Absent is fine: the
/// payload is an item of its own then. A non-empty directory there refuses.
///
/// # Errors
/// The errno that would stop the removal.
pub fn check_info_removable(d: &TrashDir, entry: &[u8]) -> Result<(), i32> {
    let dir = d
        .pin(Some("info"))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    check_info_removable_at(&dir, entry)
}

/// [`check_info_removable`] in a held `info/`.
///
/// # Errors
/// The errno that would stop the removal.
pub fn check_info_removable_at(dir: &OwnedFd, entry: &[u8]) -> Result<(), i32> {
    let errno = |e: io::Error| e.raw_os_error().unwrap_or(libc::EIO);
    // SAFETY: valid NUL-terminated path, and "." is the pinned directory itself.
    if unsafe { libc::faccessat(dir.as_raw_fd(), c".".as_ptr(), libc::W_OK | libc::X_OK, 0) } != 0 {
        return Err(errno(io::Error::last_os_error()));
    }
    let name = info_name(entry).map_err(errno)?;
    match stat_at(dir.as_raw_fd(), &name) {
        Err(e) if no_such_info(&e) => Ok(()),
        Err(e) => Err(errno(e)),
        Ok(st) if is_dir(&st) => {
            let sub = open_at(dir.as_raw_fd(), &name, DIR | libc::O_NOFOLLOW).map_err(errno)?;
            match fs::read_dir(fd_path(&sub)).map_err(errno)?.next() {
                None => Ok(()),
                Some(_) => Err(libc::ENOTEMPTY),
            }
        }
        Ok(_) => Ok(()),
    }
}

/// Remove the info entry and the item's `directorysizes` line, after the payload went.
///
/// # Errors
/// The removal failed; the payload is gone by then, and the error says so to the caller.
pub fn remove_info(d: &TrashDir, entry: &[u8]) -> io::Result<()> {
    let dir = d.pin(Some("info"));
    match dir {
        Ok(dir) => remove_info_at(d, &dir, entry),
        Err(e) => {
            let _ = drop_size_line(d, entry);
            Err(e)
        }
    }
}

/// [`remove_info`] in a held `info/`: the entry checked is the entry removed.
///
/// # Errors
/// See [`remove_info`].
pub fn remove_info_at(d: &TrashDir, dir: &OwnedFd, entry: &[u8]) -> io::Result<()> {
    let r = (|| {
        let name = info_name(entry)?;
        match stat_at(dir.as_raw_fd(), &name) {
            Err(e) if no_such_info(&e) => Ok(()),
            Err(e) => Err(e),
            Ok(st) if is_dir(&st) => unlink_at(dir.as_raw_fd(), &name, libc::AT_REMOVEDIR),
            Ok(_) => unlink_at(dir.as_raw_fd(), &name, 0),
        }
    })();
    // The cache is only a cache: a stale line makes readers rescan, so failing to drop
    // it is not worth reporting.
    let _ = drop_size_line(d, entry);
    r
}

/// `m`, within `wait`.
fn turn(m: &Mutex<()>, wait: Duration) -> Option<MutexGuard<'_, ()>> {
    let t0 = Instant::now();
    loop {
        match m.try_lock() {
            Ok(g) => return Some(g),
            Err(TryLockError::Poisoned(e)) => return Some(e.into_inner()),
            Err(TryLockError::WouldBlock) if t0.elapsed() >= wait => return None,
            Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(1)),
        }
    }
}

/// Remove `entry`'s line from `directorysizes`, atomically (`<size> <mtime> <encoded>`).
fn drop_size_line(d: &TrashDir, entry: &[u8]) -> io::Result<()> {
    let Some(_serial) = turn(&SIZES, SIZES_WAIT) else {
        return Ok(());
    };
    let dir = d.pin(None)?;
    let dirfd = dir.as_raw_fd();
    let text = match read_capped(dirfd, c"directorysizes", SIZES_MAX) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EFBIG) => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::with_capacity(text.len());
    let mut changed = false;
    for line in text.split_inclusive(|&b| b == b'\n') {
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let name = body.splitn(3, |&b| b == b' ').nth(2);
        if name.and_then(percent_decode).as_deref() == Some(entry) {
            changed = true;
        } else {
            out.extend_from_slice(line);
        }
    }
    if !changed {
        return Ok(());
    }
    let tmp = c_path(format!(".directorysizes-{}", std::process::id()).as_bytes())?;
    // The name may already be planted: drop it, then create exclusively (no link is followed).
    match unlink_at(dirfd, &tmp, 0) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
    let mut f = File::from(open_at(dirfd, &tmp, flags)?);
    let written = f.write_all(&out);
    drop(f);
    // SAFETY: valid NUL-terminated names.
    let r = written.and_then(|()| {
        if unsafe { libc::renameat(dirfd, tmp.as_ptr(), dirfd, c"directorysizes".as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    });
    if r.is_err() {
        let _ = unlink_at(dirfd, &tmp, 0);
    }
    r
}

/// Whether an info file has been there long enough not to be a trash in progress.
fn settled(info: &OwnedFd, entry: &[u8]) -> bool {
    // SAFETY: time(NULL) only returns the clock.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    match info_name(entry).and_then(|n| stat_at(info.as_raw_fd(), &n)) {
        // From the future (clock skew, a FAT volume): no age can be told, so none is waited.
        Ok(st) => !(0..ORPHAN_AGE_SECS).contains(&now.saturating_sub(st.st_mtime)),
        Err(e) => e.kind() != io::ErrorKind::NotFound,
    }
}

/// Info files whose payload is gone: what a crash between the two removals leaves.
/// Removes them; returns how many went.
#[must_use]
pub fn remove_orphans(d: &TrashDir) -> usize {
    let Ok(Pins { files, info }) = d.pins() else {
        return 0;
    };
    let Ok(it) = fs::read_dir(fd_path(&info)) else {
        return 0;
    };
    let mut n = 0;
    for e in it.flatten() {
        let name = e.file_name();
        let Some(entry) = name
            .as_bytes()
            .strip_suffix(b".trashinfo")
            .filter(|e| valid_entry(e))
        else {
            continue;
        };
        // Only a payload known to be gone makes an orphan: any other failure may be
        // hiding a file whose info is all that says where it belongs.
        let gone =
            matches!(stat_payload(&files, entry), Err(e) if e.kind() == io::ErrorKind::NotFound);
        if gone && settled(&info, entry) && remove_info_at(d, &info, entry).is_ok() {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct T(PathBuf);

    impl T {
        fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build/tmp");
            let p = base.join(format!("tr-{tag}-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn trash(&self) -> TrashDir {
            let d = TrashDir {
                dir: self.0.join("Trash"),
                top: self.0.clone(),
                home: true,
            };
            fs::create_dir_all(d.files()).unwrap();
            fs::create_dir_all(d.info()).unwrap();
            d
        }
    }

    impl Drop for T {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn item(d: &TrashDir, e: &str, path: &str) {
        fs::write(d.files().join(e), b"data").unwrap();
        let text = format!("[Trash Info]\nPath={path}\nDeletionDate=2026-10-31T10:00:00\n");
        fs::write(d.info().join(format!("{e}.trashinfo")), text).unwrap();
    }

    #[test]
    fn info_parsing() {
        let i = parse_info(b"[Trash Info]\nPath=/a%20b\nDeletionDate=x\n").unwrap();
        assert_eq!(
            (i.path.as_slice(), i.deleted.as_slice()),
            (&b"/a b"[..], &b"x"[..])
        );
        assert!(parse_info(b"Path=/outside/the/group\n").is_none());
        assert!(parse_info(b"[Other]\nPath=/a\n").is_none());
        assert!(parse_info(b"[Trash Info]\nPath=/a%zz\n").is_none());
        assert!(parse_info(b"[Trash Info]\nPath=/a%00b\n").is_none());
        assert!(parse_info(b"").is_none());
    }

    /// SEC-F-001: a relative, bad or unreadable entry never fails the page.
    #[test]
    fn a_bad_entry_never_fails_the_page() {
        let t = T::new("page");
        let d = t.trash();
        item(&d, "good", "/home/u/good");
        item(&d, "relative", "docs/rel");
        fs::write(d.files().join("malformed"), b"x").unwrap();
        fs::write(d.info().join("malformed.trashinfo"), b"garbage\0\xff").unwrap();
        fs::write(d.files().join("noinfo"), b"x").unwrap();
        fs::write(d.files().join("dirinfo"), b"x").unwrap();
        fs::create_dir(d.info().join("dirinfo.trashinfo")).unwrap();
        fs::write(d.files().join("sock"), b"x").unwrap();
        // A FIFO opens with ENXIO-class trouble of its own; opening must never block.
        let fifo = CString::new(d.info().join("sock.trashinfo").as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        fs::write(d.files().join("locked"), b"x").unwrap();
        let locked = d.info().join("locked.trashinfo");
        fs::write(&locked, b"[Trash Info]\nPath=/x\n").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o0)).unwrap();
        let items = scan(&d).unwrap();
        assert_eq!(items.len(), 7);
        let get = |n: &[u8]| items.iter().find(|i| i.entry == n).unwrap();
        assert_eq!(get(b"good").orig, b"/home/u/good");
        assert_eq!(get(b"good").deleted, b"2026-10-31T10:00:00");
        let mut rel = t.0.as_os_str().as_bytes().to_vec();
        rel.extend_from_slice(b"/docs/rel");
        assert_eq!(get(b"relative").orig, rel);
        for bad in [&b"malformed"[..], b"noinfo", b"dirinfo", b"sock"] {
            assert_eq!(get(bad).orig, b"", "{}", String::from_utf8_lossy(bad));
            assert_eq!(get(bad).kind, KIND_FILE);
        }
        // SAFETY: plain getter.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(get(b"locked").orig, b"");
        }
    }

    /// An orphan .trashinfo is not listed, and empty removes it (the crash window).
    #[test]
    fn orphans_are_not_listed_and_can_be_removed() {
        let t = T::new("orphan");
        let d = t.trash();
        item(&d, "kept", "/k");
        let gone = d.info().join("gone.trashinfo");
        fs::write(&gone, b"[Trash Info]\nPath=/g\n").unwrap();
        assert_eq!(scan(&d).unwrap().len(), 1);
        // Just written: g_file_trash may be about to rename its payload in.
        assert_eq!(remove_orphans(&d), 0);
        let then = std::time::SystemTime::now() - Duration::from_secs(60);
        File::options()
            .write(true)
            .open(&gone)
            .unwrap()
            .set_modified(then)
            .unwrap();
        // A future date tells nothing, and must not keep it for ever.
        let later = std::time::SystemTime::now() + Duration::from_secs(1 << 20);
        File::options()
            .write(true)
            .open(&gone)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(remove_orphans(&d), 1);
        assert!(!d.info().join("gone.trashinfo").exists());
        fs::write(&gone, b"x").unwrap();
        File::options()
            .write(true)
            .open(&gone)
            .unwrap()
            .set_modified(then)
            .unwrap();
        fs::remove_file(d.files().join("kept")).unwrap();
        fs::remove_file(d.info().join("kept.trashinfo")).unwrap();
        assert!(!sweep_if_empty(&d));
        assert!(!gone.exists(), "the last delete takes the orphans along");
        let stuck = d.info().join("stuck.trashinfo");
        fs::create_dir_all(stuck.join("x")).unwrap();
        File::open(&stuck).unwrap().set_modified(then).unwrap();
        assert!(sweep_if_empty(&d), "one that would not go is reported");
        fs::remove_dir_all(&stuck).unwrap();
        fs::set_permissions(d.info(), fs::Permissions::from_mode(0o300)).unwrap();
        let unreadable = sweep_if_empty(&d);
        fs::set_permissions(d.info(), fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: plain getter.
        assert!(unreadable || unsafe { libc::geteuid() } == 0);
        item(&d, "kept", "/k");
        assert!(d.info().join("kept.trashinfo").exists());
    }

    /// BC-T005-F1: a directory at the info path.
    #[test]
    fn a_directory_at_the_info_path_is_checked_before_the_payload() {
        let t = T::new("infodir");
        let d = t.trash();
        fs::create_dir(d.info().join("e.trashinfo")).unwrap();
        assert_eq!(check_info_removable(&d, b"e"), Ok(()));
        fs::write(d.info().join("e.trashinfo/x"), b"x").unwrap();
        assert_eq!(check_info_removable(&d, b"e"), Err(libc::ENOTEMPTY));
        fs::remove_file(d.info().join("e.trashinfo/x")).unwrap();
        remove_info(&d, b"e").unwrap();
        assert!(!d.info().join("e.trashinfo").exists());
    }

    #[test]
    fn names_resolve_only_to_known_directories() {
        let t = T::new("names");
        let home = t.trash();
        let vol = TrashDir {
            dir: PathBuf::from("/mnt/usb/.Trash-1000"),
            top: PathBuf::from("/mnt/usb"),
            home: false,
        };
        let dirs = [home.clone(), vol.clone()];
        let (d, e) = resolve(&dirs, b"h-my-file").unwrap();
        assert!(d.home);
        assert_eq!(e, b"my-file");
        let mut n = vol.volume().into_bytes();
        n.extend_from_slice(b"-x");
        assert_eq!(resolve(&dirs, &n).unwrap().0.dir, vol.dir);
        let mut other = hex(b"/etc").into_bytes();
        other.extend_from_slice(b"-passwd");
        assert!(resolve(&dirs, &other).is_none());
        assert!(resolve(&dirs, b"h-..").is_none());
        assert!(resolve(&dirs, b"h-a/b").is_none());
        assert!(resolve(&dirs, b"nodash").is_none());
    }

    /// R-001: on a volume, an absolute path must stay on the volume.
    #[test]
    fn restore_paths_stay_on_their_volume() {
        let vol = TrashDir {
            dir: PathBuf::from("/mnt/usb/.Trash-1000"),
            top: PathBuf::from("/mnt/usb"),
            home: false,
        };
        assert_eq!(original_path(&vol, b"a/b").unwrap(), b"/mnt/usb/a/b");
        assert_eq!(original_path(&vol, b"/mnt/usb/a").unwrap(), b"/mnt/usb/a");
        assert!(original_path(&vol, b"/etc/passwd").is_none());
        assert!(original_path(&vol, b"/mnt/usbother/a").is_none());
        assert!(original_path(&vol, b"../../etc/passwd").is_none());
        let home = TrashDir {
            dir: PathBuf::from("/h/.local/share/Trash"),
            top: PathBuf::from("/h/.local/share"),
            home: true,
        };
        assert_eq!(original_path(&home, b"/anywhere").unwrap(), b"/anywhere");
        assert!(original_path(&home, b"/a/../b").is_none());
    }

    /// F05: a symlink at Trash/files is no trash directory.
    #[test]
    fn a_symlinked_trash_directory_is_refused() {
        let t = T::new("link");
        let d = t.trash();
        // SAFETY: plain getter.
        let uid = unsafe { libc::geteuid() };
        assert!(sound(&d, uid));
        fs::remove_dir(d.files()).unwrap();
        let elsewhere = t.0.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        symlink(&elsewhere, d.files()).unwrap();
        assert!(!sound(&d, uid));
    }

    #[test]
    fn volume_trash_rules() {
        let t = T::new("vol");
        // SAFETY: plain getter.
        let uid = unsafe { libc::geteuid() };
        assert!(volume_dirs(&t.0, uid).is_empty());
        let personal = t.0.join(format!(".Trash-{uid}"));
        fs::create_dir(&personal).unwrap();
        assert_eq!(volume_dirs(&t.0, uid).len(), 1);
        let shared = t.0.join(".Trash");
        fs::create_dir_all(shared.join(uid.to_string())).unwrap();
        assert_eq!(volume_dirs(&t.0, uid).len(), 1, "not sticky");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(volume_dirs(&t.0, uid).len(), 2);
    }

    /// Deletes run on up to four threads: each must drop its own line.
    #[test]
    fn concurrent_deletes_drop_every_size_line() {
        let t = T::new("sizes-race");
        let d = t.trash();
        for round in 0..30 {
            let text: String = (0..8).map(|i| format!("1 2 e{round}x{i}\n")).collect();
            fs::write(d.dir.join("directorysizes"), text).unwrap();
            std::thread::scope(|s| {
                for i in 0..8 {
                    let d = &d;
                    s.spawn(move || {
                        let e = format!("e{round}x{i}");
                        let _ = drop_size_line(d, e.as_bytes());
                    });
                }
            });
            assert_eq!(fs::read(d.dir.join("directorysizes")).unwrap(), b"");
        }
    }

    /// A swap after the check must not redirect anything: info and listing stay put.
    #[test]
    fn a_swapped_info_directory_is_refused() {
        let t = T::new("swap-info");
        let d = t.trash();
        let other = t.0.join("other");
        fs::create_dir(&other).unwrap();
        let bait = other.join("x.trashinfo");
        fs::write(&bait, b"precious").unwrap();
        fs::rename(d.info(), t.0.join("old")).unwrap();
        symlink(&other, d.info()).unwrap();
        assert!(remove_info(&d, b"x").is_err());
        assert_eq!(check_info_removable(&d, b"x"), Err(libc::ENOTDIR));
        assert_eq!(remove_orphans(&d), 0);
        assert!(bait.exists());
    }

    /// The restore parent is resolved beneath the top, atomically.
    #[test]
    fn a_restore_parent_cannot_leave_the_volume() {
        let t = T::new("beneath");
        let mut d = t.trash();
        d.home = false;
        fs::create_dir(t.0.join("in")).unwrap();
        symlink("in", t.0.join("inner")).unwrap();
        symlink("/tmp", t.0.join("abs")).unwrap();
        symlink("../..", t.0.join("up")).unwrap();
        let at = |n: &str| t.0.join(n).join("f").as_os_str().as_bytes().to_vec();
        assert!(restore_parent(&d, &at("in")).is_some());
        assert!(restore_parent(&d, &at("inner")).is_some());
        assert!(restore_parent(&d, &at("abs")).is_none());
        assert!(restore_parent(&d, &at("up")).is_none());
        // An absolute link that stays on the volume is an ordinary layout.
        symlink(t.0.join("in"), t.0.join("alias")).unwrap();
        assert!(restore_parent(&d, &at("alias")).is_some());
        assert!(restore_parent(&d, b"/etc/f").is_none());
        assert!(restore_parent(&d, t.0.join("f").as_os_str().as_bytes()).is_some());
    }

    /// A hostile info file costs no more than a path's worth of memory.
    #[test]
    fn oversized_info_fields_are_dropped() {
        let long = "x".repeat(PATH_LEN_MAX + 1);
        assert!(parse_info(format!("[Trash Info]\nPath=/{long}\n").as_bytes()).is_none());
        let i = parse_info(format!("[Trash Info]\nPath=/a\nDeletionDate={long}\n").as_bytes());
        assert!(i.unwrap().deleted.is_empty());
    }

    /// A scan stops at its budget; what it left is seen by the empty's final look.
    #[test]
    fn a_scan_keeps_to_its_byte_budget() {
        let t = T::new("budget");
        let d = t.trash();
        for n in 0..5 {
            fs::write(d.files().join(format!("f{n}")), b"x").unwrap();
        }
        assert_eq!(scan_capped(&d, &mut 1).unwrap().len(), 1);
        assert_eq!(scan_capped(&d, &mut (1 << 20)).unwrap().len(), 5);
        assert!(scan_capped(&d, &mut 0).unwrap().is_empty());
    }

    /// An orphan stuck beside live items still reaches the client; a live item is none.
    #[test]
    fn stuck_orphans_show_beside_items() {
        let t = T::new("stuck-beside");
        let d = t.trash();
        item(&d, "kept", "/k");
        let items = scan(&d).unwrap();
        assert!(!stuck_orphans(&d, &items));
        let stuck = d.info().join("stuck.trashinfo");
        fs::create_dir_all(stuck.join("x")).unwrap();
        // Too new to tell from a file on its way in.
        assert!(!stuck_orphans(&d, &items));
        let then = std::time::SystemTime::now() - Duration::from_secs(60);
        File::open(&stuck).unwrap().set_modified(then).unwrap();
        assert!(stuck_orphans(&d, &items));
        fs::remove_dir_all(&stuck).unwrap();
        // One that cannot even be looked at is not a clean bill of health.
        fs::create_dir_all(stuck.join("x")).unwrap();
        fs::set_permissions(d.info(), fs::Permissions::from_mode(0o400)).unwrap();
        let hidden = stuck_orphans(&d, &[]);
        fs::set_permissions(d.info(), fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: plain getter.
        assert!(hidden || unsafe { libc::geteuid() } == 0);
        fs::remove_dir_all(&stuck).unwrap();
        // A plain one is simply cleared.
        let gone = d.info().join("gone.trashinfo");
        fs::write(&gone, b"x").unwrap();
        File::options()
            .write(true)
            .open(&gone)
            .unwrap()
            .set_modified(then)
            .unwrap();
        assert!(!stuck_orphans(&d, &items));
        assert!(!gone.exists());
    }

    /// Depth costs no descriptors, and `..` cannot leave the top.
    #[test]
    fn a_deep_restore_parent_holds_one_descriptor() {
        let t = T::new("deep");
        let mut d = t.trash();
        d.home = false;
        let mut p = t.0.clone();
        for _ in 0..1100 {
            p.push("d");
        }
        fs::create_dir_all(&p).unwrap();
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a valid out pointer.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) },
            0
        );
        if rl.rlim_cur > 1024 {
            // Cover the case the old walk failed: fewer descriptors than the path is deep.
            let low = libc::rlimit {
                rlim_cur: 1024,
                rlim_max: rl.rlim_max,
            };
            // SAFETY: a valid limit.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const low) },
                0
            );
        }
        let dest = p.join("f");
        let got = restore_parent(&d, dest.as_os_str().as_bytes());
        // SAFETY: a valid limit.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const rl) };
        assert!(got.is_some());
        symlink("../../..", t.0.join("up3")).unwrap();
        let esc = t.0.join("up3/f");
        assert!(restore_parent(&d, esc.as_os_str().as_bytes()).is_none());
        fs::create_dir_all(t.0.join("a/b")).unwrap();
        symlink("../b", t.0.join("a/b/side")).unwrap();
        assert!(restore_parent(&d, t.0.join("a/b/side/f").as_os_str().as_bytes()).is_some());
    }

    /// Odd spellings have no meaning: they would not compare equal to what GFile sends.
    #[test]
    fn a_path_has_one_spelling() {
        let t = T::new("spell");
        let d = t.trash();
        for odd in [&b"a//b"[..], b"a/b/", b"/a//b", b"/a/b/"] {
            assert_eq!(original_path(&d, odd), None, "{odd:?}");
        }
        assert!(original_path(&d, b"a/b").is_some());
        assert!(original_path(&d, b"/a/b").is_some());
    }

    /// A symlink payload reports its target.
    #[test]
    fn a_symlink_item_carries_its_target() {
        let t = T::new("link-item");
        let d = t.trash();
        symlink("/some/where", d.files().join("l")).unwrap();
        assert_eq!(read_item(&d, b"l").link, b"/some/where");
    }

    /// Another device right below a root is found; the same device and skips are not.
    #[test]
    fn subvolumes_are_found_one_level_down() {
        let shm = Path::new("/dev/shm");
        let differs = |a: &Path, b: &Path| {
            let dev = |p: &Path| fs::metadata(p).map(|m| m.dev()).ok();
            dev(a) != dev(b)
        };
        if differs(Path::new("/dev"), shm) {
            assert!(
                subvolume_tops(Path::new("/dev"), &|_| false)
                    .iter()
                    .any(|p| p == shm)
            );
            assert!(
                !subvolume_tops(Path::new("/dev"), &|p| p == shm)
                    .iter()
                    .any(|p| p == shm)
            );
        }
    }

    /// What an empty's final look depends on.
    #[test]
    fn has_items_sees_a_late_arrival() {
        let t = T::new("late");
        let d = t.trash();
        assert!(!has_items(&d).unwrap());
        fs::write(d.files().join("b"), b"x").unwrap();
        assert!(has_items(&d).unwrap());
    }

    /// An orphan that cannot be removed is still something an empty left.
    #[test]
    fn has_items_sees_a_stuck_orphan() {
        let t = T::new("stuck-orphan");
        let d = t.trash();
        fs::write(d.info().join("o.trashinfo"), b"x").unwrap();
        fs::write(d.info().join("unrelated"), b"x").unwrap();
        assert!(has_items(&d).unwrap());
        fs::remove_file(d.info().join("o.trashinfo")).unwrap();
        assert!(!has_items(&d).unwrap());
        for odd in [".trashinfo", "..trashinfo", "...trashinfo"] {
            fs::write(d.info().join(odd), b"x").unwrap();
        }
        assert_eq!(remove_orphans(&d), 0);
        assert!(!has_items(&d).unwrap());
    }

    /// REV2-4: a trash swapped under an orphan sweep keeps the new tree's records.
    #[test]
    fn a_held_info_directory_outlives_a_swap() {
        let t = T::new("swap-orphan");
        let d = t.trash();
        fs::write(d.info().join("e.trashinfo"), b"old").unwrap();
        let held = d.pins().unwrap();
        fs::rename(&d.dir, t.0.join("gone")).unwrap();
        let live = t.trash();
        fs::write(live.info().join("e.trashinfo"), b"live").unwrap();
        remove_info_at(&d, &held.info, b"e").unwrap();
        assert_eq!(fs::read(live.info().join("e.trashinfo")).unwrap(), b"live");
        assert!(!t.0.join("gone/info/e.trashinfo").exists());
    }

    /// A delete that cannot get its turn gives up on the cache, it does not wait.
    #[test]
    fn a_held_cache_lock_cannot_hold_a_delete() {
        let m = Mutex::new(());
        let wait = Duration::from_millis(50);
        let g = m.lock().unwrap();
        let t0 = Instant::now();
        assert!(turn(&m, wait).is_none());
        assert!(t0.elapsed() < wait * 20);
        drop(g);
        assert!(turn(&m, wait).is_some());
    }

    /// A hostile volume's temp name must not aim the cache rewrite at another file.
    #[test]
    fn the_size_cache_rewrite_never_follows_a_planted_link() {
        let t = T::new("sizes-link");
        let d = t.trash();
        let victim = t.0.join("victim");
        fs::write(&victim, b"precious").unwrap();
        fs::write(d.dir.join("directorysizes"), b"1 2 e\n").unwrap();
        let tmp = d
            .dir
            .join(format!(".directorysizes-{}", std::process::id()));
        symlink(&victim, &tmp).unwrap();
        drop_size_line(&d, b"e").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert_eq!(fs::read(d.dir.join("directorysizes")).unwrap(), b"");
    }

    /// A FIFO or an endless device at the cache must neither hang nor fill memory.
    #[test]
    fn the_size_cache_is_only_read_when_it_is_a_small_regular_file() {
        let t = T::new("sizes-odd");
        let d = t.trash();
        let p = d.dir.join("directorysizes");
        let c = CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t0 = std::time::Instant::now();
        let _ = drop_size_line(&d, b"e");
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
        fs::remove_file(&p).unwrap();
        symlink("/dev/zero", &p).unwrap();
        let _ = drop_size_line(&d, b"e");
    }

    /// Only a payload known to be gone makes an orphan (EACCES is not ENOENT).
    #[test]
    fn an_unexaminable_payload_keeps_its_info() {
        // SAFETY: plain getter.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let t = T::new("orphan-eacces");
        let d = t.trash();
        item(&d, "kept", "/k");
        fs::set_permissions(d.files(), fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(remove_orphans(&d), 0);
        fs::set_permissions(d.files(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(d.info().join("kept.trashinfo").exists());
    }

    /// An owned trash that cannot be entered may hide items.
    #[test]
    fn an_inaccessible_trash_is_unusable() {
        // SAFETY: plain getter.
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return;
        }
        let t = T::new("mode0");
        let d = t.trash();
        assert!(!unusable(&d, uid));
        fs::set_permissions(&d.dir, fs::Permissions::from_mode(0o000)).unwrap();
        let bad = unusable(&d, uid);
        fs::set_permissions(&d.dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(bad);
    }

    #[test]
    fn deleting_a_size_line_keeps_the_others() {
        let t = T::new("sizes");
        let d = t.trash();
        fs::write(d.dir.join("directorysizes"), b"1 2 a%20b\n3 4 c\n").unwrap();
        remove_info(&d, b"a b").unwrap();
        assert_eq!(fs::read(d.dir.join("directorysizes")).unwrap(), b"3 4 c\n");
    }
}
