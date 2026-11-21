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
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::MetadataExt,
        },
    },
    path::{Component, Path, PathBuf},
    sync::{Mutex, MutexGuard, TryLockError},
    thread,
    time::{Duration, Instant},
};

use crate::{fsid::MountEntry, ops::Anchor};

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
pub use crate::proto::{KIND_DIR, KIND_FILE, KIND_SPECIAL, KIND_SYMLINK};

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
    s.chunks(2).map(crate::hex_byte).collect()
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
            out.push(crate::hex_byte(h)?);
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

/// The directory `rel` (`a/b`, may be empty) below the payload `entry`, walked with no link
/// followed. A name that could not be an entry anywhere is simply not there.
fn open_below(files: &OwnedFd, entry: &[u8], rel: &[u8]) -> io::Result<OwnedFd> {
    let mut cur: Option<OwnedFd> = None;
    let parts = std::iter::once(entry).chain(rel.split(|&b| b == b'/').filter(|p| !p.is_empty()));
    for part in parts {
        if !valid_entry(part) {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let at = cur.as_ref().unwrap_or(files).as_raw_fd();
        cur = Some(open_at(at, &c_path(part)?, DIR | libc::O_NOFOLLOW)?);
    }
    cur.ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
}

/// One entry inside a trashed folder. Only looked at: nothing inside an item can be
/// deleted or restored on its own, the item is what the trash has a record of.
fn inner_item(
    dir: RawFd,
    leaf: &[u8],
    name: Vec<u8>,
    orig: &[u8],
    target: Vec<u8>,
) -> io::Result<Item> {
    let cleaf = c_path(leaf)?;
    let st = stat_at(dir, &cleaf)?;
    let kind = kind_of(&st);
    let link = if kind == KIND_SYMLINK {
        read_link_at(dir, &cleaf).unwrap_or_default()
    } else {
        Vec::new()
    };
    let orig = if orig.is_empty() {
        Vec::new()
    } else {
        [orig, b"/", leaf].concat()
    };
    Ok(Item {
        name,
        entry: Vec::new(),
        orig,
        target,
        kind,
        size: st.st_size as u64,
        mtime: st.st_mtime,
        deleted: Vec::new(),
        link,
    })
}

fn joined(base: &[u8], rel: &[u8]) -> Vec<u8> {
    if rel.is_empty() {
        base.to_vec()
    } else {
        [base, b"/", rel].concat()
    }
}

/// The entry `rel` inside the trashed folder `entry`; `name` is the whole URI name.
///
/// # Errors
/// It is not there, or a component is no directory.
pub fn child_item(
    d: &TrashDir,
    pins: &Pins,
    entry: &[u8],
    rel: &[u8],
    name: &[u8],
) -> io::Result<Item> {
    let top = item_in(d, pins, entry);
    let (dir_rel, leaf) = match rel.iter().rposition(|&b| b == b'/') {
        Some(at) => (&rel[..at], &rel[at + 1..]),
        None => (&rel[..0], rel),
    };
    if !valid_entry(leaf) {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    let dir = open_below(&pins.files, entry, dir_rel)?;
    let orig = if top.orig.is_empty() {
        Vec::new()
    } else {
        joined(&top.orig, dir_rel)
    };
    let target = joined(&joined(&top.target, dir_rel), leaf);
    inner_item(dir.as_raw_fd(), leaf, name.to_vec(), &orig, target)
}

/// What is in the folder `rel` of the payload `entry`, out of a budget of text.
///
/// # Errors
/// It is not there, or no directory.
pub fn children_of(
    d: &TrashDir,
    pins: &Pins,
    entry: &[u8],
    rel: &[u8],
    name: &[u8],
    left: &mut usize,
    skip: &dyn Fn(&[u8]) -> bool,
) -> io::Result<Vec<Item>> {
    let top = item_in(d, pins, entry);
    if !rel.is_empty() && !valid_entry(rel.rsplit(|&b| b == b'/').next().unwrap_or_default()) {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    let dir = open_below(&pins.files, entry, rel)?;
    let orig = if top.orig.is_empty() {
        Vec::new()
    } else {
        joined(&top.orig, rel)
    };
    let base = joined(&top.target, rel);
    let mut items = Vec::new();
    for (n, e) in fs::read_dir(fd_path(&dir))?.enumerate() {
        // Entries read, not entries kept: one that vanished still used up the scan.
        if n >= SCAN_MAX {
            *left = 0;
        }
        if *left == 0 {
            break;
        }
        let leaf = e?.file_name();
        let leaf = leaf.as_bytes();
        let target = joined(&base, leaf);
        // A mount known hung is not to be touched, not even by a stat.
        let looked = if skip(&target) {
            Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))
        } else {
            inner_item(
                dir.as_raw_fd(),
                leaf,
                joined(name, leaf),
                &orig,
                target.clone(),
            )
        };
        let it = match looked {
            Ok(it) => it,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue, // gone since the listing
            // There, but it cannot be looked at: still an entry, as in the trash itself.
            Err(_) => Item {
                name: joined(name, leaf),
                entry: Vec::new(),
                orig: joined(&orig, leaf),
                target,
                kind: KIND_SPECIAL,
                size: 0,
                mtime: 0,
                deleted: Vec::new(),
                link: Vec::new(),
            },
        };
        *left =
            left.saturating_sub(it.name.len() + it.orig.len() + it.target.len() + it.link.len());
        items.push(it);
    }
    Ok(items)
}

/// What changes when anything is added to or removed from `d`.
#[must_use]
pub fn stamp(d: &TrashDir) -> u64 {
    let mut h = fnv(0xcbf2_9ce4_8422_2325, d.dir.as_os_str().as_bytes());
    if let Ok(pins) = d.pins() {
        for fd in [&pins.files, &pins.info] {
            if let Ok(st) = stat_at(fd.as_raw_fd(), c"") {
                h = fnv(h, &st.st_mtime.to_le_bytes());
                h = fnv(h, &st.st_mtime_nsec.to_le_bytes());
            }
        }
    }
    h
}

/// FNV-1a: a change detector, kept in memory only.
#[must_use]
pub fn fnv(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    h
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
/// (BC-T005-F1): the held `info/` is writable, and what is there is removable. Absent is
/// fine: the payload is an item of its own then. A non-empty directory there refuses.
///
/// # Errors
/// The errno that would stop the removal.
fn check_info_removable_at(dir: &OwnedFd, entry: &[u8]) -> Result<(), i32> {
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

/// Remove the info entry and the item's `directorysizes` line, after the payload went, in
/// the held `info/`: the entry checked is the entry removed.
///
/// # Errors
/// The removal failed; the payload is gone by then, and the error says so to the caller.
fn remove_info_at(d: &TrashDir, dir: &OwnedFd, entry: &[u8]) -> io::Result<()> {
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

/// The payload step of an item's delete or restore, for the caller's op engine to run.
/// Each place is an [`Anchor`], held open: the op acts on that directory's entry, never on
/// a path walked again, so it stays in the trash it checked.
#[derive(Debug)]
pub enum Step {
    /// Remove the payload, whatever it holds.
    DeleteTree { src: Vec<u8>, src_at: Anchor },
    /// Move the payload to `dest`. `dest_at` is set when the destination is on the trash's
    /// own volume, walked and checked from its top.
    Move {
        src: Vec<u8>,
        src_at: Anchor,
        dest: Vec<u8>,
        dest_at: Option<Anchor>,
    },
}

/// Why an item's delete or restore stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemError<E> {
    /// A system error, before or after the payload step.
    Os(i32),
    /// No such item.
    NotFound,
    /// A destination with no single meaning.
    BadRequest,
    /// The payload step itself failed; the item is still listed.
    Step(E),
}

fn os_of<E>(e: &io::Error) -> ItemError<E> {
    ItemError::Os(e.raw_os_error().unwrap_or(libc::EIO))
}

/// `leaf` under the held `dir`; a name with a NUL in it names nothing.
fn anchor<E>(dir: OwnedFd, leaf: &[u8]) -> Result<Anchor, ItemError<E>> {
    Ok(Anchor {
        dir: std::sync::Arc::new(dir),
        leaf: CString::new(leaf).map_err(|_| ItemError::BadRequest)?,
    })
}

/// A sound trash's two directories, pinned for one item's operation.
fn pinned<E>(d: &TrashDir, uid: u32) -> Result<Pins, ItemError<E>> {
    if !sound(d, uid) {
        return Err(ItemError::Os(libc::ENOTDIR));
    }
    d.pins().map_err(|e| os_of(&e))
}

/// An absolute path in its one canonical spelling: no empty, `.` or `..` component, no
/// trailing slash, not `/` itself. What GIO sends (`g_file_get_path`) always is.
fn canonical_abs(p: &[u8]) -> bool {
    let Some(rest) = p.strip_prefix(b"/") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split(|&b| b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

/// Delete one item. The info entry is checked before `run` touches the payload and
/// removed after it is gone, all in one pinned pair of directories, so a failed delete
/// leaves the item listed and retryable. A delete that leaves `files/` empty sweeps the
/// orphans (real clients empty a trash item by item).
///
/// # Errors
/// [`ItemError`]; `run`'s own error comes back as [`ItemError::Step`].
pub fn delete<E>(
    d: &TrashDir,
    uid: u32,
    entry: &[u8],
    run: impl FnOnce(Step) -> Result<(), E>,
) -> Result<(), ItemError<E>> {
    let pins = pinned(d, uid)?;
    check_info_removable_at(&pins.info, entry).map_err(ItemError::Os)?;
    match stat_payload(&pins.files, entry) {
        Ok(()) => {
            let src = d.payload(entry).into_os_string().into_vec();
            let src_at = anchor(pins.files, entry)?;
            run(Step::DeleteTree { src, src_at }).map_err(ItemError::Step)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ItemError::NotFound),
        Err(e) => return Err(os_of(&e)),
    }
    let r = remove_info_at(d, &pins.info, entry).map_err(|e| os_of(&e));
    // An orphan that would not go is no failure of this delete: the next listing says so.
    let _ = sweep_if_empty(d);
    r
}

/// Restore one item to `dest`, or to where it came from when `dest` is empty. The same
/// order as [`delete`]: info checked, payload moved by `run`, info removed.
///
/// The item's own path is foreign data even when a client sends it back (`g_file_move`
/// always does, respelled): on a volume trash, a destination on that volume is walked
/// from the volume's top component by component ([`restore_parent`]) and the move made
/// there; only a destination elsewhere is the user's own choice.
///
/// # Errors
/// [`ItemError`]; `run`'s own error comes back as [`ItemError::Step`].
pub fn restore<E>(
    d: &TrashDir,
    uid: u32,
    entry: &[u8],
    dest: &[u8],
    run: impl FnOnce(Step) -> Result<(), E>,
) -> Result<(), ItemError<E>> {
    let pins = pinned(d, uid)?;
    let item = item_in(d, &pins, entry);
    let inside = Path::new(OsStr::from_bytes(dest)).starts_with(&d.top);
    let foreign = !d.home && (dest.is_empty() || inside);
    let to = if dest.is_empty() {
        item.orig
    } else {
        dest.to_vec()
    };
    // One spelling per place (SEC H-007): `inside` above is a lexical test, and a `..`
    // could climb back onto the volume past it and its checks.
    if !canonical_abs(&to) {
        return Err(ItemError::BadRequest);
    }
    // The check is the descriptor: what was checked is where the file lands.
    let dest_at = if foreign {
        let parent = restore_parent(d, &to).ok_or(ItemError::Os(libc::EACCES))?;
        let leaf = to.rsplit(|&b| b == b'/').next().unwrap_or_default();
        Some(anchor(parent, leaf)?)
    } else {
        None
    };
    check_info_removable_at(&pins.info, entry).map_err(ItemError::Os)?;
    let src_at = anchor(pins.files, entry)?;
    run(Step::Move {
        src: item.target,
        src_at,
        dest: to,
        dest_at,
    })
    .map_err(ItemError::Step)?;
    remove_info_at(d, &pins.info, entry).map_err(|e| os_of(&e))
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

// ---------------------------------------------------------------------------------------
// Which trash directories exist: discovery from the mount table

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

/// What volume discovery works from. Everything it may not do itself comes in here: the
/// mount table (read by the caller), and as callbacks whether a path's mount is hung or
/// gone, whether a FUSE mount's server is gone, and the btrfs subvolume search (which
/// runs on a thread of the caller's, with its own bounds).
pub struct Volumes<'a> {
    pub table: &'a [MountEntry],
    /// The home trash, if there is one.
    pub home: Option<&'a TrashDir>,
    /// `$HOME`, whose subvolumes hold trash as well.
    pub home_root: Option<&'a Path>,
    pub uid: u32,
    /// Volumes beyond the mount table.
    pub extra_tops: &'a [PathBuf],
    /// Search the table's btrfs mounts for subvolumes.
    pub host_subvols: bool,
    pub blocked: &'a dyn Fn(&Path) -> bool,
    pub fuse_gone: &'a dyn Fn(&Path) -> bool,
    /// The subvolumes below these roots, and whether that is all of them.
    pub subvolumes: &'a dyn Fn(Vec<PathBuf>) -> (Vec<PathBuf>, bool),
}

/// The trash directories reachable now.
#[derive(Debug, Default)]
pub struct Dirs {
    pub dirs: Vec<TrashDir>,
    /// Volumes left out as hung or gone; they may hold a trash.
    pub skipped: Vec<PathBuf>,
    /// Every subvolume was seen.
    pub complete: bool,
}

/// Every trash directory `v` can reach: the home trash, then each volume's (mounts, test
/// volumes, subvolumes, other devices right below a mount or `$HOME`). A hung or gone
/// volume is never touched, only named; a FUSE mount whose server is gone holds nothing
/// to miss; a mounted btrfs snapshot is a backup unless the system or the user lives on
/// it.
#[must_use]
pub fn discover(v: &Volumes<'_>) -> Dirs {
    let blocked = v.blocked;
    let mut dirs: Vec<TrashDir> = Vec::new();
    let mut skipped = Vec::new();
    if let Some(h) = v.home {
        if blocked(&h.dir) {
            skipped.push(h.dir.clone());
        } else {
            dirs.push(h.clone());
        }
    }
    let mut tops = mount_points(v.table);
    tops.extend(v.extra_tops.iter().cloned());
    let mut roots = if v.host_subvols {
        btrfs_mounts(v.table)
    } else {
        Vec::new()
    };
    roots.extend(v.extra_tops.iter().cloned());
    // A mounted snapshot is a backup, unless the system or the user lives on it (a
    // rollback runs from one, even with /home mounted apart): only then is its trash a
    // real one.
    let lived_on: Vec<PathBuf> = [
        Some(Path::new("/")),
        v.home_root,
        v.home.map(|h| h.dir.as_path()),
    ]
    .into_iter()
    .flatten()
    .filter_map(|p| mount_of(&tops, p).cloned())
    .collect();
    tops.retain(|t| {
        !roots.contains(t) || blocked(t) || lived_on.contains(t) || !crate::btrfs::is_snapshot(t)
    });
    roots.retain(|t| tops.contains(t));
    // A subvolume needs no mount of its own, and g_file_trash treats it as a volume.
    // Btrfs lists its own, at any depth. Other filesystems: what shows as another device
    // right below a root, which needs no walking of the disk.
    let (subvols, complete) = (v.subvolumes)(roots);
    let mut below = Vec::new();
    for root in tops.iter().map(PathBuf::as_path).chain(v.home_root) {
        if !blocked(root) {
            below.extend(subvolume_tops(root, &|p| blocked(p)));
        }
    }
    tops.extend(below);
    tops.extend(subvols);
    let fuse = fuse_mounts(v.table);
    for top in tops {
        // A FUSE mount whose server is gone can never be read again (a stale AppImage
        // mount, say): no trash there to miss, so it does not make listings partial.
        // Hung mounts, and network mounts that may come back, still do.
        if fuse.contains(&top) && (v.fuse_gone)(&top) {
            continue;
        }
        if blocked(&top) {
            // Only a volume with a trash matters, and asking would touch it: a hung mount
            // from the mount table is named, as it may hold one.
            skipped.push(top);
            continue;
        }
        for d in volume_dirs(&top, v.uid) {
            if !dirs.iter().any(|x| x.dir == d.dir) {
                dirs.push(d);
            }
        }
    }
    Dirs {
        dirs,
        skipped,
        complete,
    }
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

    fn me() -> u32 {
        // SAFETY: plain getter.
        unsafe { libc::geteuid() }
    }

    /// What the op engine would do with a step, done in place, recorded in `log`.
    fn engine(log: &std::cell::RefCell<Vec<String>>) -> impl FnOnce(Step) -> Result<(), i32> {
        move |s| {
            match s {
                Step::DeleteTree { src_at, .. } => {
                    let p = fd_path(&src_at.dir).join(OsStr::from_bytes(src_at.leaf.as_bytes()));
                    log.borrow_mut()
                        .push(format!("delete {}", src_at.leaf.to_string_lossy()));
                    if p.is_dir() {
                        fs::remove_dir_all(p)
                    } else {
                        fs::remove_file(p)
                    }
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                }
                Step::Move {
                    src_at,
                    dest,
                    dest_at,
                    ..
                } => {
                    let from = fd_path(&src_at.dir).join(OsStr::from_bytes(src_at.leaf.as_bytes()));
                    let to = match &dest_at {
                        Some(a) => fd_path(&a.dir).join(OsStr::from_bytes(a.leaf.as_bytes())),
                        None => PathBuf::from(OsStr::from_bytes(&dest)),
                    };
                    log.borrow_mut().push(format!("move {}", dest_at.is_some()));
                    fs::rename(from, to).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                }
            }
            Ok(())
        }
    }

    fn untouched(log: &std::cell::RefCell<Vec<String>>) -> impl FnOnce(Step) -> Result<(), i32> {
        move |s| {
            log.borrow_mut().push(format!("{s:?}"));
            Ok(())
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
        fs::write(d.files().join("e"), b"data").unwrap();
        fs::create_dir(d.info().join("e.trashinfo")).unwrap();
        fs::write(d.info().join("e.trashinfo/x"), b"x").unwrap();
        let log = std::cell::RefCell::default();
        assert_eq!(
            delete(&d, me(), b"e", untouched(&log)),
            Err(ItemError::Os(libc::ENOTEMPTY))
        );
        assert!(log.borrow().is_empty(), "the payload was never handed on");
        assert!(d.files().join("e").exists());
        fs::remove_file(d.info().join("e.trashinfo/x")).unwrap();
        delete(&d, me(), b"e", engine(&log)).unwrap();
        assert!(!d.info().join("e.trashinfo").exists());
        assert!(!d.files().join("e").exists());
    }

    /// The order of a delete: info checked, payload removed, info removed last. A failed
    /// payload step leaves the item listed and retryable.
    #[test]
    fn a_failed_delete_keeps_the_item() {
        let t = T::new("del-fail");
        let d = t.trash();
        item(&d, "a", "/x/a");
        let r = delete(&d, me(), b"a", |_| Err(libc::EIO));
        assert_eq!(r, Err(ItemError::Step(libc::EIO)));
        assert!(d.info().join("a.trashinfo").exists());
        assert_eq!(scan(&d).unwrap().len(), 1, "still listed");
        let log = std::cell::RefCell::default();
        delete(&d, me(), b"a", engine(&log)).unwrap();
        assert_eq!(*log.borrow(), ["delete a"]);
        assert!(scan(&d).unwrap().is_empty());
        assert!(!d.info().join("a.trashinfo").exists());
    }

    #[test]
    fn deleting_a_missing_payload_is_not_found() {
        let t = T::new("del-missing");
        let d = t.trash();
        let log = std::cell::RefCell::default();
        assert_eq!(
            delete(&d, me(), b"nope", untouched(&log)),
            Err(ItemError::NotFound)
        );
        assert!(log.borrow().is_empty());
    }

    /// The home trash restores to the original path through the engine's own walk; the
    /// info goes only once the payload has moved.
    #[test]
    fn a_home_item_is_restored_to_its_path() {
        let t = T::new("restore-home");
        let d = t.trash();
        // A restore takes only canonical paths, and the scratch base has a `..` in it.
        let back = fs::canonicalize(&t.0).unwrap().join("back");
        item(&d, "r", back.to_str().unwrap());
        let log = std::cell::RefCell::default();
        restore(&d, me(), b"r", b"", engine(&log)).unwrap();
        assert_eq!(*log.borrow(), ["move false"]);
        assert_eq!(fs::read(&back).unwrap(), b"data");
        assert!(!d.info().join("r.trashinfo").exists());
    }

    /// On a volume, a destination on that volume is walked from its top: the step gets a
    /// held parent, never a path to walk again.
    #[test]
    fn a_volume_item_is_restored_through_a_held_parent() {
        let t = T::new("restore-vol");
        let top = fs::canonicalize(&t.0).unwrap();
        let d = TrashDir {
            dir: top.join(".Trash-1"),
            top,
            home: false,
        };
        fs::create_dir_all(d.files()).unwrap();
        fs::create_dir_all(d.info()).unwrap();
        fs::create_dir(t.0.join("dir")).unwrap();
        item(&d, "v", "dir/v");
        let log = std::cell::RefCell::default();
        restore(&d, me(), b"v", b"", engine(&log)).unwrap();
        assert_eq!(*log.borrow(), ["move true"]);
        assert_eq!(fs::read(t.0.join("dir/v")).unwrap(), b"data");
    }

    #[test]
    fn a_restore_destination_has_one_spelling() {
        let t = T::new("restore-spell");
        let d = t.trash();
        item(&d, "s", "/x/s");
        let log = std::cell::RefCell::default();
        for bad in [&b"/a/../b"[..], b"rel", b"/a/", b"/", b"/a//b"] {
            assert_eq!(
                restore(&d, me(), b"s", bad, untouched(&log)),
                Err(ItemError::BadRequest)
            );
        }
        assert!(log.borrow().is_empty());
        assert!(d.info().join("s.trashinfo").exists());
    }

    #[test]
    fn a_failed_restore_keeps_the_item() {
        let t = T::new("restore-fail");
        let d = t.trash();
        item(&d, "f", "/x/f");
        let r = restore(&d, me(), b"f", b"", |_| Err(libc::EXDEV));
        assert_eq!(r, Err(ItemError::Step(libc::EXDEV)));
        assert!(d.info().join("f.trashinfo").exists());
        assert!(d.files().join("f").exists());
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
        fs::write(d.files().join("x"), b"x").unwrap();
        let log = std::cell::RefCell::default();
        assert!(matches!(
            delete(&d, me(), b"x", untouched(&log)),
            Err(ItemError::Os(_))
        ));
        assert!(log.borrow().is_empty());
        assert!(d.files().join("x").exists());
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

    /// Inside a trashed folder: looked at through descriptors, no link followed.
    #[test]
    fn a_trashed_folder_can_be_read_into() {
        let t = T::new("inner");
        let d = t.trash();
        item(&d, "dir", "/o/dir");
        let f = d.files().join("dir");
        fs::remove_file(&f).ok();
        fs::create_dir_all(f.join("sub")).unwrap();
        fs::write(f.join("sub/leaf"), b"hello").unwrap();
        symlink("/etc", f.join("out")).unwrap();
        let pins = d.pins().unwrap();
        let mut left = 1 << 20;
        let mut got: Vec<_> = children_of(&d, &pins, b"dir", b"", b"h-dir", &mut left, &|_| false)
            .unwrap()
            .into_iter()
            .map(|i| (i.name, i.kind))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                (b"h-dir/out".to_vec(), KIND_SYMLINK),
                (b"h-dir/sub".to_vec(), KIND_DIR)
            ]
        );
        let leaf = child_item(&d, &pins, b"dir", b"sub/leaf", b"h-dir/sub/leaf").unwrap();
        assert_eq!((leaf.kind, leaf.size), (KIND_FILE, 5));
        assert_eq!(leaf.orig, b"/o/dir/sub/leaf");
        assert!(leaf.target.ends_with(b"files/dir/sub/leaf"));
        // A link is not walked through, and no name climbs out.
        assert!(child_item(&d, &pins, b"dir", b"out/passwd", b"x").is_err());
        assert!(children_of(&d, &pins, b"dir", b"out", b"x", &mut left, &|_| false).is_err());
        assert!(child_item(&d, &pins, b"dir", b"sub/../../x", b"x").is_err());
        assert!(child_item(&d, &pins, b"dir", b"..", b"x").is_err());
        assert!(children_of(&d, &pins, b"dir", b"sub/..", b"x", &mut left, &|_| false).is_err());
    }

    /// A folder that lists but cannot be searched shows its entries, degraded.
    #[test]
    fn unexaminable_children_are_listed() {
        let t = T::new("no-search");
        let d = t.trash();
        item(&d, "dir", "/o/dir");
        let f = d.files().join("dir");
        fs::remove_file(&f).ok();
        fs::create_dir_all(&f).unwrap();
        fs::write(f.join("a"), b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        let pins = d.pins().unwrap();
        let got = children_of(&d, &pins, b"dir", b"", b"h-dir", &mut (1 << 20), &|_| false);
        let skipped = children_of(&d, &pins, b"dir", b"", b"h-dir", &mut (1 << 20), &|_| true);
        fs::set_permissions(&f, fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: plain getter.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(got.unwrap()[0].kind, KIND_SPECIAL);
        }
        assert_eq!(
            skipped.unwrap()[0].kind,
            KIND_SPECIAL,
            "a hung child is not touched"
        );
    }

    /// The stamp moves with the trash, and stays put without it.
    #[test]
    fn the_stamp_follows_changes() {
        let t = T::new("stamp");
        let d = t.trash();
        let a = stamp(&d);
        assert_eq!(a, stamp(&d));
        let then = std::time::SystemTime::now() - Duration::from_secs(5);
        File::open(d.files()).unwrap().set_modified(then).unwrap();
        let b = stamp(&d);
        assert_ne!(a, b);
        fs::write(d.files().join("n"), b"x").unwrap();
        assert_ne!(b, stamp(&d));
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
        // Bottom up, one at a time: a recursive remove holds a descriptor per level, and
        // under a limit of 1024 this tree would outlive the test and block the next
        // checkout in CI, which cannot remove it either.
        let mut level = p;
        while level != t.0 {
            fs::remove_dir(&level).unwrap();
            level.pop();
        }
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
        let pins = d.pins().unwrap();
        assert_eq!(item_in(&d, &pins, b"l").link, b"/some/where");
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
        fs::write(d.dir.join("files/c"), b"c").unwrap();
        item(&d, "a b", "/x/a b");
        let log = std::cell::RefCell::default();
        delete(&d, me(), b"a b", engine(&log)).unwrap();
        assert_eq!(fs::read(d.dir.join("directorysizes")).unwrap(), b"3 4 c\n");
    }

    fn table(t: &str) -> Vec<MountEntry> {
        crate::fsid::parse_mountinfo(t.as_bytes())
    }

    #[test]
    fn fuse_mounts_are_the_topmost_fuse_ones() {
        let t = "1 0 0:1 / / rw - btrfs /dev/sda2 rw\n\
            2 1 0:2 / /tmp/.mount_app rw - fuse.app app ro\n\
            3 1 0:3 / /home/u/remote rw - fuse.sshfs h:/ rw\n\
            4 1 0:4 / /mnt/x rw - fuse dead rw\n\
            5 4 0:5 / /mnt/x rw - ext4 /dev/sdb1 rw\n\
            6 1 0:6 / /m\\040n rw - fuseblk /dev/sdc1 rw\n";
        assert_eq!(
            fuse_mounts(&table(t)),
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
        let t = "36 1 0:32 / / rw - btrfs /dev/a rw\n\
                 37 1 0:33 / /mnt/my\\040disk rw shared:1 - btrfs /dev/b rw\n\
                 38 1 0:34 / /mnt/nfs rw - nfs4 s:/x rw\n";
        assert_eq!(
            btrfs_mounts(&table(t)),
            vec![PathBuf::from("/"), PathBuf::from("/mnt/my disk")]
        );
    }

    #[test]
    fn mountinfo_gives_candidate_volumes() {
        let t = "22 1 0:21 / / rw - ext4 /dev/sda1 rw\n\
                 23 22 0:22 / /proc rw - proc proc rw\n\
                 24 22 0:23 / /mnt/my\\040disk rw shared:1 - vfat /dev/sdb1 rw\n\
                 garbage line\n";
        assert_eq!(
            mount_points(&table(t)),
            [PathBuf::from("/"), PathBuf::from("/mnt/my disk")]
        );
    }

    /// Discovery from a table alone: a hung volume is named and never opened, a FUSE
    /// mount whose server is gone is left out without making the listing partial, and the
    /// subvolume search's verdict is the listing's.
    #[test]
    fn discovery_names_hung_volumes_and_drops_dead_fuse_ones() {
        let t = T::new("discover");
        let home = t.trash();
        let ok = t.0.join("ok");
        let hung = t.0.join("hung");
        let dead = t.0.join("dead");
        for v in [&ok, &hung, &dead] {
            fs::create_dir_all(v.join(format!(".Trash-{}/files", me()))).unwrap();
        }
        let line = |n: u32, p: &Path, fs: &str| {
            format!("{n} 1 0:{n} / {} rw - {fs} src rw\n", p.display())
        };
        let text = [
            line(30, &ok, "ext4"),
            line(31, &hung, "nfs4"),
            line(32, &dead, "fuse.app"),
        ]
        .concat();
        let found = discover(&Volumes {
            table: &table(&text),
            home: Some(&home),
            home_root: None,
            uid: me(),
            extra_tops: &[],
            host_subvols: false,
            blocked: &|p| p.starts_with(&hung),
            fuse_gone: &|p| p.starts_with(&dead),
            subvolumes: &|_| (Vec::new(), false),
        });
        let tops: Vec<&Path> = found.dirs.iter().map(|d| d.top.as_path()).collect();
        assert!(tops.contains(&ok.as_path()), "{tops:?}");
        assert!(!tops.contains(&dead.as_path()) && !tops.contains(&hung.as_path()));
        assert!(found.dirs.iter().any(|d| d.home), "the home trash first");
        assert_eq!(found.skipped, [hung]);
        assert!(!found.complete, "an unfinished subvolume search says so");
    }
}
