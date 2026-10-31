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
    ffi::{CString, OsStr},
    fs,
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

/// Longest `.trashinfo` read; anything bigger is listed degraded.
const INFO_MAX: u64 = 64 * 1024;
const HOME_VOLUME: &str = "h";
/// Entries read from one trash directory: a volume is foreign media, and its list is not
/// allowed to grow the daemon without bound.
pub const SCAN_MAX: usize = 1 << 17;
/// Largest `directorysizes` rewritten; a bigger one is left alone, it is only a cache.
const SIZES_MAX: u64 = 1 << 20;
/// Request threads delete at the same time; each rewrite must see the last one's result.
static SIZES: Mutex<()> = Mutex::new(());

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

    fn info_path(&self, entry: &[u8]) -> PathBuf {
        let mut n = entry.to_vec();
        n.extend_from_slice(b".trashinfo");
        self.info().join(OsStr::from_bytes(&n))
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
    (!info.path.is_empty()).then_some(info)
}

/// Read a `.trashinfo` without following a link, blocking on a FIFO or taking a terminal.
fn read_capped(p: &Path) -> io::Result<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(p)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut out = Vec::new();
    f.take(INFO_MAX + 1).read_to_end(&mut out)?;
    if out.len() as u64 > INFO_MAX {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    Ok(out)
}

/// The absolute path an info's `Path=` means in `d`, `None` if it has no safe meaning.
/// Outside the home trash an absolute path must lie on the volume itself.
#[must_use]
pub fn original_path(d: &TrashDir, path: &[u8]) -> Option<Vec<u8>> {
    if path.split(|&b| b == b'/').any(|c| c == b"." || c == b"..") {
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

fn kind_of(m: &fs::Metadata) -> u8 {
    let t = m.file_type();
    if t.is_symlink() {
        KIND_SYMLINK
    } else if t.is_dir() {
        KIND_DIR
    } else if t.is_file() {
        KIND_FILE
    } else {
        KIND_SPECIAL
    }
}

/// One item from its entry name.
#[must_use]
pub fn read_item(d: &TrashDir, entry: &[u8]) -> Item {
    let payload = d.payload(entry);
    // A payload that cannot be examined is still an item (A-T005-1).
    let (kind, size, mtime) = match fs::symlink_metadata(&payload) {
        Ok(m) => (kind_of(&m), m.len(), m.mtime()),
        Err(_) => (KIND_SPECIAL, 0, 0),
    };
    let info = read_capped(&d.info_path(entry))
        .ok()
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
    }
}

/// List a trash directory. Per-entry trouble degrades that entry; only an unusable
/// directory is an error. An info file with no payload is an orphan: not listed.
///
/// # Errors
/// `files/` cannot be read.
pub fn scan(d: &TrashDir) -> io::Result<Vec<Item>> {
    let mut items = Vec::new();
    for e in fs::read_dir(d.files())?.take(SCAN_MAX) {
        let name = e?.file_name();
        items.push(read_item(d, name.as_bytes()));
    }
    Ok(items)
}

/// Check that the info entry of `entry` can be removed, before the payload is touched
/// (BC-T005-F1): `info/` is writable, and what is there is removable. Absent is fine: the
/// payload is an item of its own then. A non-empty directory there refuses.
///
/// # Errors
/// The errno that would stop the removal.
pub fn check_info_removable(d: &TrashDir, entry: &[u8]) -> Result<(), i32> {
    let dir = CString::new(d.info().as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    // SAFETY: valid NUL-terminated path.
    if unsafe { libc::access(dir.as_ptr(), libc::W_OK | libc::X_OK) } != 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    let p = d.info_path(entry);
    match fs::symlink_metadata(&p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.raw_os_error().unwrap_or(libc::EIO)),
        Ok(m) if m.is_dir() => match fs::read_dir(&p) {
            Ok(mut it) => match it.next() {
                None => Ok(()),
                Some(_) => Err(libc::ENOTEMPTY),
            },
            Err(e) => Err(e.raw_os_error().unwrap_or(libc::EIO)),
        },
        Ok(_) => Ok(()),
    }
}

/// Remove the info entry and the item's `directorysizes` line, after the payload went.
///
/// # Errors
/// The removal failed; the payload is gone by then, and the error says so to the caller.
pub fn remove_info(d: &TrashDir, entry: &[u8]) -> io::Result<()> {
    let p = d.info_path(entry);
    let r = match fs::symlink_metadata(&p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() => fs::remove_dir(&p),
        Ok(_) => fs::remove_file(&p),
    };
    // The cache is only a cache: a stale line makes readers rescan, so failing to drop
    // it is not worth reporting.
    let _ = drop_size_line(d, entry);
    r
}

/// Remove `entry`'s line from `directorysizes`, atomically (`<size> <mtime> <encoded>`).
fn drop_size_line(d: &TrashDir, entry: &[u8]) -> io::Result<()> {
    let _serial = SIZES.lock().unwrap_or_else(PoisonError::into_inner);
    let path = d.dir.join("directorysizes");
    if fs::symlink_metadata(&path).is_ok_and(|m| m.len() > SIZES_MAX) {
        return Ok(());
    }
    let text = match fs::read(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
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
    let tmp = d
        .dir
        .join(format!(".directorysizes-{}", std::process::id()));
    fs::write(&tmp, &out)?;
    fs::rename(&tmp, &path)
}

/// Info files whose payload is gone: what a crash between the two removals leaves.
/// Removes them; returns how many went.
#[must_use]
pub fn remove_orphans(d: &TrashDir) -> usize {
    let Ok(it) = fs::read_dir(d.info()) else {
        return 0;
    };
    let mut n = 0;
    for e in it.flatten() {
        let name = e.file_name();
        let Some(entry) = name.as_bytes().strip_suffix(b".trashinfo") else {
            continue;
        };
        if fs::symlink_metadata(d.payload(entry)).is_err() && remove_info(d, entry).is_ok() {
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
        fs::write(d.info().join("gone.trashinfo"), b"[Trash Info]\nPath=/g\n").unwrap();
        assert_eq!(scan(&d).unwrap().len(), 1);
        assert_eq!(remove_orphans(&d), 1);
        assert!(!d.info().join("gone.trashinfo").exists());
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

    #[test]
    fn deleting_a_size_line_keeps_the_others() {
        let t = T::new("sizes");
        let d = t.trash();
        fs::write(d.dir.join("directorysizes"), b"1 2 a%20b\n3 4 c\n").unwrap();
        remove_info(&d, b"a b").unwrap();
        assert_eq!(fs::read(d.dir.join("directorysizes")).unwrap(), b"3 4 c\n");
    }
}
