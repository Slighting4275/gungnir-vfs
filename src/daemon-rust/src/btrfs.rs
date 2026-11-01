//! Btrfs subvolumes with no mount of their own. `g_file_trash` treats one as a volume (its
//! `st_dev` differs), so it can hold a `.Trash-$uid` that no mount table leads to. The
//! kernel lists a subvolume's children to any user (`GET_SUBVOL_ROOTREF`, Linux 4.18), the
//! way libbtrfsutil does when unprivileged, so nothing has to walk the disk.

use std::{
    ffi::{CString, OsStr},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const BTRFS_IOC_GET_SUBVOL_INFO: u32 = 0x81f8_943c;
pub const BTRFS_IOC_GET_SUBVOL_ROOTREF: u32 = 0xd000_943d;
pub const BTRFS_IOC_INO_LOOKUP_USER: u32 = 0xd000_943e;
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683e;
/// A subvolume's root directory is always this inode.
const SUBVOL_ROOT_INO: u64 = 256;
/// How long one search may take, on any image.
const SEARCH_TIME_MAX: Duration = Duration::from_secs(5);
/// `BTRFS_ROOT_SUBVOL_RDONLY`: what `GET_SUBVOL_INFO` reports, the on-disk flag.
const ROOT_SUBVOL_RDONLY: u64 = 1 << 0;
/// Subvolumes looked at below one root; a hostile image may have any number.
pub const SUBVOLS_MAX: usize = 1 << 14;

// Offsets in the kernel's structures, from <linux/btrfs.h>.
const INFO_WORDS: usize = 504 / 8;
const INFO_FLAGS_WORD: usize = 288 / 8;
const INFO_PARENT_UUID_WORD: usize = 312 / 8;
const ROOTREF_WORDS: usize = 4096 / 8;
const ROOTREF_COUNT_BYTE: usize = 4088;
const LOOKUP_NAME: usize = 16;
const LOOKUP_PATH: usize = 272;

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

fn open_at(dir: RawFd, name: &[u8], flags: i32) -> io::Result<OwnedFd> {
    let n = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: a valid NUL-terminated name; the result is checked before it is owned.
    let fd = unsafe { libc::openat(dir, n.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_err());
    }
    // SAFETY: a new descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// An open that failed only because this user has no business there, or it is gone.
fn benign(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EACCES | libc::EPERM | libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
    )
}

/// Whether `path` is on btrfs.
#[must_use]
pub fn is_btrfs(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: an all-zero statfs is valid, and the kernel only writes to it.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid path and out pointer.
    unsafe { libc::statfs(c.as_ptr(), &raw mut fs) == 0 && fs.f_type == BTRFS_SUPER_MAGIC }
}

/// Open subvolume `rel` below `root`, following no link. `None`: it is not one, after all.
fn open_rel(root: RawFd, rel: &Path) -> io::Result<Option<OwnedFd>> {
    let dir = libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let mut cur: Option<OwnedFd> = None;
    let mut parts = rel.iter().peekable();
    while let Some(part) = parts.next() {
        let flags = if parts.peek().is_some() {
            libc::O_PATH
        } else {
            libc::O_RDONLY
        };
        let at = cur.as_ref().map_or(root, AsRawFd::as_raw_fd);
        cur = Some(open_at(at, part.as_bytes(), flags | dir)?);
    }
    let Some(fd) = cur else {
        return Ok(None);
    };
    // SAFETY: an all-zero stat is valid, and the kernel only writes to it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a live descriptor and a valid out pointer.
    let ok = unsafe { libc::fstat(fd.as_raw_fd(), &raw mut st) } == 0;
    Ok((ok && st.st_ino == SUBVOL_ROOT_INO).then_some(fd))
}

/// Whether a subvolume is one the user works in: not read-only, which `g_file_trash`
/// cannot use and no empty could finish, and not a snapshot, whose trash is a backup's
/// copy of the real one, not a thing to list again or to delete. An unknown answer counts
/// as no: leaving a trash out is safe, deleting a backup is not.
fn live(fd: RawFd) -> bool {
    let mut info = [0u64; INFO_WORDS];
    // SAFETY: a buffer of exactly the size the request encodes.
    let r = unsafe { libc::ioctl(fd, BTRFS_IOC_GET_SUBVOL_INFO as _, info.as_mut_ptr()) };
    r == 0 && live_info(&info)
}

fn live_info(info: &[u64; INFO_WORDS]) -> bool {
    info[INFO_FLAGS_WORD] & ROOT_SUBVOL_RDONLY == 0
        && info[INFO_PARENT_UUID_WORD] == 0
        && info[INFO_PARENT_UUID_WORD + 1] == 0
}

/// Whether `path` is in a snapshot: a subvolume with a parent, or a read-only one. On btrfs
/// an answer that cannot be had counts as yes: its root can be unreadable while the trash
/// below it is not, and hiding a trash is safe where deleting a backup is not.
#[must_use]
pub fn is_snapshot(path: &Path) -> bool {
    if !is_btrfs(path) {
        return false;
    }
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let Ok(fd) = open_at(libc::AT_FDCWD, path.as_os_str().as_bytes(), flags) else {
        return true;
    };
    !live(fd.as_raw_fd())
}

/// The path of child `tree` of the subvolume at `fd`, relative to it.
fn child_path(fd: RawFd, tree: u64, dirid: u64) -> Option<PathBuf> {
    let mut buf = [0u64; ROOTREF_WORDS];
    buf[0] = dirid;
    buf[1] = tree;
    // SAFETY: a buffer of exactly the size the request encodes.
    if unsafe { libc::ioctl(fd, BTRFS_IOC_INO_LOOKUP_USER as _, buf.as_mut_ptr()) } != 0 {
        return None; // EACCES: on the way there is someone else's directory
    }
    // SAFETY: the same memory as bytes, in bounds of its 4096.
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), 4096) };
    let text = |b: &'_ [u8]| {
        let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        b[..n].to_vec()
    };
    let (name, dir) = (
        text(&bytes[LOOKUP_NAME..LOOKUP_PATH]),
        text(&bytes[LOOKUP_PATH..]),
    );
    // The names come off the disk, and the disk may be hostile.
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return None;
    }
    if dir.split(|&c| c == b'/').any(|c| c == b"." || c == b"..") {
        return None;
    }
    let dir = Path::new(OsStr::from_bytes(&dir))
        .strip_prefix("/")
        .map_or_else(
            |_| PathBuf::from(OsStr::from_bytes(&dir)),
            Path::to_path_buf,
        );
    Some(dir.join(OsStr::from_bytes(&name)))
}

/// Up to `room` children of the subvolume at `fd` as `(tree, dirid)`, and whether that is
/// all of them.
fn children(fd: RawFd, room: usize) -> (Vec<(u64, u64)>, bool) {
    const ITEMS_AT: usize = 1;
    let mut out = Vec::new();
    let mut min = 0u64;
    loop {
        let mut buf = [0u64; ROOTREF_WORDS];
        buf[0] = min;
        // SAFETY: a buffer of exactly the size the request encodes.
        let r = unsafe { libc::ioctl(fd, BTRFS_IOC_GET_SUBVOL_ROOTREF as _, buf.as_mut_ptr()) };
        let more = r != 0 && last_err().raw_os_error() == Some(libc::EOVERFLOW);
        if r != 0 && !more {
            return (out, false);
        }
        // SAFETY: the same memory as bytes, in bounds of its 4096.
        let n = usize::from(unsafe { *buf.as_ptr().cast::<u8>().add(ROOTREF_COUNT_BYTE) }).min(255);
        for i in 0..n {
            if out.len() >= room {
                return (out, false);
            }
            out.push((buf[ITEMS_AT + 2 * i], buf[ITEMS_AT + 2 * i + 1]));
        }
        if !more {
            return (out, true);
        }
        // The kernel moved it past what it returned; if it did not, stop rather than spin.
        if buf[0] <= min {
            return (out, false);
        }
        min = buf[0];
    }
}

/// The subvolumes below `root` a user works in (see [`live`]), at any depth, and whether
/// the search saw everything. `skip` says which paths must not be touched (a mount known
/// hung). Bounded in subvolumes, path length and time, since the image may be hostile. A
/// filesystem that is not btrfs has none.
#[must_use]
pub fn subvolumes(root: &Path, max: usize, skip: &dyn Fn(&Path) -> bool) -> (Vec<PathBuf>, bool) {
    let t0 = Instant::now();
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let top = match open_at(libc::AT_FDCWD, root.as_os_str().as_bytes(), flags) {
        Ok(f) => f,
        Err(e) => return (Vec::new(), benign(&e)),
    };
    // SAFETY: an all-zero statfs is valid, and the kernel only writes to it.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a live descriptor and a valid out pointer.
    if unsafe { libc::fstatfs(top.as_raw_fd(), &raw mut fs) } != 0 || fs.f_type != BTRFS_SUPER_MAGIC
    {
        return (Vec::new(), true);
    }
    let (mut out, mut complete) = (Vec::new(), true);
    let mut seen = 0usize;
    let mut left = vec![PathBuf::new()];
    while let Some(rel) = left.pop() {
        if t0.elapsed() >= SEARCH_TIME_MAX {
            return (out, false);
        }
        let held;
        let fd = if rel.as_os_str().is_empty() {
            top.as_raw_fd()
        } else {
            let path = root.join(&rel);
            if skip(&path) {
                complete = false;
                continue;
            }
            match open_rel(top.as_raw_fd(), &rel) {
                Ok(Some(f)) => held = f,
                Ok(None) => continue,
                Err(e) => {
                    complete &= benign(&e);
                    continue;
                }
            }
            if live(held.as_raw_fd()) {
                out.push(path);
            }
            held.as_raw_fd()
        };
        let (kids, whole) = children(fd, max.saturating_sub(seen));
        complete &= whole;
        seen += kids.len();
        for (tree, dirid) in kids {
            if let Some(p) = child_path(fd, tree, dirid) {
                let full = rel.join(p);
                if full.as_os_str().len() < libc::PATH_MAX as usize {
                    left.push(full);
                }
            }
        }
    }
    (out, complete)
}

/// Make a subvolume, for tests.
///
/// # Errors
/// Not on btrfs, or not allowed.
#[cfg(any(test, feature = "test-hooks"))]
pub fn create_subvolume(path: &Path) -> io::Result<()> {
    const BTRFS_IOC_SUBVOL_CREATE: u32 = 0x5000_940e;
    let parent = path
        .parent()
        .and_then(|p| {
            open_at(
                libc::AT_FDCWD,
                p.as_os_str().as_bytes(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
            .ok()
        })
        .ok_or_else(last_err)?;
    let mut args = [0u8; 4096];
    let name = path.file_name().map(OsStr::as_bytes).unwrap_or_default();
    args[8..8 + name.len()].copy_from_slice(name);
    // SAFETY: a buffer of exactly the size the request encodes.
    if unsafe {
        libc::ioctl(
            parent.as_raw_fd(),
            BTRFS_IOC_SUBVOL_CREATE as _,
            args.as_ptr(),
        )
    } != 0
    {
        return Err(last_err());
    }
    Ok(())
}

/// Snapshot subvolume `src` as `path`, for tests.
///
/// # Errors
/// Not on btrfs, or not allowed.
#[cfg(any(test, feature = "test-hooks"))]
pub fn create_snapshot(src: &Path, path: &Path) -> io::Result<()> {
    const BTRFS_IOC_SNAP_CREATE: u32 = 0x5000_9401;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let from = open_at(libc::AT_FDCWD, src.as_os_str().as_bytes(), flags)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    let dir = open_at(libc::AT_FDCWD, parent.as_os_str().as_bytes(), flags)?;
    let mut args = [0u8; 4096];
    args[..8].copy_from_slice(&i64::from(from.as_raw_fd()).to_ne_bytes());
    let name = path.file_name().map(OsStr::as_bytes).unwrap_or_default();
    args[8..8 + name.len()].copy_from_slice(name);
    // SAFETY: a buffer of exactly the size the request encodes.
    if unsafe { libc::ioctl(dir.as_raw_fd(), BTRFS_IOC_SNAP_CREATE as _, args.as_ptr()) } != 0 {
        return Err(last_err());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::fs;

    const SUBVOL_SETFLAGS: u32 = 0x4008_941a;

    fn set_read_only(p: &Path, on: bool) {
        let f = fs::File::open(p).unwrap();
        let flags: u64 = if on { 1 << 1 } else { 0 }; // BTRFS_SUBVOL_RDONLY
        // SAFETY: a pointer to the u64 the request encodes.
        assert_eq!(
            unsafe { libc::ioctl(f.as_raw_fd(), SUBVOL_SETFLAGS as _, &raw const flags) },
            0
        );
    }

    /// Any depth, through plain directories and through other subvolumes.
    #[test]
    fn subvolumes_are_found_at_any_depth() {
        let t = TestDir::new("btrfs").unwrap();
        let root = t.join("root");
        if create_subvolume(&root).is_err() {
            eprintln!("skipped: no btrfs here");
            return;
        }
        fs::create_dir_all(root.join("plain/deep")).unwrap();
        let (a, b, ro) = (root.join("a"), root.join("plain/deep/b"), root.join("ro"));
        create_subvolume(&a).unwrap();
        create_subvolume(&b).unwrap();
        create_subvolume(&ro).unwrap();
        fs::create_dir_all(a.join("x/y")).unwrap();
        let c = a.join("x/y/c");
        create_subvolume(&c).unwrap();
        set_read_only(&ro, true);
        let (mut got, complete) = subvolumes(&root, SUBVOLS_MAX, &|_| false);
        got.sort();
        let mut want = vec![a.clone(), c.clone(), b.clone()];
        want.sort();
        assert_eq!(got, want);
        assert!(complete);
        assert!(
            !subvolumes(&root, 1, &|_| false).1,
            "a cap reached is not all of them"
        );
        set_read_only(&ro, false);
        for p in [&c, &b, &ro, &a] {
            let _ = fs::remove_dir_all(p);
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// A snapshot is a backup, read-only or not: its trash stays out of it.
    #[test]
    fn a_writable_snapshot_is_left_out() {
        let t = TestDir::new("btrfs-snap").unwrap();
        let root = t.join("root");
        if create_subvolume(&root).is_err() {
            eprintln!("skipped: no btrfs here");
            return;
        }
        let a = root.join("a");
        create_subvolume(&a).unwrap();
        if create_snapshot(&a, &root.join("snap")).is_err() {
            eprintln!("skipped: no snapshot allowed here");
            return;
        }
        assert!(is_snapshot(&root.join("snap")));
        assert!(!is_snapshot(&a));
        assert!(!is_snapshot(Path::new("/proc")), "not btrfs: no such thing");
        // Cannot be asked: counts as one.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&a, fs::Permissions::from_mode(0o311)).unwrap();
        // SAFETY: plain getter.
        let unreadable = unsafe { libc::geteuid() } != 0;
        assert_eq!(is_snapshot(&a), unreadable);
        fs::set_permissions(&a, fs::Permissions::from_mode(0o755)).unwrap();
        let (got, _) = subvolumes(&root, SUBVOLS_MAX, &|_| false);
        assert_eq!(got, vec![a.clone()]);
        let _ = fs::remove_dir_all(root.join("snap"));
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&root);
    }

    /// Past one page of the kernel's reply (255 children).
    #[test]
    fn every_page_of_children_is_read() {
        let t = TestDir::new("btrfs-many").unwrap();
        let root = t.join("root");
        if create_subvolume(&root).is_err() {
            eprintln!("skipped: no btrfs here");
            return;
        }
        let names: Vec<_> = (0..300).map(|n| root.join(format!("s{n}"))).collect();
        for n in &names {
            create_subvolume(n).unwrap();
        }
        let (got, complete) = subvolumes(&root, SUBVOLS_MAX, &|_| false);
        assert_eq!(got.len(), 300);
        assert!(complete);
        for n in &names {
            let _ = fs::remove_dir_all(n);
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// A path that must not be touched is not, and makes the answer incomplete.
    #[test]
    fn a_skipped_subvolume_is_no_complete_answer() {
        let t = TestDir::new("btrfs-skip").unwrap();
        let root = t.join("root");
        if create_subvolume(&root).is_err() {
            eprintln!("skipped: no btrfs here");
            return;
        }
        let a = root.join("a");
        create_subvolume(&a).unwrap();
        let (got, complete) = subvolumes(&root, SUBVOLS_MAX, &|p| p == a);
        assert!(got.is_empty() && !complete);
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn another_filesystem_has_none() {
        assert_eq!(
            subvolumes(Path::new("/proc"), 8, &|_| false),
            (Vec::new(), true)
        );
        let (none, complete) = subvolumes(Path::new("/nonexistent/x"), 8, &|_| false);
        assert!(none.is_empty() && complete);
    }
}
