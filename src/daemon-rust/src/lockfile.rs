//! A lock file: a regular file of ours, held with an exclusive `flock` for the holder's
//! whole life. The daemon holds two, `<socket>.lock` (no two daemons on one socket,
//! BC-HC-F07) and `<metadata.db>.lock` (no two daemons on one store, DIR-C1-F02), and a
//! live upgrade carries both into the new image without ever letting go (BC-CM-D02).

use std::{
    fs, io, mem,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

/// Why a lock could not be taken.
#[derive(Debug)]
pub enum LockError {
    /// Another process holds it.
    Held,
    /// The path is not a regular file of ours (a link, a directory, someone else's).
    Foreign,
    Io(io::Error),
}

/// A held lock file. The lock goes when this is dropped (its fd closed).
#[derive(Debug)]
pub struct LockFile {
    file: fs::File,
    path: PathBuf,
    created: bool,
}

fn euid() -> u32 {
    // SAFETY: plain getter.
    unsafe { libc::geteuid() }
}

impl LockFile {
    /// The lock at `path` for this process: the one a live upgrade carried (`carried`,
    /// adopted, see [`Self::adopt`]), else taken fresh ([`Self::take`]).
    ///
    /// # Errors
    /// [`LockError`]; a carried fd that is not this lock is [`LockError::Io`].
    pub fn acquire(path: PathBuf, carried: Option<RawFd>) -> Result<Self, LockError> {
        match carried {
            Some(fd) => Self::adopt(fd, path).map_err(LockError::Io),
            None => Self::take(path),
        }
    }

    /// Take the lock at `path`, creating the file (0600) if there is none. Never follows
    /// a symlink there.
    ///
    /// # Errors
    /// [`LockError`].
    pub fn take(path: PathBuf) -> Result<Self, LockError> {
        let open = |create_new: bool| {
            let mut o = fs::OpenOptions::new();
            o.read(true).write(true).mode(0o600);
            if create_new {
                o.create_new(true);
            }
            o.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
        };
        let (file, created) = match open(true) {
            Ok(f) => (f, true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (
                open(false).map_err(|e| {
                    if e.raw_os_error() == Some(libc::ELOOP) {
                        LockError::Foreign
                    } else {
                        LockError::Io(e)
                    }
                })?,
                false,
            ),
            Err(e) => return Err(LockError::Io(e)),
        };
        let md = file.metadata().map_err(LockError::Io)?;
        if !md.is_file() || md.uid() != euid() {
            return Err(LockError::Foreign);
        }
        // SAFETY: flock on an fd this function owns; no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let e = io::Error::last_os_error();
            return Err(if e.kind() == io::ErrorKind::WouldBlock {
                LockError::Held
            } else {
                LockError::Io(e)
            });
        }
        Ok(Self {
            file,
            path,
            created,
        })
    }

    /// Adopt `fd`, inherited across a live upgrade, as the lock at `path`: it must be that
    /// very file (same device and inode, a regular file of ours) and still hold the
    /// exclusive `flock` (re-taken on the same open file, which succeeds only for the
    /// holder's own open file). Never reopens the path, so there is no moment without
    /// the lock.
    ///
    /// # Errors
    /// `fd` is not that lock, or the lock is not held through it; the fd is then left as
    /// it was.
    pub fn adopt(fd: RawFd, path: PathBuf) -> io::Result<Self> {
        let mismatch = || {
            io::Error::other(format!(
                "the lock fd {fd} inherited from a live upgrade is not {}",
                path.display()
            ))
        };
        let mut st = mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat on an fd number; reads the buffer only on success.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
            return Err(mismatch());
        }
        // SAFETY: fstat succeeded.
        let st = unsafe { st.assume_init() };
        let md = fs::symlink_metadata(&path).map_err(|_| mismatch())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG
            || (st.st_dev, st.st_ino) != (md.dev(), md.ino())
            || st.st_uid != euid()
        {
            return Err(mismatch());
        }
        // SAFETY: flock on a validated fd; no pointers.
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(mismatch());
        }
        // SAFETY: fcntl on a validated fd; no pointers.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        Ok(Self {
            // SAFETY: the fd was handed to this image for exactly this; nothing else owns it.
            file: unsafe { fs::File::from_raw_fd(fd) },
            path,
            created: false,
        })
    }

    /// The lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this holder created the file.
    #[must_use]
    pub fn created(&self) -> bool {
        self.created
    }

    /// The lock's fd (carried across a live upgrade).
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    #[test]
    fn one_holder_at_a_time() -> io::Result<()> {
        let d = TestDir::new("lockfile")?;
        let p = d.join("x.lock");
        let first = LockFile::take(p.clone()).map_err(|e| io::Error::other(format!("{e:?}")))?;
        assert!(first.created());
        assert!(matches!(LockFile::take(p.clone()), Err(LockError::Held)));
        drop(first);
        let again = LockFile::take(p).map_err(|e| io::Error::other(format!("{e:?}")))?;
        assert!(!again.created(), "the file was there already");
        Ok(())
    }

    #[test]
    fn a_link_or_a_directory_is_never_a_lock() -> io::Result<()> {
        let d = TestDir::new("lockfile-foreign")?;
        fs::write(d.join("target"), b"")?;
        std::os::unix::fs::symlink(d.join("target"), d.join("link.lock"))?;
        assert!(matches!(
            LockFile::take(d.join("link.lock")),
            Err(LockError::Foreign)
        ));
        fs::create_dir(d.join("dir.lock"))?;
        assert!(matches!(
            LockFile::take(d.join("dir.lock")),
            Err(LockError::Foreign | LockError::Io(_))
        ));
        Ok(())
    }

    #[test]
    fn an_upgrade_adopts_only_the_lock_it_holds() -> io::Result<()> {
        let d = TestDir::new("lockfile-adopt")?;
        let held =
            LockFile::take(d.join("a.lock")).map_err(|e| io::Error::other(format!("{e:?}")))?;
        // SAFETY: dup of an fd this test owns.
        let fd = unsafe { libc::dup(held.fd()) };
        assert!(
            LockFile::adopt(fd, d.join("other.lock")).is_err(),
            "another path"
        );
        let adopted = LockFile::adopt(fd, d.join("a.lock"))?;
        assert_eq!(adopted.path(), d.join("a.lock"));
        Ok(())
    }
}
