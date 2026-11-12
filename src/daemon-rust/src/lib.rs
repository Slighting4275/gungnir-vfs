use std::{fmt, io, path::PathBuf};

pub mod btrfs;
pub mod fsid;
pub mod health;
pub mod ipc;
pub mod md;
pub mod mdsvc;
pub mod ops;
pub mod opsvc;
pub mod recent;
pub mod seccomp;
pub mod store;
pub mod trash;
pub mod vfssvc;

pub use store::open_db;

/// One byte from exactly two hex digits (either case), as `%XX` escapes and the
/// daemon's hex names spell it. Not `u8::from_str_radix`, which also takes a sign:
/// `+f` decoded to 0x0f, so one byte had two spellings where GLib rejects the escape.
#[must_use]
pub(crate) fn hex_byte(pair: &[u8]) -> Option<u8> {
    let [hi, lo] = pair else { return None };
    let d = |b: u8| {
        char::from(b)
            .to_digit(16)
            .and_then(|v| u8::try_from(v).ok())
    };
    Some((d(*hi)? << 4) | d(*lo)?)
}

/// What a test does when this machine lacks something it needs (btrfs, a filesystem
/// feature, a user namespace, a non-root user): it fails, unless
/// `GUNGNIR_ALLOW_MISSING=1` asks to skip such tests on purpose, and then it says so on a
/// SKIP line. No test skips silently. Where a tmpfs can stand in (holes, user xattrs,
/// btime, the filesystem uuid ioctl), [`testenv::rerun_on_tmpfs`] runs the test there.
#[doc(hidden)]
pub mod testenv {
    use std::{io::Write as _, path::Path, process::Command};

    /// Set (to anything but "" or "0") to skip, with a SKIP line, the tests this machine
    /// cannot run.
    pub const ALLOW_MISSING_ENV: &str = "GUNGNIR_ALLOW_MISSING";
    /// Set in a test's rerun on tmpfs (see [`rerun_on_tmpfs`]).
    pub const ON_TMPFS_ENV: &str = "GUNGNIR_TEST_ON_TMPFS";

    /// A line straight to stderr: the test harness swallows `eprintln!` of a passing test,
    /// and a skip must always show.
    pub fn say(line: &str) {
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    }

    fn allowed(v: Option<&std::ffi::OsStr>) -> bool {
        v.is_some_and(|v| !v.is_empty() && v != "0")
    }

    /// The test `test` cannot run: this machine has no `what`. Panics (fails the test)
    /// unless [`ALLOW_MISSING_ENV`] is set; then prints a SKIP line and returns.
    ///
    /// # Panics
    /// As described.
    pub fn missing(test: &str, what: &str) {
        match decide(test, what, std::env::var_os(ALLOW_MISSING_ENV).as_deref()) {
            Ok(()) => say(&format!(
                "SKIP ({ALLOW_MISSING_ENV}=1): no {what} here: {test} did not run"
            )),
            Err(e) => panic!("{e}"),
        }
    }

    /// [`missing`]'s rule with the variable's value given (prints nothing): `Ok` if the
    /// skip is allowed, else `Err` with the reason.
    ///
    /// # Errors
    /// Not allowed.
    pub fn decide(test: &str, what: &str, allow: Option<&std::ffi::OsStr>) -> Result<(), String> {
        if allowed(allow) {
            Ok(())
        } else {
            Err(format!(
                "no {what} here, so {test} cannot run; set {ALLOW_MISSING_ENV}=1 to skip such \
                 tests on purpose"
            ))
        }
    }

    /// True in a rerun made by [`rerun_on_tmpfs`].
    #[must_use]
    pub fn on_tmpfs() -> bool {
        allowed(std::env::var_os(ON_TMPFS_ENV).as_deref())
    }

    /// Run test `test` of this test binary again in a user+mount namespace with a private
    /// tmpfs mounted over `base` (where its scratch directories live), for a feature the
    /// filesystem here lacks (`what`). `Ok` if it passed there (its SKIP lines are passed
    /// on); `Err` with its output if it failed. Without user namespaces: [`missing`].
    ///
    /// # Errors
    /// The rerun failed, or could not be started.
    pub fn rerun_on_tmpfs(test: &str, base: &Path, what: &str) -> Result<(), String> {
        if on_tmpfs() {
            return Err(format!("{test}: even a tmpfs here has no {what}"));
        }
        let usable = Command::new("unshare")
            .args(["-rm", "true"])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !usable {
            missing(
                test,
                &format!("{what}, and no user namespace to mount a tmpfs with it"),
            );
            return Ok(());
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(base).map_err(|e| e.to_string())?;
        let out = Command::new("unshare")
            .args([
                "-rm",
                "sh",
                "-c",
                "mount -t tmpfs -o mode=0700 gungnir-test \"$0\" && exec \"$@\"",
            ])
            .arg(base)
            .arg(&exe)
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(ON_TMPFS_ENV, "1")
            .output()
            .map_err(|e| e.to_string())?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        text.lines().filter(|l| l.starts_with("SKIP")).for_each(say);
        if !out.status.success() || !text.contains("test result: ok. 1 passed") {
            return Err(format!(
                "{test} failed in its rerun on tmpfs (no {what} here) ({}):\n{text}",
                out.status
            ));
        }
        say(&format!(
            "note: this filesystem lacks {what}: {test} ran on a tmpfs instead"
        ));
        Ok(())
    }

    /// `<repo>/.build/tmp`, where every test keeps its scratch directories.
    ///
    /// # Panics
    /// `<repo>/.build` cannot be resolved.
    #[must_use]
    pub fn scratch_base() -> std::path::PathBuf {
        std::fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build"))
            .unwrap_or_else(|e| panic!("<repo>/.build: {e}"))
            .join("tmp")
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::OsStr;

        /// A missing feature fails a test unless a skip is asked for.
        #[test]
        fn a_missing_feature_fails_unless_a_skip_is_asked_for() {
            for (allow, skips) in [
                (None, false),
                (Some(OsStr::new("")), false),
                (Some(OsStr::new("0")), false),
                (Some(OsStr::new("1")), true),
            ] {
                let got = super::decide("rule test", "widget", allow);
                if skips {
                    assert_eq!(got, Ok(()), "{allow:?}");
                } else {
                    assert!(
                        got.as_ref().is_err_and(|e| e.contains("no widget here")
                            && e.contains(super::ALLOW_MISSING_ENV)),
                        "{allow:?}: {got:?}"
                    );
                }
            }
        }
    }
}

/// Scratch directories for tests, under `<repo>/.build/tmp` (AGENTS.md §3: never /tmp).
#[cfg(test)]
pub(crate) mod testdir {
    use std::{
        ffi::CString,
        fs, io,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, PermissionsExt},
            },
        },
        path::{Path, PathBuf},
        sync::atomic::{AtomicU32, Ordering},
    };

    /// A fresh directory that only we can enter (0700), one per test, removed with its
    /// contents on drop. CI runners check the repo out with umask 0000, which leaves
    /// `.build/tmp` itself 0777, and `ipc::bind` (rightly) refuses a socket directory that
    /// others can write to. Every check and chmod is done on an fd opened with
    /// `O_NOFOLLOW` (never by path), so a symlink or a directory swapped in between the
    /// check and the chmod can never redirect it to some other directory.
    pub(crate) struct TestDir(PathBuf);

    fn euid() -> u32 {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// Open `name` (relative to `dirfd`, or a path if `dirfd` is `AT_FDCWD`) as a
    /// directory without following a symlink in its last component, and require that it
    /// is a directory owned by us.
    fn open_own_dir(dirfd: i32, name: &CString) -> io::Result<fs::File> {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `name` is a valid NUL-terminated string that outlives the call.
        let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by openat and nothing else owns it.
        let dir = unsafe { fs::File::from_raw_fd(fd) };
        let md = dir.metadata()?; // fstat: the object we opened, not whatever the path is now
        if !md.is_dir() || md.uid() != euid() {
            return Err(io::Error::other("not a directory owned by us"));
        }
        Ok(dir)
    }

    fn cstr(p: &[u8]) -> io::Result<CString> {
        CString::new(p).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }

    impl TestDir {
        pub(crate) fn new(name: &str) -> io::Result<Self> {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let (base_path, base) = base()?;
            loop {
                let n = NEXT.fetch_add(1, Ordering::Relaxed);
                let leaf = format!("{name}-{}-{n}", std::process::id());
                let c_leaf = cstr(leaf.as_bytes())?;
                // mkdirat in the directory we checked; never adopt an existing entry.
                // SAFETY: `base` is an open directory fd and `c_leaf` is NUL-terminated.
                if unsafe { libc::mkdirat(base.as_raw_fd(), c_leaf.as_ptr(), 0o700) } < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::AlreadyExists && n < 1_000_000 {
                        continue;
                    }
                    return Err(e);
                }
                let dir = TestDir(base_path.join(&leaf));
                // The umask may have stripped bits from 0700, never added any: make it exact.
                open_own_dir(base.as_raw_fd(), &c_leaf)?
                    .set_permissions(fs::Permissions::from_mode(0o700))?;
                return Ok(dir);
            }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }

        pub(crate) fn join(&self, file: &str) -> PathBuf {
            self.0.join(file)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            // remove_dir_all never follows symlinks inside the tree (std, since 1.58.1).
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// `<repo>/.build/tmp` (its parent canonicalised: `sun_path` holds only 108 bytes),
    /// opened `O_NOFOLLOW`: a symlink there is refused, never followed. It must be a
    /// directory owned by us, and its group/world write bits are removed via `fchmod` on
    /// that fd, so no other user can swap a test's directory out from under it.
    fn base() -> io::Result<(PathBuf, fs::File)> {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build");
        let path = fs::canonicalize(&parent)?.join("tmp");
        if let Err(e) = fs::create_dir(&path)
            && e.kind() != io::ErrorKind::AlreadyExists
        {
            return Err(e);
        }
        let dir =
            open_own_dir(libc::AT_FDCWD, &cstr(path.as_os_str().as_bytes())?).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: {e} (symlinks are refused)", path.display()),
                )
            })?;
        let mode = dir.metadata()?.mode();
        if mode & 0o022 != 0 {
            dir.set_permissions(fs::Permissions::from_mode(mode & 0o7755))?;
        }
        Ok((path, dir))
    }

    #[test]
    fn test_dirs_are_private_whatever_the_umask() -> io::Result<()> {
        let a = TestDir::new("priv")?;
        let b = TestDir::new("priv")?;
        assert_ne!(a.path(), b.path());
        for d in [&a, &b] {
            let md = fs::symlink_metadata(d.path())?;
            assert!(md.is_dir());
            assert_eq!(md.mode() & 0o7777, 0o700);
            let parent = d.path().parent().ok_or(io::ErrorKind::NotFound)?;
            assert_eq!(fs::symlink_metadata(parent)?.mode() & 0o022, 0);
        }
        let gone = a.path().to_path_buf();
        fs::write(a.join("f"), b"x")?;
        drop(a);
        assert!(!gone.exists());
        Ok(())
    }
    #[test]
    fn open_own_dir_never_follows_a_symlink() -> io::Result<()> {
        let t = TestDir::new("sym")?;
        let real = t.join("real");
        fs::create_dir(&real)?;
        let link = t.join("link");
        std::os::unix::fs::symlink(&real, &link)?;
        let c = cstr(link.as_os_str().as_bytes())?;
        assert!(open_own_dir(libc::AT_FDCWD, &c).is_err());
        assert!(open_own_dir(libc::AT_FDCWD, &cstr(real.as_os_str().as_bytes())?).is_ok());
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Sqlite(rusqlite::Error),
    NoHome,
    WalUnavailable(String),
    NoSocketPath,
    SocketPathTooLong(PathBuf),
    AlreadyRunning(PathBuf),
    /// Another daemon holds the store's lock (DIR-C1-F02).
    StoreInUse(PathBuf),
    NotASocket(PathBuf),
    InsecureSocketDir(PathBuf),
    InsecureDbDir(PathBuf),
    Protocol(&'static str),
    RingFull,
    Fsid(fsid::FsidError),
    Md(md::MdError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Sqlite(e) => write!(f, "sqlite: {e}"),
            Error::NoHome => write!(
                f,
                "neither XDG_DATA_HOME nor HOME is an absolute path, and no database path was given"
            ),
            Error::WalUnavailable(mode) => {
                write!(
                    f,
                    "sqlite refused WAL journal mode (still in '{mode}' mode)"
                )
            }
            Error::NoSocketPath => write!(f, "no socket path (set XDG_RUNTIME_DIR or HOME)"),
            Error::SocketPathTooLong(p) => write!(f, "socket path too long: {}", p.display()),
            Error::AlreadyRunning(p) => write!(f, "already listening on {}", p.display()),
            Error::StoreInUse(p) => write!(
                f,
                "another gungnird is already using the store {}",
                p.display()
            ),
            Error::NotASocket(p) => write!(f, "{} exists and is not a socket", p.display()),
            Error::InsecureSocketDir(p) => write!(
                f,
                "{} must be a directory owned by this user and not world-writable",
                p.display()
            ),
            Error::InsecureDbDir(p) => write!(
                f,
                "{} must be owned by this user and not writable by others",
                p.display()
            ),
            Error::Protocol(what) => write!(f, "protocol: {what}"),
            Error::RingFull => write!(f, "ring full"),
            Error::Fsid(e) => write!(f, "fsid: {e}"),
            Error::Md(e) => write!(f, "metadata: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<fsid::FsidError> for Error {
    fn from(e: fsid::FsidError) -> Self {
        Error::Fsid(e)
    }
}

impl From<md::MdError> for Error {
    fn from(e: md::MdError) -> Self {
        Error::Md(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Synthetic fs id for UUID-less filesystems: `synth-<first 32 hex of BLAKE3>`.
/// Each part is length-prefixed so ("ab","c") and ("a","bc") never collide.
#[must_use]
pub fn synth_fs_id(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let hex = h.finalize().to_hex();
    format!("synth-{}", &hex[..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synth_id_format_and_separation() {
        let id = synth_fs_id(&[b"tmpfs", b"/run/user/1000"]);
        assert!(id.starts_with("synth-"));
        assert_eq!(id.len(), "synth-".len() + 32);
        assert!(id[6..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, synth_fs_id(&[b"tmpfs", b"/run/user/1000"]));
        assert_ne!(synth_fs_id(&[b"ab", b"c"]), synth_fs_id(&[b"a", b"bc"]));
    }
}
