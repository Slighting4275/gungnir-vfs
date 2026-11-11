//! BC-HC-F07: no double start. A socket-activated daemon that cannot hold the socket's
//! instance lock refuses before serving, with no side effects; a daemon removes its
//! socket on exit only while that path is still the socket it bound.

use std::{
    fs,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};

type R<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A private (0700) directory under <repo>/.build/tmp, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> R<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let base = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build"))?
            .join("tmp");
        fs::create_dir_all(&base)?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = base.join(format!("it-f07-{name}-{}-{n}", std::process::id()));
        fs::create_dir(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        Ok(Self(p))
    }

    fn join(&self, p: &str) -> PathBuf {
        self.0.join(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Kills the child on drop, so a failed assertion never leaves a daemon running.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The daemon with the store at `<d>/data/m.db`, run through `sh` so the environment
/// can name its own pid: `LISTEN_PID=$$` before `exec` is the daemon's pid, as systemd
/// sets it. (`Command` builds the environment before the fork, so `pre_exec` cannot.)
fn base_cmd(d: &Dir, activated: bool) -> Command {
    let script = if activated {
        "export LISTEN_FDS=1 LISTEN_PID=$$; exec \"$0\" \"$@\""
    } else {
        "exec \"$0\" \"$@\""
    };
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_gungnird"))
        .arg("-d")
        .arg(d.join("data/m.db"))
        .env("HOME", &d.0)
        .env("XDG_RUNTIME_DIR", &d.0)
        .env_remove("GUNGNIR_SECCOMP")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

/// A daemon started the way systemd starts it: `listener` as fd 3, `LISTEN_FDS=1` and
/// `LISTEN_PID` its own pid.
fn activated(d: &Dir, listener: &UnixListener) -> R<Running> {
    let raw = listener.as_raw_fd();
    let mut cmd = base_cmd(d, true);
    // SAFETY: only async-signal-safe calls (dup2, fcntl) between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(3, libc::F_GETFD);
            libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            Ok(())
        });
    }
    Ok(Running(cmd.spawn()?))
}

/// Wait at most 5 s for the child to exit: its status and stderr.
fn exits(mut child: Running) -> R<(std::process::ExitStatus, String)> {
    let t0 = Instant::now();
    let status = loop {
        if let Some(st) = child.0.try_wait()? {
            break st;
        }
        if t0.elapsed() > Duration::from_secs(5) {
            return Err("the daemon kept running".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let mut err = String::new();
    if let Some(mut e) = child.0.stderr.take() {
        e.read_to_string(&mut err)?;
    }
    Ok((status, err))
}

fn manual(d: &Dir, sock: &Path) -> R<Running> {
    let mut cmd = base_cmd(d, false);
    let mut child = Running(cmd.arg("-s").arg(sock).stderr(Stdio::null()).spawn()?);
    let t0 = Instant::now();
    while UnixStream::connect(sock).is_err() {
        if let Some(st) = child.0.try_wait()? {
            return Err(format!("the daemon exited before serving: {st}").into());
        }
        if t0.elapsed() > Duration::from_secs(10) {
            return Err("the daemon did not start serving within 10 s".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(child)
}

fn sigterm_and_wait(child: Running) -> R {
    // SAFETY: kill(2) on our own child's pid; no pointers.
    unsafe { libc::kill(child.0.id().cast_signed(), libc::SIGTERM) };
    let (status, _) = exits(child)?;
    assert!(status.success(), "a clean exit on SIGTERM: {status}");
    Ok(())
}

#[test]
fn activated_start_refuses_a_held_instance_lock_without_side_effects() -> R {
    let d = Dir::new("held")?;
    let sock = d.join("s.sock");
    let listener = UnixListener::bind(&sock)?;
    // Another daemon's instance lock on this socket.
    let lock = fs::File::create(d.join("s.sock.lock"))?;
    // SAFETY: flock on a file we own; no pointers.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let (status, err) = exits(activated(&d, &listener)?)?;
    assert_eq!(status.code(), Some(1), "{err}");
    assert!(
        err.contains(&format!("already listening on {}", sock.display())),
        "{err}"
    );
    assert!(sock.exists(), "the supervisor's socket is kept");
    assert!(!d.join("data").exists(), "the store was touched: {err}");
    Ok(())
}

#[test]
fn activated_start_refuses_lock_open_errors_without_side_effects() -> R {
    let d = Dir::new("lockerr")?;
    let sock = d.join("s.sock");
    let listener = UnixListener::bind(&sock)?;
    fs::create_dir(d.join("s.sock.lock"))?; // cannot be opened as the lock file
    let (status, err) = exits(activated(&d, &listener)?)?;
    assert_eq!(status.code(), Some(1), "{err}");
    assert!(err.contains("gungnird: io:"), "{err}");
    assert!(sock.exists(), "the supervisor's socket is kept");
    assert!(!d.join("data").exists(), "the store was touched: {err}");
    Ok(())
}

#[test]
fn manual_owner_exit_preserves_a_replaced_socket() -> R {
    let d = Dir::new("replaced")?;
    let sock = d.join("s.sock");
    let first = manual(&d, &sock)?;
    // Someone removed the first daemon's socket and another one now listens there.
    fs::remove_file(&sock)?;
    let other = UnixListener::bind(&sock)?;
    sigterm_and_wait(first)?;
    assert!(
        sock.exists(),
        "the exiting daemon removed a socket it did not bind"
    );
    let _c = UnixStream::connect(&sock)?;
    other.set_nonblocking(true)?;
    assert!(other.accept().is_ok(), "the other socket still works");
    Ok(())
}

#[test]
fn manual_owner_exit_removes_its_own_socket() -> R {
    let d = Dir::new("own")?;
    let sock = d.join("s.sock");
    let daemon = manual(&d, &sock)?;
    sigterm_and_wait(daemon)?;
    assert!(!sock.exists(), "the daemon's own socket is removed on exit");
    Ok(())
}
