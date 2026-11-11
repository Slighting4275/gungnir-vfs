//! BC-CM-D02: a live upgrade (SIGHUP, an `execve` of the same process) never lets go of
//! the socket's instance lock or the store lock. A contender trying to take either lock
//! throughout 50 contended re-execs never gets it, and the daemon serves after each one.

use std::{
    fs,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use gungnird::md::Client;

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
        let p = base.join(format!("it-d02-{name}-{}-{n}", std::process::id()));
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

/// Ping `sock` until it answers or 5 s pass.
fn answers(sock: &Path) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        if let Ok(mut c) = Client::connect(sock, Duration::from_millis(500))
            && c.ping(b"d02").is_ok_and(|r| r == b"d02")
        {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    false
}

fn try_lock(path: &Path) -> bool {
    let Ok(f) = fs::OpenOptions::new().read(true).write(true).open(path) else {
        return false;
    };
    // SAFETY: flock on a file this function owns; closing it releases any lock taken.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

const REEXECS: usize = 50;

#[test]
fn contended_live_upgrades_never_release_the_locks() -> R {
    let d = Dir::new("contended")?;
    let sock = d.join("run/s.sock");
    let log = d.join("gungnird.log");
    let mut daemon = Running(
        Command::new(env!("CARGO_BIN_EXE_gungnird"))
            .arg("-s")
            .arg(&sock)
            .arg("-d")
            .arg(d.join("data/m.db"))
            .env("HOME", &d.0)
            .env("XDG_RUNTIME_DIR", &d.0)
            .env_remove("GUNGNIR_SECCOMP")
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log)?)
            .spawn()?,
    );
    let t0 = Instant::now();
    while UnixStream::connect(&sock).is_err() || !d.join("data/m.db.lock").exists() {
        if daemon.0.try_wait()?.is_some() || t0.elapsed() > Duration::from_secs(10) {
            return Err("the daemon did not start".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(answers(&sock));

    let stop = Arc::new(AtomicBool::new(false));
    let stolen = Arc::new(AtomicUsize::new(0));
    let contender = {
        let (stop, stolen) = (Arc::clone(&stop), Arc::clone(&stolen));
        let locks = [d.join("run/s.sock.lock"), d.join("data/m.db.lock")];
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                for l in &locks {
                    if try_lock(l) {
                        stolen.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    };

    let pid = daemon.0.id();
    let mut failure = None;
    for i in 1..=REEXECS {
        // SAFETY: a signal to our own child; no pointers.
        unsafe { libc::kill(pid.cast_signed(), libc::SIGHUP) };
        // Wait for this re-exec to be logged, then for the new image to serve.
        let t1 = Instant::now();
        loop {
            let mut text = String::new();
            fs::File::open(&log)?.read_to_string(&mut text)?;
            if text.matches("live upgrade: re-execing").count() >= i {
                break;
            }
            if t1.elapsed() > Duration::from_secs(5) {
                failure = Some(format!("re-exec {i} was not logged"));
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        if failure.is_some() {
            break;
        }
        if daemon.0.try_wait()?.is_some() || !answers(&sock) {
            failure = Some(format!("the daemon stopped serving after re-exec {i}"));
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = contender.join();
    let text = fs::read_to_string(&log)?;
    assert!(failure.is_none(), "{}\n{text}", failure.unwrap_or_default());
    assert_eq!(
        stolen.load(Ordering::Relaxed),
        0,
        "a contender took a lock during a live upgrade\n{text}"
    );
    assert_eq!(daemon.0.id(), pid);
    // SAFETY: as above.
    unsafe { libc::kill(pid.cast_signed(), libc::SIGTERM) };
    let status = daemon.0.wait()?;
    assert!(status.success(), "{status}\n{text}");
    Ok(())
}
