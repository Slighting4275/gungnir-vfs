//! BC-CM-D02: a live upgrade (SIGHUP, an `execve` of the same process) never lets go of
//! the socket's instance lock or the store lock. A contender trying to take either lock
//! throughout 50 contended re-execs never gets it, and the daemon serves after each one.
//!
//! Why the real binary: the locks must survive real `execve`s of the daemon, fd numbers
//! and all. The handover's environment and its undo after a failed exec are tested in
//! process too (`ipc::tests::a_failed_live_upgrade_hands_over_then_undoes_everything`).

use std::{
    fs,
    io::Read,
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use gungnird::md::Client;

mod common;
use common::{Dir, R, Reaped as Running};

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
