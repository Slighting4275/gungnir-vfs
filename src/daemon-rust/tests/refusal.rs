//! DIR-A2-F01: a start refused after the bind (a TSYNC failure, or workers short of
//! restricted rings, both injected by the test-hooks build) leaves no socket, releases
//! the lock, and removes the store when that start created it. Through the real binary
//! on the io_uring engine with the real seccomp path: restricted rings are process-wide,
//! so this cannot run in a test process. The rollback itself (fresh and existing store,
//! a held store) is tested in process, `daemon::tests`.
#![cfg(feature = "test-hooks")]

use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

mod common;
use common::{Dir, R};

/// No `common::gungnird` here: its log file would show in the trees these tests compare,
/// and they read stderr themselves.
fn daemon(d: &Dir, env: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
    cmd.arg("--seccomp=filter")
        .arg("-s")
        .arg(d.0.join("run/s.sock"))
        .arg("-d")
        .arg(d.0.join("data/gungnir/m.db"))
        .env("HOME", &d.0)
        .env("XDG_RUNTIME_DIR", &d.0)
        .env_remove("GUNGNIR_SECCOMP")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

/// Run a start that must be refused: its status and stderr.
///
/// A daemon that does not refuse (it starts serving) is stopped after 10 s and reported
/// as such, so the test fails instead of waiting forever: without io_uring the mixed-ring
/// start fell back to threads and served, and the test hung.
fn refused(d: &Dir, env: &[(&str, &str)]) -> R<(ExitStatus, String)> {
    use std::io::Read;
    let mut child = daemon(d, env).spawn()?;
    let mut stderr = child.stderr.take().ok_or("no stderr pipe")?;
    let reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let t0 = Instant::now();
    let (st, late) = loop {
        if let Some(st) = child.try_wait()? {
            break (st, false);
        }
        if t0.elapsed() > Duration::from_secs(10) {
            // SAFETY: a signal to our own child.
            unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
            break (child.wait()?, true);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let mut err = reader.join().map_err(|_| "stderr reader panicked")?;
    if late {
        err.push_str("\n(test: the daemon did not refuse; stopped after 10 s)");
    }
    Ok((st, err))
}

/// Start a normal daemon, check it serves, stop it with SIGTERM: its stderr.
fn serves(d: &Dir, env: &[(&str, &str)]) -> R<String> {
    let mut child = daemon(d, env).stderr(Stdio::null()).spawn()?;
    let t0 = Instant::now();
    let r = loop {
        if UnixStream::connect(d.0.join("run/s.sock")).is_ok() {
            break Ok(String::new());
        }
        if let Some(st) = child.try_wait()? {
            break Err(format!("daemon exited: {st}").into());
        }
        if t0.elapsed() > Duration::from_secs(10) {
            break Err("daemon did not listen".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    // SAFETY: a signal to our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let st = child.wait()?;
    r.and_then(|s| {
        if st.success() {
            Ok(s)
        } else {
            Err(format!("stop: {st}").into())
        }
    })
}

use gungnird::testenv::tree;

const TSYNC: (&str, &str) = ("GUNGNIR_TEST_TSYNC_FAIL", "1");

/// The io_uring engine only: the thread engine's refusal runs in process
/// (`daemon::tests::a_refused_sandbox_leaves_nothing_behind`).
fn engines() -> [(&'static str, &'static str); 1] {
    [("GUNGNIR_NO_URING", "0")]
}

#[test]
fn a_refused_start_on_a_fresh_store_leaves_no_socket_and_no_store() -> R {
    for eng in engines() {
        let d = Dir::new("fresh")?;
        fs::create_dir(d.0.join("run"))?;
        fs::set_permissions(d.0.join("run"), fs::Permissions::from_mode(0o700))?;
        let (st, err) = refused(&d, &[eng, TSYNC])?;
        assert!(!st.success(), "{eng:?}: {st}\n{err}");
        assert!(err.contains("TSYNC"), "{eng:?}\n{err}");
        // Only the lock file stays (flock-based, like after any stop).
        assert_eq!(tree(&d.0), ["run", "run/s.sock.lock"], "{eng:?}\n{err}");
        // The lock is free: a normal start right after works.
        serves(&d, &[eng])?;
        assert!(d.0.join("data/gungnir/m.db").exists());
    }
    Ok(())
}

/// The refusal when a uring engine ends up with a worker short of a restricted ring
/// (mixed engines): same cleanup. Only where io_uring rings can be made.
#[test]
fn a_mixed_engine_refusal_leaves_no_socket_and_no_store() -> R {
    let d = Dir::new("mixed")?;
    fs::create_dir(d.0.join("run"))?;
    fs::set_permissions(d.0.join("run"), fs::Permissions::from_mode(0o700))?;
    let (st, err) = refused(
        &d,
        &[("GUNGNIR_NO_URING", "0"), ("GUNGNIR_TEST_MIXED_RINGS", "1")],
    )?;
    if !err.contains("file ops engine: Uring") {
        // A fallback is acceptable only where io_uring is unavailable and a skip was asked
        // for (GUNGNIR_ALLOW_NO_URING=1); otherwise this fails.
        assert!(
            !gungnird::ops::io::uring_for_tests_env("the mixed-engine refusal test"),
            "io_uring works here, but the daemon did not use it\n{err}"
        );
        return Ok(());
    }
    assert!(!st.success(), "{st}\n{err}");
    assert!(err.contains("refusing to start sandboxed"), "{err}");
    assert_eq!(tree(&d.0), ["run", "run/s.sock.lock"], "{err}");
    serves(&d, &[])?;
    Ok(())
}
