//! DIR-C1-F02: one daemon per store. A second daemon on another socket but the same
//! store is refused before it touches the store: it neither moves the first daemon's
//! temp ledger aside nor sweeps its live temp files, and leaves no socket. Once the
//! first daemon has stopped, the store can be taken again.

use std::{
    fs,
    os::unix::net::UnixStream,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

mod common;
use common::{Dir, R, Reaped as Running};

/// A daemon on `sock` with the store at `<d>/data/gungnir/m.db`.
fn daemon(d: &Dir, sock: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
    cmd.arg("-s")
        .arg(d.join(sock))
        .arg("-d")
        .arg(d.join("data/gungnir/m.db"))
        .env("HOME", &d.0)
        .env("XDG_RUNTIME_DIR", &d.0)
        .env_remove("GUNGNIR_SECCOMP")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    cmd
}

fn start_serving(d: &Dir, sock: &str) -> R<Running> {
    let mut child = Running(daemon(d, sock).stderr(Stdio::null()).spawn()?);
    // No log: stderr is not kept, so the path is never there.
    drop(common::ready(
        &mut child,
        &d.join(sock),
        &d.join("no-log"),
        Duration::from_secs(10),
    )?);
    Ok(child)
}

fn stop(mut child: Running) -> R {
    // SAFETY: kill(2) on our own child's pid; no pointers.
    unsafe { libc::kill(child.0.id().cast_signed(), libc::SIGTERM) };
    let t0 = Instant::now();
    while child.0.try_wait()?.is_none() {
        if t0.elapsed() > Duration::from_secs(10) {
            return Err("the daemon did not stop within 10 s of SIGTERM".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[test]
fn a_second_daemon_on_the_same_store_is_refused_before_touching_it() -> R {
    let d = Dir::new("second")?;
    let first = start_serving(&d, "run/a.sock")?;
    // The socket answers from the bind; the store is the first daemon's once its temp
    // ledger exists (created after the store lock and its own sweep).
    let ledger = d.join("data/gungnir/ops-pending");
    let t0 = Instant::now();
    while !ledger.exists() {
        if t0.elapsed() > Duration::from_secs(10) {
            return Err("the first daemon never created its temp ledger".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    // A temp file of an op the first daemon is running right now.
    fs::create_dir(d.join("dest"))?;
    let live_temp = d.join("dest/.gungnir-00000000000000f2-0.tmp");
    fs::write(&live_temp, b"copy in progress")?;
    fs::write(
        &ledger,
        format!(
            "S 00000000000000f2 {}\n",
            d.join("dest/file")
                .as_os_str()
                .as_encoded_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
    )?;

    let mut second = Running(daemon(&d, "run/b.sock").stderr(Stdio::piped()).spawn()?);
    let t0 = Instant::now();
    let status = loop {
        if let Some(st) = second.0.try_wait()? {
            break st;
        }
        if t0.elapsed() > Duration::from_secs(5) {
            return Err("a second daemon on the same store kept running".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let mut err = String::new();
    if let Some(mut e) = second.0.stderr.take() {
        std::io::Read::read_to_string(&mut e, &mut err)?;
    }
    assert!(!status.success(), "refused, not a clean exit: {err}");
    assert!(
        err.contains("already using the store"),
        "the refusal names the store: {err}"
    );
    // It never touched the store: the ledger and the live temp file are as they were.
    assert!(ledger.exists(), "the first daemon's ledger was moved aside");
    assert!(!d.join("data/gungnir/ops-pending.sweep").exists());
    assert_eq!(fs::read(&live_temp)?, b"copy in progress");
    assert!(
        !d.join("run/b.sock").exists(),
        "the refused start left a socket"
    );
    assert!(
        UnixStream::connect(d.join("run/a.sock")).is_ok(),
        "the first daemon still serves"
    );
    stop(first)?;
    Ok(())
}

#[test]
fn the_store_can_be_taken_again_once_its_daemon_stopped() -> R {
    let d = Dir::new("again")?;
    let first = start_serving(&d, "run/a.sock")?;
    stop(first)?;
    let next = start_serving(&d, "run/b.sock")?;
    stop(next)?;
    Ok(())
}
