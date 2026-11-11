//! DIR-C1-F02: one daemon per store. A second daemon on another socket but the same
//! store is refused before it touches the store: it neither moves the first daemon's
//! temp ledger aside nor sweeps its live temp files, and leaves no socket. Once the
//! first daemon has stopped, the store can be taken again.

use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixStream},
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
        let p = base.join(format!("it-storelock-{name}-{}-{n}", std::process::id()));
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

/// Kills the child on drop, so a failed assertion never leaves a daemon running.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_serving(d: &Dir, sock: &str) -> R<Running> {
    let mut child = Running(daemon(d, sock).stderr(Stdio::null()).spawn()?);
    let t0 = Instant::now();
    while UnixStream::connect(d.join(sock)).is_err() {
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
