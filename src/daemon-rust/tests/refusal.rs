//! DIR-A2-F01: a start refused after the bind (a TSYNC failure, or workers short of
//! restricted rings, both injected by the test-hooks build) leaves no socket, releases
//! the lock, and removes the store when that start created it; an existing store is
//! kept and still opens.
#![cfg(feature = "test-hooks")]

use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
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
        let mode = fs::symlink_metadata(&base)?.permissions().mode();
        if mode & 0o022 != 0 {
            fs::set_permissions(&base, fs::Permissions::from_mode(mode & 0o7755))?;
        }
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = base.join(format!("it-refuse-{name}-{}-{n}", std::process::id()));
        fs::create_dir(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        Ok(Self(p))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

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

/// Every path under `dir`, relative, sorted.
fn tree(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, d: &Path, out: &mut Vec<String>) {
        if let Ok(rd) = fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                out.push(p.strip_prefix(base).unwrap().display().to_string());
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    walk(base, &p, out);
                }
            }
        }
    }
    let mut v = Vec::new();
    walk(dir, dir, &mut v);
    v.sort();
    v
}

const TSYNC: (&str, &str) = ("GUNGNIR_TEST_TSYNC_FAIL", "1");

fn engines() -> [(&'static str, &'static str); 2] {
    [("GUNGNIR_NO_URING", "0"), ("GUNGNIR_NO_URING", "1")]
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

#[test]
fn a_refused_start_on_an_existing_store_leaves_no_socket_and_keeps_the_store() -> R {
    for eng in engines() {
        let d = Dir::new("existing")?;
        fs::create_dir(d.0.join("run"))?;
        fs::set_permissions(d.0.join("run"), fs::Permissions::from_mode(0o700))?;
        serves(&d, &[eng])?;
        let db = d.0.join("data/gungnir/m.db");
        let before = fs::read(&db)?;
        let paths = tree(&d.0);
        let (st, err) = refused(&d, &[eng, TSYNC])?;
        assert!(!st.success(), "{eng:?}: {st}\n{err}");
        assert!(
            !d.0.join("run/s.sock").exists(),
            "{eng:?}: socket left\n{err}"
        );
        let mut after = tree(&d.0);
        after.retain(|p| !p.ends_with("-shm") && !p.ends_with("-wal"));
        let mut want = paths.clone();
        want.retain(|p| !p.ends_with("-shm") && !p.ends_with("-wal"));
        assert_eq!(after, want, "{eng:?}\n{err}");
        assert!(!err.contains("removed the store"), "{eng:?}\n{err}");
        assert_eq!(fs::read(&db)?.len(), before.len(), "{eng:?}");
        serves(&d, &[eng])?;
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
