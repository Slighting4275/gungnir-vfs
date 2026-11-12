//! The 64-client cap under load (AGENTS.md §1.B: "serves at most 64 clients at once and
//! closes further connections immediately"): a 65th client is refused at once, the 64
//! keep working, freed slots are served again, and rounds of connect/disconnect leak no
//! descriptor. With and without the seccomp filter.

use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};

use gungnird::{ipc::MAX_CLIENTS, md::Client};

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
        let p = base.join(format!("it-cap-{name}-{}-{n}", std::process::id()));
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

/// The daemon; killed and reaped on drop.
struct Daemon(Child, PathBuf);

impl Daemon {
    fn start(d: &Dir, seccomp: bool) -> R<Self> {
        let sock = d.0.join("s.sock");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
        if seccomp {
            cmd.arg("--seccomp=filter");
        }
        cmd.arg("-s")
            .arg(&sock)
            .arg("-d")
            .arg(d.0.join("data/m.db"))
            .env("HOME", &d.0)
            .env("XDG_DATA_HOME", d.0.join("data"))
            .env("XDG_RUNTIME_DIR", &d.0)
            .env_remove("GUNGNIR_SECCOMP")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let me = Self(cmd.spawn()?, sock);
        let t0 = Instant::now();
        while UnixStream::connect(&me.1).is_err() {
            if t0.elapsed() > Duration::from_secs(10) {
                return Err("gungnird did not start listening".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        drop(Client::connect(&me.1, Duration::from_secs(10))?);
        Ok(me)
    }

    fn fds(&self) -> usize {
        fs::read_dir(format!("/proc/{}/fd", self.0.id())).map_or(0, Iterator::count)
    }

    fn running(&mut self) -> bool {
        matches!(self.0.try_wait(), Ok(None))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Descriptors settle once the daemon has reaped closed clients.
fn settled_fds(d: &Daemon, at_most: usize) -> usize {
    let t0 = Instant::now();
    loop {
        let n = d.fds();
        if n <= at_most || t0.elapsed() > Duration::from_secs(5) {
            return n;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn cap_holds(seccomp: bool) -> R {
    let dir = Dir::new(if seccomp { "seccomp" } else { "plain" })?;
    let mut d = Daemon::start(&dir, seccomp)?;
    // The start-up probe's slot is released a moment after it closes.
    thread::sleep(Duration::from_millis(300));
    let idle_fds = settled_fds(&d, usize::MAX);
    let t = Duration::from_secs(5);

    // All 64 are served, and answer.
    let mut clients = (0..MAX_CLIENTS)
        .map(|_| Client::connect(&d.1, t))
        .collect::<Result<Vec<_>, _>>()?;
    for c in &mut clients {
        assert_eq!(c.ping(b"hi")?, b"hi");
    }
    // More are refused at once (closed, no hello answered), and none of the 64 suffers.
    for _ in 0..20 {
        let t0 = Instant::now();
        assert!(
            Client::connect(&d.1, t).is_err(),
            "a client over the cap was served"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "refusal took {:?}",
            t0.elapsed()
        );
    }
    for c in &mut clients {
        assert_eq!(c.ping(b"still")?, b"still");
    }
    // Freed slots are served again, round after round, with no descriptor kept.
    for round in 0..5 {
        clients.truncate(MAX_CLIENTS - 16);
        thread::sleep(Duration::from_millis(100)); // the daemon notices the closes
        let mut fresh = Vec::new();
        let t0 = Instant::now();
        while fresh.len() < 16 {
            match Client::connect(&d.1, t) {
                Ok(c) => fresh.push(c),
                Err(e) if t0.elapsed() < Duration::from_secs(5) => {
                    let _ = e; // a slot not yet released: try again
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(format!("round {round}: freed slots not served: {e}").into()),
            }
        }
        clients.extend(fresh);
        for c in &mut clients {
            assert_eq!(c.ping(b"r")?, b"r");
        }
    }
    drop(clients);
    let after = settled_fds(&d, idle_fds);
    assert!(
        after <= idle_fds,
        "descriptors leaked: {idle_fds} idle before, {after} after"
    );
    assert!(d.running(), "gungnird died under load");
    Ok(())
}

#[test]
fn the_client_cap_holds_under_load() -> R {
    cap_holds(false)
}

#[test]
fn the_client_cap_holds_under_load_with_seccomp() -> R {
    cap_holds(true)
}
