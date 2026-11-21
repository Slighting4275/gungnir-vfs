//! The 64-client cap under load (AGENTS.md §1.B: "serves at most 64 clients at once and
//! closes further connections immediately"): a 65th client is refused at once, the 64
//! keep working, freed slots are served again, and rounds of connect/disconnect leak no
//! descriptor. With and without the seccomp filter.

use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use gungnird::{ipc::MAX_CLIENTS, md::Client};

mod common;
use common::{Dir, R, Reaped};

/// The daemon; killed and reaped on drop.
struct Daemon(Reaped, PathBuf);

impl Daemon {
    fn start(d: &Dir, seccomp: bool) -> R<Self> {
        let sock = d.join("s.sock");
        let mut cmd = common::gungnird(d)?;
        if seccomp {
            cmd.arg("--seccomp=filter");
        }
        cmd.arg("-s")
            .arg(&sock)
            .arg("-d")
            .arg(d.join("data/m.db"))
            .env("XDG_RUNTIME_DIR", &d.0);
        let mut child = Reaped(cmd.spawn()?);
        drop(common::ready(
            &mut child,
            &sock,
            &d.join("log"),
            Duration::from_secs(10),
        )?);
        Ok(Self(child, sock))
    }

    fn fds(&self) -> usize {
        fs::read_dir(format!("/proc/{}/fd", self.0.id())).map_or(0, Iterator::count)
    }

    fn running(&mut self) -> bool {
        matches!(self.0.try_wait(), Ok(None))
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
