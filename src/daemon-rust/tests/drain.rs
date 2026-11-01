//! BC-A2-F03 / BC-HC-F06: the drain before an upgrade exit under `--seccomp` (D-044 item 2)
//! and the startup sweep of temp files left by unfinished copies.
//! (a) an op sent during the drain is refused (Busy), never run;
//! (b) at the drain bound, running ops are cancelled: their temp file is removed, the
//!     client gets a Cancelled done event, and the daemon exits nonzero;
//! (c) SIGTERM during the drain ends it at once, with the same cleanup as (b);
//! and a temp file recorded in the ledger by a killed daemon is removed at the next start.
//! The drain cases need the test-hooks build (slow ops, a short drain bound).
#![cfg_attr(not(feature = "test-hooks"), allow(dead_code))]

use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};

use gungnird::{
    md::{Client, MSG_MD_REPLY, ST_OK},
    ops::{self, MSG_OP_DONE, MSG_OP_PROGRESS, MSG_OP_START, OpKind, OpRequest},
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
        let p = base.join(format!("it-drain-{name}-{}-{n}", std::process::id()));
        fs::create_dir(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        Ok(Self(p))
    }

    fn join(&self, f: &str) -> PathBuf {
        self.0.join(f)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The daemon; killed and reaped on drop if still running.
struct Daemon {
    child: Child,
    sock: PathBuf,
    log: PathBuf,
}

impl Daemon {
    fn start(d: &Dir, seccomp: bool, env: &[(&str, &str)]) -> R<Self> {
        let sock = d.join("s.sock");
        let log = d.join("d.log");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
        if seccomp {
            cmd.arg("--seccomp=filter");
        }
        cmd.arg("-s")
            .arg(&sock)
            .arg("-d")
            .arg(d.join("data/m.db"))
            .env("HOME", &d.0)
            .env("XDG_DATA_HOME", d.join("data"))
            .env("XDG_RUNTIME_DIR", &d.0)
            .env_remove("GUNGNIR_SECCOMP")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log)?);
        let mut me = Self {
            child: cmd.spawn()?,
            sock,
            log,
        };
        let t0 = Instant::now();
        while UnixStream::connect(&me.sock).is_err() {
            if let Some(st) = me.child.try_wait()? {
                return Err(format!("gungnird exited early: {st}\n{}", me.text()).into());
            }
            if t0.elapsed() > Duration::from_secs(10) {
                return Err("gungnird did not start listening".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        // The socket is bound before the start-up work (the sweep among it): a handshake
        // is answered only once the daemon serves.
        drop(Client::connect(&me.sock, Duration::from_secs(10))?);
        Ok(me)
    }

    fn text(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn signal(&self, sig: i32) {
        // SAFETY: a signal to our own child.
        unsafe { libc::kill(self.child.id() as i32, sig) };
    }

    fn wait_exit(&mut self, max: Duration) -> R<(ExitStatus, Duration)> {
        let t0 = Instant::now();
        loop {
            if let Some(st) = self.child.try_wait()? {
                return Ok((st, t0.elapsed()));
            }
            if t0.elapsed() > max {
                return Err(format!("no exit within {max:?}\n{}", self.text()).into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn data_file(p: &Path, mib: usize) -> R {
    let chunk: Vec<u8> = (0..(1usize << 20))
        .map(|i| (i * 31 % 251) as u8 | 1)
        .collect();
    let mut f = fs::File::create(p)?;
    for _ in 0..mib {
        std::io::Write::write_all(&mut f, &chunk)?;
    }
    Ok(())
}

/// Send a copy; its accept status.
fn start_copy(c: &mut Client, src: &Path, dst: &Path) -> R<u32> {
    let r = OpRequest {
        kind: OpKind::Copy,
        flags: 0,
        timeout_ms: 0,
        src: src.as_os_str().as_bytes().to_vec(),
        dest: dst.as_os_str().as_bytes().to_vec(),
        src_at: None,
        dest_at: None,
    };
    let seq = c.send(MSG_OP_START, &r.encode())?;
    loop {
        let m = c.recv(Duration::from_secs(10))?;
        if m.kind == MSG_MD_REPLY && m.seq == seq {
            return Ok(u32::from_le_bytes(m.payload()[..4].try_into()?));
        }
    }
}

/// The result in the op's done event.
fn done_result(c: &mut Client) -> R<ops::OpResult> {
    let t0 = Instant::now();
    loop {
        let left = Duration::from_secs(10)
            .checked_sub(t0.elapsed())
            .ok_or("no done event")?;
        let m = c.recv(left)?;
        match m.kind {
            MSG_OP_DONE => return Ok(ops::parse_done(m.payload()).ok_or("bad done")?.result),
            MSG_OP_PROGRESS => {}
            k => return Err(format!("unexpected message kind {k}").into()),
        }
    }
}

fn temps(d: &Path) -> Vec<String> {
    fs::read_dir(d)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(".gungnir-"))
                .collect()
        })
        .unwrap_or_default()
}

/// Every chunk of a copy waits this long, so a 16 MiB copy runs for seconds.
const SLOW: &str = "1500";

fn engines() -> [(&'static str, &'static str); 2] {
    [(ops::NO_URING_ENV, "0"), (ops::NO_URING_ENV, "1")]
}

/// (b): the drain bound passes with a copy running.
#[cfg(feature = "test-hooks")]
#[test]
fn a_copy_running_at_the_drain_bound_is_cancelled_cleaned_and_the_exit_is_nonzero() -> R {
    for eng in engines() {
        let d = Dir::new("bound")?;
        let src = d.join("big");
        data_file(&src, 16)?;
        let out = d.join("out");
        fs::create_dir(&out)?;
        let mut dm = Daemon::start(
            &d,
            true,
            &[
                (ops::SLOW_OPS_ENV, SLOW),
                ("GUNGNIR_TEST_DRAIN_MS", "300"),
                eng,
            ],
        )?;
        let mut c = Client::connect(&dm.sock, Duration::from_secs(5))?;
        assert_eq!(start_copy(&mut c, &src, &out.join("dst"))?, ST_OK);
        thread::sleep(Duration::from_millis(100));
        dm.signal(libc::SIGHUP);
        let (st, took) = dm.wait_exit(Duration::from_secs(10))?;
        let text = dm.text();
        assert!(!st.success(), "{eng:?}: exit {st} after a cancel\n{text}");
        assert!(took < Duration::from_secs(4), "{eng:?}: {took:?}\n{text}");
        assert_eq!(
            done_result(&mut c)?,
            Err(ops::OpError::Cancelled),
            "{eng:?}\n{text}"
        );
        assert_eq!(temps(&out), Vec::<String>::new(), "{eng:?}\n{text}");
        assert!(!out.join("dst").exists(), "{eng:?}");
        assert!(text.contains("cancelling 1 file op"), "{eng:?}\n{text}");
    }
    Ok(())
}

/// The pause hook holds a copy at each named point on both engines, with its temp file
/// there and the destination not, and the drain bound still ends it cleanly.
#[cfg(feature = "test-hooks")]
#[test]
fn the_pause_hook_holds_a_copy_at_its_point_until_it_is_stopped() -> R {
    for point in ["mid-copy", "before-publish"] {
        for eng in engines() {
            let d = Dir::new("pause")?;
            let src = d.join("big");
            data_file(&src, 16)?;
            let out = d.join("out");
            fs::create_dir(&out)?;
            let mut dm = Daemon::start(
                &d,
                true,
                &[
                    (ops::PAUSE_AT_ENV, point),
                    ("GUNGNIR_TEST_DRAIN_MS", "300"),
                    eng,
                ],
            )?;
            let mut c = Client::connect(&dm.sock, Duration::from_secs(5))?;
            assert_eq!(start_copy(&mut c, &src, &out.join("dst"))?, ST_OK);
            let t0 = Instant::now();
            while !dm.text().contains("op paused at") {
                assert!(t0.elapsed() < Duration::from_secs(5), "{point} {eng:?}");
                thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(temps(&out).len(), 1, "{point} {eng:?}");
            assert!(!out.join("dst").exists(), "{point} {eng:?}");
            dm.signal(libc::SIGHUP);
            let (st, _) = dm.wait_exit(Duration::from_secs(10))?;
            let text = dm.text();
            assert!(!st.success(), "{point} {eng:?}: exit {st}\n{text}");
            assert_eq!(done_result(&mut c)?, Err(ops::OpError::Cancelled));
            assert_eq!(temps(&out), Vec::<String>::new(), "{point} {eng:?}");
            assert!(!out.join("dst").exists(), "{point} {eng:?}");
        }
    }
    Ok(())
}

/// A2-MGR-03: a sandboxed worker that needs a ring when the pool is empty never runs on
/// plain syscalls: the daemon exits nonzero, and the next start sweeps the temp file and
/// serves. Thread-engine daemons have no rings to lose and keep serving.
#[cfg(feature = "test-hooks")]
#[test]
fn an_empty_ring_pool_ends_a_sandboxed_daemon_rather_than_mixing_engines() -> R {
    let d = Dir::new("ringloss")?;
    let src = d.join("big");
    data_file(&src, 16)?;
    let out = d.join("out");
    fs::create_dir(&out)?;
    let uring = [(ops::RING_LOSS_ENV, "1"), (ops::NO_URING_ENV, "0")];
    let mut dm = Daemon::start(&d, true, &uring)?;
    let text = dm.text();
    let mut c = Client::connect(&dm.sock, Duration::from_secs(5))?;
    let started = start_copy(&mut c, &src, &out.join("dst"));
    let (st, _) = dm.wait_exit(Duration::from_secs(10))?;
    let log = dm.text();
    if text.contains("thread engine") {
        return Ok(()); // no io_uring here: nothing to lose
    }
    drop(started);
    assert!(!st.success(), "exit {st}\n{log}");
    assert!(log.contains("no restricted io_uring ring left"), "{log}");
    assert!(!out.join("dst").exists());
    drop(dm);
    let dm = Daemon::start(&d, true, &[(ops::NO_URING_ENV, "0")])?;
    let mut c = Client::connect(&dm.sock, Duration::from_secs(5))?;
    assert_eq!(start_copy(&mut c, &src, &out.join("dst"))?, ST_OK);
    assert_eq!(done_result(&mut c)?, Ok(()), "{}", dm.text());
    assert_eq!(temps(&out), Vec::<String>::new());

    let t = Dir::new("ringloss-threads")?;
    let src = t.join("big");
    data_file(&src, 1)?;
    let dm = Daemon::start(
        &t,
        true,
        &[(ops::RING_LOSS_ENV, "1"), (ops::NO_URING_ENV, "1")],
    )?;
    let mut c = Client::connect(&dm.sock, Duration::from_secs(5))?;
    assert_eq!(start_copy(&mut c, &src, &t.join("dst"))?, ST_OK);
    assert_eq!(done_result(&mut c)?, Ok(()), "{}", dm.text());
    Ok(())
}

/// (a): an op sent during the drain is refused.
#[cfg(feature = "test-hooks")]
#[test]
fn an_op_sent_during_the_drain_is_refused() -> R {
    let d = Dir::new("refuse")?;
    let src = d.join("big");
    data_file(&src, 16)?;
    let mut dm = Daemon::start(
        &d,
        true,
        &[
            (ops::SLOW_OPS_ENV, SLOW),
            ("GUNGNIR_TEST_DRAIN_MS", "20000"),
        ],
    )?;
    let mut c = Client::connect(&dm.sock, Duration::from_secs(5))?;
    let mut c2 = Client::connect(&dm.sock, Duration::from_secs(5))?;
    assert_eq!(start_copy(&mut c, &src, &d.join("dst1"))?, ST_OK);
    thread::sleep(Duration::from_millis(50));
    dm.signal(libc::SIGHUP);
    let t0 = Instant::now();
    while !dm.text().contains("draining") {
        assert!(t0.elapsed() < Duration::from_secs(5), "{}", dm.text());
        thread::sleep(Duration::from_millis(5));
    }
    let st = start_copy(&mut c2, &src, &d.join("dst2"))?;
    assert_eq!(
        st,
        gungnird::md::ST_BUSY,
        "the second copy was accepted\n{}",
        dm.text()
    );
    dm.signal(libc::SIGTERM);
    let (es, _) = dm.wait_exit(Duration::from_secs(10))?;
    assert!(!es.success(), "{es}");
    assert!(!d.join("dst2").exists() && temps(&d.0).is_empty());
    Ok(())
}

/// (c): SIGTERM during a long drain ends it at once, with the cleanup of (b).
#[cfg(feature = "test-hooks")]
#[test]
fn sigterm_during_the_drain_ends_it_promptly_and_cleans_up() -> R {
    for eng in engines() {
        let d = Dir::new("term")?;
        let src = d.join("big");
        data_file(&src, 16)?;
        let mut dm = Daemon::start(
            &d,
            true,
            &[
                (ops::SLOW_OPS_ENV, SLOW),
                ("GUNGNIR_TEST_DRAIN_MS", "20000"),
                eng,
            ],
        )?;
        let mut c = Client::connect(&dm.sock, Duration::from_secs(5))?;
        assert_eq!(start_copy(&mut c, &src, &d.join("dst"))?, ST_OK);
        thread::sleep(Duration::from_millis(50));
        dm.signal(libc::SIGHUP);
        thread::sleep(Duration::from_millis(50));
        dm.signal(libc::SIGTERM);
        let (st, took) = dm.wait_exit(Duration::from_secs(10))?;
        let text = dm.text();
        assert!(!st.success(), "{eng:?}: {st}\n{text}");
        assert!(took < Duration::from_secs(3), "{eng:?}: {took:?}\n{text}");
        assert!(text.contains("during the drain"), "{eng:?}\n{text}");
        assert_eq!(
            done_result(&mut c)?,
            Err(ops::OpError::Cancelled),
            "{eng:?}\n{text}"
        );
        assert_eq!(temps(&d.0), Vec::<String>::new(), "{eng:?}\n{text}");
    }
    Ok(())
}

/// BC-HC-F06: temp files of a copy a killed daemon left behind are removed at the next
/// start (ledger next to the database), and nothing else is touched. Sandboxed, so the
/// ledger writes are checked under the filter too.
#[test]
fn temp_files_of_unfinished_copies_are_swept_at_start() -> R {
    let d = Dir::new("sweep")?;
    let out = d.join("out");
    let tree = out.join("tree");
    fs::create_dir_all(tree.join("sub"))?;
    fs::create_dir_all(d.join("data"))?;
    // Private whatever the umask (the daemon refuses a data dir others can write).
    fs::set_permissions(d.join("data"), fs::Permissions::from_mode(0o700))?;
    let id = 0x2a_u64;
    let ours = [
        out.join(format!(".gungnir-{id:016x}-0.tmp")),
        tree.join(format!("sub/.gungnir-{id:016x}-1.tmp")),
    ];
    let keep = [
        out.join(format!(".gungnir-{:016x}-0.tmp", id + 1)), // another op's, ended
        out.join("user.txt"),
        tree.join("sub/.gungnir-notes.tmp"),
    ];
    for p in ours.iter().chain(keep.iter()) {
        fs::write(p, b"x")?;
    }
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let ledger = format!(
        "S {id:016x} {}\nS {:016x} {}\nE {:016x}\n",
        hex(tree.as_os_str().as_bytes()),
        id + 1,
        hex(out.join("other").as_os_str().as_bytes()),
        id + 1
    );
    fs::write(d.join("data/ops-pending"), ledger)?;
    let dm = Daemon::start(&d, true, &[])?;
    for p in &ours {
        assert!(!p.exists(), "{} left\n{}", p.display(), dm.text());
    }
    for p in &keep {
        assert!(p.exists(), "{} removed\n{}", p.display(), dm.text());
    }
    assert!(
        dm.text().contains("removed 2 temp file(s)"),
        "{}",
        dm.text()
    );
    assert_eq!(fs::read(d.join("data/ops-pending"))?, b"");
    // A finished copy leaves the ledger empty again (it does not grow without bound).
    let mut c = Client::connect(&dm.sock, Duration::from_secs(5))?;
    assert_eq!(start_copy(&mut c, &keep[1], &out.join("copy.txt"))?, ST_OK);
    assert_eq!(done_result(&mut c)?, Ok(()), "{}", dm.text());
    assert_eq!(fs::read(out.join("copy.txt"))?, b"x");
    assert_eq!(fs::read(d.join("data/ops-pending"))?, b"");
    Ok(())
}
