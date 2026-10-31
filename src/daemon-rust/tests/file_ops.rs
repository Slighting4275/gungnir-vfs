//! Milestone 8 over the real socket: the built `gungnird` runs copy, move, delete,
//! delete-tree and fsync for a client, streams progress, answers exactly one done per
//! op, keeps metadata with moved and copied files, and does all of it with io_uring and
//! with the thread pool (`GUNGNIR_NO_URING=1`). In a `test-hooks` build it also cancels
//! a slowed-down copy mid-way, cancels ops whose client hung up, and refuses ops on a
//! fake hung mount at once.

use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use gungnird::{
    md::{self, Client, MSG_MD_REPLY, ST_BAD_REQUEST, ST_OK, Value},
    ops::{
        self, Done, FLAG_ALL_METADATA, MSG_OP_CANCEL, MSG_OP_DONE, MSG_OP_PROGRESS, MSG_OP_START,
        OP_COPY, OP_DELETE, OP_DELETE_TREE, OP_FSYNC, OP_MOVE, OpError, OpKind, OpRequest,
        Progress,
    },
};

type R<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> R<Self> {
        let base = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build"))?
            .join("tmp");
        fs::create_dir_all(&base)?;
        let mode = fs::symlink_metadata(&base)?.permissions().mode();
        if mode & 0o022 != 0 {
            fs::set_permissions(&base, fs::Permissions::from_mode(mode & 0o7755))?;
        }
        let p = base.join(format!("fo-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
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

struct Daemon {
    child: Child,
    sock: PathBuf,
}

impl Daemon {
    /// gungnird with everything (socket, database, XDG dirs, HOME) inside `dir`.
    fn start(dir: &Dir, no_uring: bool, env: &[(&str, &Path)]) -> R<Self> {
        let sock = dir.join("gungnird.sock");
        let log = fs::File::create(dir.join(&format!("gungnird-{no_uring}.log")))?;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
        cmd.arg(dir.join("data/metadata.db"))
            .env("GUNGNIR_SOCKET", &sock)
            .env("HOME", &dir.0)
            .env("XDG_DATA_HOME", dir.join("data"))
            .env("XDG_RUNTIME_DIR", &dir.0)
            .env_remove(ops::NO_URING_ENV)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log);
        if no_uring {
            cmd.env(ops::NO_URING_ENV, "1");
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd.spawn()?;
        let mut d = Self { child, sock };
        let t0 = Instant::now();
        while UnixStream::connect(&d.sock).is_err() {
            if let Some(st) = d.child.try_wait()? {
                return Err(format!("gungnird exited early: {st}").into());
            }
            if t0.elapsed() > Duration::from_secs(10) {
                return Err("gungnird did not start listening".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(d)
    }

    fn client(&self) -> R<Client> {
        Ok(Client::connect(&self.sock, Duration::from_secs(5))?)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn b(p: &Path) -> Vec<u8> {
    p.as_os_str().as_bytes().to_vec()
}

fn req(kind: OpKind, flags: u32, src: &Path, dest: Option<&Path>) -> OpRequest {
    OpRequest {
        kind,
        flags,
        timeout_ms: 0,
        src: b(src),
        dest: dest.map(b).unwrap_or_default(),
    }
}

/// Send a start request; the reply (op id or status) must come before any event, with
/// no other op running on the connection.
fn start(c: &mut Client, r: &OpRequest) -> R<(u64, std::result::Result<u64, u32>)> {
    let mut others = Vec::new();
    let r = start_among(c, r, &mut others)?;
    assert!(others.is_empty(), "an event came before the start's reply");
    Ok(r)
}

/// An event of some other op: kind, seq, payload.
type Event = (u32, u64, Vec<u8>);

/// [`start`] while other ops run on the connection: their events (which may come before
/// this start's reply) are collected in `others`.
fn start_among(
    c: &mut Client,
    r: &OpRequest,
    others: &mut Vec<Event>,
) -> R<(u64, std::result::Result<u64, u32>)> {
    let seq = c.send(MSG_OP_START, &r.encode())?;
    let t0 = Instant::now();
    let m = loop {
        let left = Duration::from_secs(5)
            .checked_sub(t0.elapsed())
            .ok_or("no start reply in time")?;
        let m = c.recv(left)?;
        match m.kind {
            MSG_MD_REPLY if m.seq == seq => break m,
            MSG_OP_DONE | MSG_OP_PROGRESS => others.push((m.kind, m.seq, m.payload().to_vec())),
            k => {
                return Err(
                    format!("unexpected message {k} (seq {}) before the reply", m.seq).into(),
                );
            }
        }
    };
    let p = m.payload();
    let st = u32::from_le_bytes(p[..4].try_into()?);
    if st != ST_OK {
        assert_eq!(p.len(), 4);
        return Ok((seq, Err(st)));
    }
    Ok((seq, Ok(u64::from_le_bytes(p[4..12].try_into()?))))
}

/// Events until the op's done (which must carry the start's seq).
fn wait_done(c: &mut Client, seq: u64, id: u64, limit: Duration) -> R<(Done, Vec<Progress>)> {
    let t0 = Instant::now();
    let mut progress = Vec::new();
    loop {
        let left = limit
            .checked_sub(t0.elapsed())
            .ok_or("no done event in time")?;
        let m = c.recv(left)?;
        match m.kind {
            MSG_OP_PROGRESS => {
                let (pid, p) = ops::parse_progress(m.payload()).ok_or("bad progress")?;
                assert_eq!((m.seq, pid), (0, id));
                progress.push(p);
            }
            MSG_OP_DONE => {
                let d = ops::parse_done(m.payload()).ok_or("bad done")?;
                assert_eq!((m.seq, d.id), (seq, id));
                return Ok((d, progress));
            }
            md::MSG_MD_REPLY => {} // a cancel's reply
            k => return Err(format!("unexpected message kind {k}").into()),
        }
    }
}

fn run(c: &mut Client, r: &OpRequest) -> R<(Done, Vec<Progress>)> {
    let (seq, id) = start(c, r)?;
    let id = id.map_err(|st| format!("start refused with status {st}"))?;
    wait_done(c, seq, id, Duration::from_secs(60))
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

fn get(c: &mut Client, p: &Path, key: &str) -> R<Option<Value>> {
    let id = c.identify(p)?;
    Ok(c.get(&id, key)?)
}

#[test]
fn file_ops_over_the_real_socket_on_both_engines() -> R {
    for no_uring in [false, true] {
        let dir = Dir::new(if no_uring { "threads" } else { "uring" })?;
        let d = Daemon::start(&dir, no_uring, &[])?;
        let mut c = d.client()?;
        let tag = Value::String(format!("engine-{no_uring}"));

        // Copy with all metadata: data, mode and the gungnir metadata come along.
        let src = dir.join("src");
        let data = pattern(9 << 20);
        fs::write(&src, &data)?;
        fs::set_permissions(&src, fs::Permissions::from_mode(0o644))?;
        let sid = c.identify(&src)?;
        c.set(&sid, "tag", &tag)?;
        let copy = dir.join("copy");
        let (done, progress) = run(
            &mut c,
            &req(OpKind::Copy, FLAG_ALL_METADATA, &src, Some(&copy)),
        )?;
        assert_eq!(done.result, Ok(()), "no_uring={no_uring}");
        assert_eq!(done.progress.bytes_done, data.len() as u64);
        assert_eq!(fs::read(&copy)?, data);
        assert_eq!(fs::metadata(&copy)?.permissions().mode() & 0o777, 0o644);
        let last = progress.last().ok_or("no progress event")?;
        assert_eq!(
            (last.bytes_done, last.bytes_total),
            (data.len() as u64, data.len() as u64)
        );
        assert_eq!(
            get(&mut c, &copy, "tag")?,
            Some(tag.clone()),
            "metadata copied"
        );
        // Without ALL_METADATA, it stays behind.
        let plain = dir.join("plain");
        assert_eq!(
            run(&mut c, &req(OpKind::Copy, 0, &src, Some(&plain)))?
                .0
                .result,
            Ok(())
        );
        assert_eq!(get(&mut c, &plain, "tag")?, None);

        // Move into a subdirectory: same identity, metadata follows.
        fs::create_dir(dir.join("sub"))?;
        let moved = dir.join("sub/moved");
        assert_eq!(
            run(&mut c, &req(OpKind::Move, 0, &copy, Some(&moved)))?
                .0
                .result,
            Ok(())
        );
        assert!(!copy.exists());
        assert_eq!(get(&mut c, &moved, "tag")?, Some(tag.clone()));

        // Errors come back as errnos / statuses.
        let (done, _) = run(&mut c, &req(OpKind::Copy, 0, &src, Some(&moved)))?;
        assert_eq!(done.result, Err(OpError::Os(libc::EEXIST)));
        let (done, _) = run(&mut c, &req(OpKind::Copy, 0, &dir.0, Some(&dir.join("x"))))?;
        assert_eq!(done.result, Err(OpError::WouldRecurse));
        let mut bad = req(OpKind::Copy, 0, &src, None);
        bad.src = b"relative".to_vec();
        assert_eq!(start(&mut c, &bad)?.1, Err(ST_BAD_REQUEST));
        let r = c.raw_call(MSG_OP_START, &[99]);
        assert!(
            matches!(r, Err(md::ClientError::Status(md::MdError::BadRequest))),
            "{r:?}"
        );
        let r = c.raw_call(MSG_OP_CANCEL, &12345u64.to_le_bytes());
        assert!(
            matches!(r, Err(md::ClientError::Status(md::MdError::NotFound))),
            "{r:?}"
        );

        // fsync, delete (metadata rows go), delete-tree.
        assert_eq!(
            run(&mut c, &req(OpKind::Fsync, 0, &moved, None))?.0.result,
            Ok(())
        );
        let mid = c.identify(&moved)?;
        assert_eq!(
            run(&mut c, &req(OpKind::Delete, 0, &moved, None))?.0.result,
            Ok(())
        );
        assert!(!moved.exists());
        assert_eq!(
            c.get(&mid, "tag")?,
            None,
            "a deleted file's metadata is dropped"
        );
        for i in 0..20 {
            fs::create_dir_all(dir.join(&format!("tree/d{}", i % 4)))?;
            fs::write(dir.join(&format!("tree/d{}/f{i}", i % 4)), b"x")?;
        }
        let (done, _) = run(&mut c, &req(OpKind::DeleteTree, 0, &dir.join("tree"), None))?;
        assert_eq!(done.result, Ok(()));
        assert_eq!(done.progress.files_done, 20 + 4 + 1);
        assert!(!dir.join("tree").exists());
        // The op codes on the wire are the documented ones.
        assert_eq!(
            [OP_COPY, OP_MOVE, OP_DELETE, OP_DELETE_TREE, OP_FSYNC],
            [1, 2, 3, 4, 5]
        );
        drop(c);
        drop(d);
        let log = fs::read_to_string(dir.join(&format!("gungnird-{no_uring}.log")))?;
        let engine = if no_uring { "Threads" } else { "Uring" };
        let uring_ok = no_uring || ops::io::uring_for_tests_env("engine log check");
        if no_uring || uring_ok {
            assert!(log.contains(&format!("file ops engine: {engine}")), "{log}");
        }
    }
    Ok(())
}

#[test]
fn many_ops_on_one_connection_each_get_one_done() -> R {
    let dir = Dir::new("many")?;
    let d = Daemon::start(&dir, false, &[])?;
    let mut c = d.client()?;
    fs::write(dir.join("s"), pattern(1 << 20))?;
    let mut started = Vec::new();
    for i in 0..8 {
        let r = req(
            OpKind::Copy,
            0,
            &dir.join("s"),
            Some(&dir.join(&format!("c{i}"))),
        );
        let mut others = Vec::new();
        let (seq, id) = start_among(&mut c, &r, &mut others)?;
        // Events before this reply belong to ops started (and answered) earlier.
        for (kind, eseq, payload) in others {
            if kind == MSG_OP_DONE {
                let done = ops::parse_done(&payload).ok_or("bad done")?;
                let i = started
                    .iter()
                    .position(|(s, id)| *id == done.id && *s == eseq)
                    .ok_or("a done for an unknown or finished op")?;
                started.remove(i);
                assert_eq!(done.result, Ok(()));
            } else {
                let (pid, _) = ops::parse_progress(&payload).ok_or("bad progress")?;
                assert!(
                    started.iter().any(|(_, id)| *id == pid),
                    "progress of an unknown op"
                );
            }
        }
        started.push((seq, id.map_err(|st| format!("status {st}"))?));
    }
    let t0 = Instant::now();
    while !started.is_empty() {
        let m = c.recv(Duration::from_secs(30).saturating_sub(t0.elapsed()))?;
        if m.kind == MSG_OP_DONE {
            let done = ops::parse_done(m.payload()).ok_or("bad done")?;
            let i = started
                .iter()
                .position(|(seq, id)| *id == done.id && *seq == m.seq)
                .ok_or("a done for an unknown or finished op")?;
            started.remove(i);
            assert_eq!(done.result, Ok(()));
        }
    }
    for i in 0..8 {
        assert_eq!(fs::read(dir.join(&format!("c{i}")))?.len(), 1 << 20);
    }
    Ok(())
}

#[cfg(feature = "test-hooks")]
#[test]
fn cancel_disconnect_and_hung_mount_gate_over_the_socket() -> R {
    use gungnird::{
        health::{self, FAKE_HUNG_ENV},
        md::ST_SUSPECT_MOUNT,
    };
    for no_uring in [false, true] {
        let dir = Dir::new(if no_uring { "hk-threads" } else { "hk-uring" })?;
        let fake = dir.join("fake-hung");
        fs::create_dir(&fake)?;
        fs::write(fake.join("f"), b"x")?;
        let slow = Path::new("100");
        let d = Daemon::start(
            &dir,
            no_uring,
            &[(FAKE_HUNG_ENV, &fake), (ops::SLOW_OPS_ENV, slow)],
        )?;
        let mut c = d.client()?;
        let src = dir.join("big");
        fs::write(&src, pattern(32 << 20))?;

        // Cancel mid-copy: done Cancelled at once, nothing left at the destination.
        let dest = dir.join("dest");
        let (seq, id) = start(&mut c, &req(OpKind::Copy, 0, &src, Some(&dest)))?;
        let id = id.map_err(|st| format!("status {st}"))?;
        thread::sleep(Duration::from_millis(250));
        let t0 = Instant::now();
        let cseq = c.send(MSG_OP_CANCEL, &id.to_le_bytes())?;
        let (done, _) = wait_done(&mut c, seq, id, Duration::from_secs(5))?;
        assert_eq!(done.result, Err(OpError::Cancelled), "no_uring={no_uring}");
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "{:?}",
            t0.elapsed()
        );
        assert!(cseq > 0);
        thread::sleep(Duration::from_millis(100));
        assert!(!dest.exists());

        // The fake hung mount: once the monitor calls it hung (its first probe deadline
        // is 1 s), ops on it are refused at submission, within milliseconds.
        let mut q = vec![health::QUERY_BY_PATH];
        q.extend_from_slice(fake.as_os_str().as_bytes());
        let t0 = Instant::now();
        loop {
            let body = c.raw_call(health::MSG_HEALTH_QUERY, &q)?;
            if health::Health::from_code(body[8]) == Some(health::Health::Hung) {
                break;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "the fake mount never turned hung"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let t0 = Instant::now();
        let (_, r) = start(
            &mut c,
            &req(OpKind::Copy, 0, &fake.join("f"), Some(&dir.join("g"))),
        )?;
        assert_eq!(r, Err(ST_SUSPECT_MOUNT));
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "{:?}",
            t0.elapsed()
        );
        let (_, r) = start(&mut c, &req(OpKind::Copy, 0, &src, Some(&fake.join("g"))))?;
        assert_eq!(r, Err(ST_SUSPECT_MOUNT), "a destination there too");
        let t0 = Instant::now();
        let (_, r) = start(&mut c, &req(OpKind::DeleteTree, 0, &fake, None))?;
        assert_eq!(r, Err(ST_SUSPECT_MOUNT));
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "{:?}",
            t0.elapsed()
        );
        assert!(fake.join("f").exists());

        // A client that hangs up mid-copy: its op is cancelled (the temp file goes).
        let (_, id) = start(&mut c, &req(OpKind::Copy, 0, &src, Some(&dest)))?;
        assert!(id.is_ok());
        thread::sleep(Duration::from_millis(250));
        drop(c);
        let t0 = Instant::now();
        let leftovers = || -> R<bool> {
            Ok(fs::read_dir(&dir.0)?
                .filter_map(std::result::Result::ok)
                .any(|e| e.file_name().as_bytes().starts_with(b".gungnir-")))
        };
        while leftovers()? && t0.elapsed() < Duration::from_secs(3) {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !leftovers()?,
            "the abandoned copy was cancelled and cleaned up"
        );
        assert!(!dest.exists());
    }
    Ok(())
}
