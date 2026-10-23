//! Milestone 7 over the real socket: the built `gungnird` answers health queries and
//! pushes snapshots to subscribers, and the fake-hung-mount test hook only works in a
//! `test-hooks` build (cargo's own builds have it off; the Zig itest turns it on).

use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use gungnird::{
    health::{
        self, EV_FIRST, EV_LAST, FAKE_HUNG_ENV, Health, MSG_HEALTH_EVENT, MSG_HEALTH_QUERY,
        MSG_HEALTH_SUBSCRIBE, QUERY_BY_ID, QUERY_BY_PATH,
    },
    md::{self, Client, ClientError, MdError},
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
        let p = base.join(format!("mh-{name}-{}", std::process::id()));
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

struct Daemon {
    child: Child,
    sock: PathBuf,
}

impl Daemon {
    fn start(dir: &Dir, fake_hung: &Path) -> R<Self> {
        let sock = dir.0.join("gungnird.sock");
        let log = fs::File::create(dir.0.join("gungnird.log"))?;
        let child = Command::new(env!("CARGO_BIN_EXE_gungnird"))
            .arg(dir.0.join("data/metadata.db"))
            .env("GUNGNIR_SOCKET", &sock)
            .env(FAKE_HUNG_ENV, fake_hung)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()?;
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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn query(c: &mut Client, by: u8, arg: &[u8]) -> md::ClientResult<(u64, Health, Vec<u8>)> {
    let mut p = vec![by];
    p.extend_from_slice(arg);
    let b = c.raw_call(MSG_HEALTH_QUERY, &p)?;
    let mut r = md::Reader(&b);
    let id = r.u64()?;
    let st = Health::from_code(r.u8()?).ok_or(MdError::BadRequest)?;
    let probed = r.u8()?;
    assert!(probed <= 1);
    let _latency_us = r.u32()?;
    let mp = r.blob16()?.to_vec();
    r.end()?;
    Ok((id, st, mp))
}

#[test]
fn health_queries_and_events_over_the_real_socket() -> R {
    let dir = Dir::new("q")?;
    let fake = dir.0.join("fake-hung");
    fs::create_dir(&fake)?;
    fs::write(fake.join("f"), b"x")?;
    let d = Daemon::start(&dir, &fake)?;
    let mut c = Client::connect(&d.sock, Duration::from_secs(5))?;

    // "/" is a real, local mount: healthy, never probed.
    let (root_id, st, mp) = query(&mut c, QUERY_BY_PATH, b"/")?;
    assert_eq!((st, mp.as_slice()), (Health::Healthy, &b"/"[..]));
    let (id, st, _) = query(&mut c, QUERY_BY_ID, &root_id.to_le_bytes())?;
    assert_eq!((id, st), (root_id, Health::Healthy));
    match query(&mut c, QUERY_BY_ID, &u64::MAX.to_le_bytes()) {
        Err(ClientError::Status(MdError::NotFound)) => {}
        other => return Err(format!("unknown mount id: {other:?}").into()),
    }

    // Subscribe: the reply, then a snapshot.
    let epoch = c.raw_call(MSG_HEALTH_SUBSCRIBE, &[])?;
    assert_eq!(epoch.len(), 8);
    let t0 = Instant::now();
    let snap = loop {
        let m = c.recv(Duration::from_secs(3))?;
        if m.kind == MSG_HEALTH_EVENT {
            break health::decode_event(m.payload()).map_err(|()| "bad event")?;
        }
        assert!(t0.elapsed() < Duration::from_secs(3));
    };
    assert!(snap.1 & EV_FIRST != 0 && snap.1 & EV_LAST != 0);

    let f = fake.join("f");
    if cfg!(feature = "test-hooks") {
        // The fake mount turns hung after the 1 s probe deadline.
        let t0 = Instant::now();
        loop {
            let (_, st, mp) = query(&mut c, QUERY_BY_PATH, f.as_os_str().as_bytes())?;
            if st == Health::Hung {
                assert_eq!(mp, fake.as_os_str().as_bytes());
                break;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "fake mount never hung"
            );
            thread::sleep(Duration::from_millis(50));
        }
        let t0 = Instant::now();
        match c.identify(&f) {
            Err(ClientError::Status(MdError::SuspectMount)) => {}
            other => return Err(format!("identify on a hung mount: {other:?}").into()),
        }
        assert!(t0.elapsed() < Duration::from_millis(100));
    } else {
        // Without the feature the variable is ignored (and says so).
        thread::sleep(Duration::from_millis(1300));
        let (_, st, mp) = query(&mut c, QUERY_BY_PATH, f.as_os_str().as_bytes())?;
        assert_eq!(st, Health::Healthy);
        assert_ne!(mp, fake.as_os_str().as_bytes());
        assert!(c.identify(&f).is_ok());
        let log = fs::read_to_string(dir.0.join("gungnird.log"))?;
        assert!(log.contains("ignored"), "log: {log}");
    }
    drop(c);
    drop(d);
    Ok(())
}
