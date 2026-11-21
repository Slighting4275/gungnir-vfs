//! Milestone 7 over the real socket: the built `gungnird` answers health queries and
//! pushes snapshots to subscribers, and the fake-hung-mount test hook only works in a
//! `test-hooks` build (cargo's own builds have it off; the Zig itest turns it on).

use std::{
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
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

mod common;
use common::{Dir, R, Reaped};

struct Daemon {
    /// Held for its drop: the daemon is killed with this.
    #[allow(dead_code)]
    child: Reaped,
    sock: PathBuf,
}

impl Daemon {
    fn start(dir: &Dir, fake_hung: &Path) -> R<Self> {
        let sock = dir.join("gungnird.sock");
        let mut cmd = common::gungnird(dir)?;
        cmd.arg(dir.join("data/metadata.db"))
            .env("GUNGNIR_SOCKET", &sock)
            .env(FAKE_HUNG_ENV, fake_hung);
        let mut child = Reaped(cmd.spawn()?);
        drop(common::ready(
            &mut child,
            &sock,
            &dir.join("log"),
            Duration::from_secs(10),
        )?);
        Ok(Self { child, sock })
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
        let log = fs::read_to_string(dir.join("log"))?;
        // This hook's own warning: other hook variables the fixture sets say "ignored" too.
        assert!(
            log.contains(&format!("{FAKE_HUNG_ENV} ignored")),
            "log: {log}"
        );
    }
    drop(c);
    drop(d);
    Ok(())
}
