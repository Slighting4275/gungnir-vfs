//! Integration tests over the real socket: start the built `gungnird` with its own socket
//! and database in a private directory under <repo>/.build/tmp (never /tmp), then talk
//! protocol v2 to it with `md::Client`.

use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};

use gungnird::{
    Error,
    ipc::{self, Frame, MSG_PING, MSG_PONG},
    md::{
        self, Client, ClientError, Ident, MAX_KEY_LEN, MAX_KEYS_PER_FILE, MSG_MD_GET, MSG_MD_REPLY,
        MSG_MD_SET, MdError, Request, Value,
    },
    store::{Store, StoreConfig},
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
        // CI checks out with umask 0000: nobody else may write next to our directories.
        let md = fs::symlink_metadata(&base)?;
        if !md.is_dir() {
            return Err("base is not a directory".into());
        }
        if md.permissions().mode() & 0o022 != 0 {
            fs::set_permissions(
                &base,
                fs::Permissions::from_mode(md.permissions().mode() & 0o7755),
            )?;
        }
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = base.join(format!("it-{name}-{}-{n}", std::process::id()));
        fs::create_dir(&p)?; // never adopt an existing directory
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        Ok(Self(p))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A running daemon, killed on drop.
struct Daemon {
    child: Child,
    sock: PathBuf,
    db: PathBuf,
    dir: Dir,
}

impl Daemon {
    fn start(name: &str) -> R<Self> {
        let dir = Dir::new(name)?;
        let sock = dir.0.join("gungnird.sock");
        let db = dir.0.join("data/metadata.db");
        let child = Command::new(env!("CARGO_BIN_EXE_gungnird"))
            .arg(&db)
            .env("GUNGNIR_SOCKET", &sock)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut d = Self {
            child,
            sock,
            db,
            dir,
        };
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

    fn file(&self, name: &str) -> R<PathBuf> {
        let p = self.dir.0.join(name);
        fs::write(&p, b"x")?;
        Ok(p)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn status<T: std::fmt::Debug>(r: md::ClientResult<T>) -> Option<MdError> {
    match r {
        Err(ClientError::Status(s)) => Some(s),
        _ => None,
    }
}

#[test]
fn set_get_list_unset_round_trip() -> R {
    let d = Daemon::start("rt")?;
    let mut c = d.client()?;
    let path = d.file("a.txt")?;
    let id = c.identify(&path)?;
    assert!(id.inode_num != 0 && !id.fs_uuid.is_empty());
    // The same file through another path (a hard link) has the same identity.
    let link = d.dir.0.join("hardlink");
    fs::hard_link(&path, &link)?;
    assert_eq!(c.identify(&link)?, id);

    assert_eq!(c.get(&id, "emblems")?, None);
    let s = Value::String("custom-icon \u{2603}".into());
    let v = Value::Stringv(vec!["emblem-a".into(), "emblem-b".into()]);
    c.set(&id, "custom-icon", &s)?;
    c.set(&id, "emblems", &v)?;
    assert_eq!(c.get(&id, "custom-icon")?, Some(s));
    assert_eq!(c.get(&id, "emblems")?, Some(v));
    assert_eq!(
        c.list(&id)?,
        vec!["custom-icon".to_string(), "emblems".to_string()]
    );

    // Another connection sees the same data.
    let mut c2 = d.client()?;
    assert_eq!(c2.list(&id)?.len(), 2);

    // The last identified path is the hint (the hard link was identified last).
    let store = Store::open(&d.db, StoreConfig::default())?;
    let hint = store.path_hint(&id)?;
    assert_eq!(hint.as_deref(), Some(link.as_os_str().as_encoded_bytes()));

    c.unset(&id, "custom-icon")?;
    assert_eq!(c.get(&id, "custom-icon")?, None);
    assert_eq!(c.list(&id)?, vec!["emblems".to_string()]);
    Ok(())
}

#[test]
fn list_paginates_over_the_wire() -> R {
    let d = Daemon::start("page")?;
    let mut c = d.client()?;
    let id = c.identify(&d.file("many")?)?;
    let v = Value::String("v".into());
    let mut want = Vec::new();
    for i in 0..MAX_KEYS_PER_FILE {
        // Long keys: the full list needs several reply slots.
        let k = format!("{i:04}{}", "k".repeat(MAX_KEY_LEN - 4));
        c.set(&id, &k, &v)?;
        want.push(k);
    }
    assert_eq!(
        status(c.set(&id, "overflow", &v)),
        Some(MdError::TooManyKeys)
    );
    assert_eq!(c.list(&id)?, want);
    Ok(())
}

#[test]
fn bad_requests_get_clean_errors() -> R {
    let d = Daemon::start("bad")?;
    let mut c = d.client()?;
    let missing = d.dir.0.join("does-not-exist");
    assert_eq!(status(c.identify(&missing)), Some(MdError::NoSuchFile));
    assert_eq!(
        status(c.raw_call(md::MSG_MD_IDENTIFY, b"relative/path")),
        Some(MdError::BadRequest)
    );
    assert_eq!(status(c.raw_call(999, b"")), Some(MdError::Unsupported));
    let id = c.identify(&d.file("f")?)?;

    let raw = |key: &[u8], value: &[u8]| -> R<Vec<u8>> {
        let mut p = Vec::new();
        md::put_ident(&mut p, &id)?;
        p.extend_from_slice(&u16::try_from(key.len())?.to_le_bytes());
        p.extend_from_slice(key);
        p.extend_from_slice(value);
        Ok(p)
    };
    let good_value = [1u8, 1, 0, b'v'];
    let long_key = vec![b'k'; MAX_KEY_LEN + 1];
    assert_eq!(
        status(c.raw_call(MSG_MD_SET, &raw(&long_key, &good_value)?)),
        Some(MdError::KeyTooLong)
    );
    assert_eq!(
        status(c.raw_call(MSG_MD_SET, &raw(&[0xff, 0xfe], &good_value)?)),
        Some(MdError::BadUtf8)
    );
    assert_eq!(
        status(c.raw_call(MSG_MD_SET, &raw(b"k", &[1, 2, 0, 0xc3, 0x28])?)),
        Some(MdError::BadUtf8)
    );
    let mut big = vec![1u8];
    big.extend_from_slice(&3500u16.to_le_bytes());
    big.extend(std::iter::repeat_n(b'v', 3500));
    assert_eq!(
        status(c.raw_call(MSG_MD_SET, &raw(b"k", &big)?)),
        Some(MdError::ValueTooLarge)
    );
    assert_eq!(
        status(c.raw_call(MSG_MD_GET, &raw(b"k", b"trailing")?)),
        Some(MdError::BadRequest)
    );
    // The client library refuses the same before sending.
    let req = Request::Set(id.clone(), "k".into(), Value::String("v".repeat(4000)));
    assert_eq!(req.encode().err(), Some(MdError::ValueTooLarge));
    // The connection is still healthy.
    c.set(&id, "k", &Value::String("ok".into()))?;
    Ok(())
}

#[test]
fn version_mismatch_is_refused_cleanly() -> R {
    let d = Daemon::start("ver")?;
    let mut s = UnixStream::connect(&d.sock)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut hello = Frame::hello();
    hello.version = 1; // a protocol-v1 client (milestone 3)
    s.write_all(&hello.encode())?;
    let (reply, fd) = ipc::recv_with_fd(&s)?;
    assert_eq!(
        (reply.kind, reply.status, reply.version),
        (ipc::KIND_REJECT, ipc::STATUS_BAD_VERSION, ipc::VERSION)
    );
    assert!(fd.is_none());
    // The daemon is fine afterwards.
    let mut c = d.client()?;
    c.identify(&d.file("after")?)?;
    Ok(())
}

/// While another process holds the database's write lock, writes answer Busy within a
/// bounded time, reads keep working, and the ring thread keeps answering pings at once
/// (it never waits for SQLite).
#[test]
fn locked_database_answers_busy_and_ring_stays_live() -> R {
    let d = Daemon::start("busy")?;
    let mut c = d.client()?;
    let id: Ident = c.identify(&d.file("f")?)?;
    c.set(&id, "before", &Value::String("v".into()))?;

    let other = rusqlite::Connection::open(&d.db)?;
    other.execute_batch("BEGIN IMMEDIATE; DELETE FROM path_hint WHERE 0;")?;

    let (kind, payload) =
        Request::Set(id.clone(), "k".into(), Value::String("v".into())).encode()?;
    let t0 = Instant::now();
    let set_seq = c.send(kind, &payload)?;
    let ping_seq = c.send(MSG_PING, b"live")?;
    let mut pong_at = None;
    let mut set_reply = None;
    while pong_at.is_none() || set_reply.is_none() {
        let m = c.recv(Duration::from_secs(5))?;
        if m.kind == MSG_PONG && m.seq == ping_seq {
            pong_at = Some(t0.elapsed());
        } else if m.kind == MSG_MD_REPLY && m.seq == set_seq {
            set_reply = Some((md::reply_result(m.payload()), t0.elapsed()));
        }
    }
    let (r, set_took) = set_reply.ok_or("no set reply")?;
    let pong_at = pong_at.ok_or("no pong")?;
    assert_eq!(status(r), Some(MdError::Busy));
    assert!(
        set_took < Duration::from_millis(1000),
        "busy took {set_took:?}"
    );
    assert!(
        pong_at <= set_took,
        "the ping waited for SQLite ({pong_at:?} vs {set_took:?})"
    );
    // Reads are not blocked by a writer in WAL mode.
    assert_eq!(c.get(&id, "before")?, Some(Value::String("v".into())));

    other.execute_batch("ROLLBACK")?;
    c.set(&id, "k", &Value::String("v".into()))?;
    Ok(())
}

/// Many requests in flight at once (more than the in-flight cap): every one is answered,
/// none lost, in any order.
#[test]
fn pipelined_requests_are_all_answered() -> R {
    let d = Daemon::start("pipe")?;
    let mut c = d.client()?;
    let id = c.identify(&d.file("f")?)?;
    let mut pending = std::collections::HashSet::new();
    let mut answered = 0;
    let total = 300u32;
    let mut sent = 0u32;
    let t0 = Instant::now();
    while answered < total {
        // Keep the request ring well fed but never overfull.
        while sent < total && pending.len() < 24 {
            let (kind, payload) = Request::Set(
                id.clone(),
                format!("k{}", sent % 100),
                Value::String(format!("{sent}")),
            )
            .encode()?;
            match c.send(kind, &payload) {
                Ok(seq) => {
                    pending.insert(seq);
                    sent += 1;
                }
                Err(Error::RingFull) => break,
                Err(e) => return Err(e.into()),
            }
        }
        let m = c.recv(Duration::from_secs(5))?;
        assert_eq!(m.kind, MSG_MD_REPLY);
        assert!(pending.remove(&m.seq), "unexpected seq {}", m.seq);
        md::reply_result(m.payload())?;
        answered += 1;
    }
    assert!(t0.elapsed() < Duration::from_secs(30));
    assert_eq!(c.list(&id)?.len(), 100);
    Ok(())
}

/// Stale rows are dropped by identify (which sees the file's current btime), never on
/// the btime a client sends: a client holding an outdated identity cannot wipe the
/// current file's metadata by reading it.
#[test]
fn only_identify_drops_stale_rows() -> R {
    let d = Daemon::start("stale")?;
    let mut c = d.client()?;
    let path = d.file("f")?;
    let id = c.identify(&path)?;
    if (id.btime_sec, id.btime_nsec) == (0, 0) {
        // No btime on this filesystem: the whole test runs on a tmpfs instead.
        drop(c);
        drop(d);
        gungnird::testenv::rerun_on_tmpfs(
            "only_identify_drops_stale_rows",
            &gungnird::testenv::scratch_base(),
            "file creation time (btime)",
        )?;
        return Ok(());
    }
    let keep = Value::String("keep".into());
    c.set(&id, "k", &keep)?;
    let mut outdated = id.clone();
    outdated.btime_sec -= 100;
    assert_eq!(c.get(&outdated, "k")?, None);
    assert_eq!(
        status(c.set(&outdated, "k", &keep)),
        Some(MdError::NoSuchFile)
    );
    assert_eq!(
        c.get(&id, "k")?,
        Some(keep.clone()),
        "a read with an old identity deleted data"
    );

    // Rows written under another btime (an earlier file on this inode) go at identify.
    let mut earlier = id.clone();
    c.unset(&id, "k")?;
    earlier.btime_sec -= 50;
    c.set(&earlier, "old", &keep)?;
    assert_eq!(c.identify(&path)?, id);
    assert_eq!(c.list(&id)?, Vec::<String>::new());
    assert_eq!(
        c.get(&earlier, "old")?,
        None,
        "identify dropped the earlier file's rows"
    );
    Ok(())
}

/// Milestone 6: GIO reports renames and deletes after the fact (`local_file_moved`,
/// `local_file_removed`); metadata stays keyed by identity, the hints follow.
#[test]
fn moved_and_removed_over_the_wire() -> R {
    let d = Daemon::start("mv")?;
    let mut c = d.client()?;
    let src = d.file("before")?;
    let id = c.identify(&src)?;
    let s = Value::String("spear".into());
    c.set(&id, "k", &s)?;

    let dest = d.dir.0.join("after");
    fs::rename(&src, &dest)?;
    assert_eq!(c.moved(&src, &dest)?, (1, 0));
    assert_eq!(c.identify(&dest)?, id, "a rename keeps the identity");
    assert_eq!(c.get(&id, "k")?, Some(s));
    let store = Store::open(&d.db, StoreConfig::default())?;
    assert_eq!(
        store.path_hint(&id)?.as_deref(),
        Some(dest.as_os_str().as_encoded_bytes())
    );

    // A rename whose destination is gone by now: a clean error, nothing changes.
    let gone = d.dir.0.join("gone");
    assert_eq!(status(c.moved(&dest, &gone)), Some(MdError::NoSuchFile));

    // Delete reported while the file still exists (not really deleted): kept.
    assert_eq!(c.removed(&dest)?, 0);
    assert!(c.get(&id, "k")?.is_some());
    fs::remove_file(&dest)?;
    assert_eq!(c.removed(&dest)?, 1);
    assert_eq!(c.get(&id, "k")?, None);
    assert_eq!(store.path_hint(&id)?, None);
    // Malformed: relative path, same source and destination.
    assert_eq!(
        status(c.raw_call(md::MSG_MD_REMOVED, b"relative")),
        Some(MdError::BadRequest)
    );
    let mut p = Vec::new();
    for _ in 0..2 {
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(b"/x");
    }
    assert_eq!(
        status(c.raw_call(md::MSG_MD_MOVED, &p)),
        Some(MdError::BadRequest)
    );
    Ok(())
}

/// Review: the key is the inode. Deleting one of two hard links through GIO must keep the
/// metadata that the other link still shows (the remove used to go by path only).
#[test]
fn deleting_one_hard_link_keeps_the_metadata_of_the_other() -> R {
    let d = Daemon::start("hardlink")?;
    let mut c = d.client()?;
    let a = d.file("a")?;
    let b = d.dir.0.join("b");
    fs::hard_link(&a, &b)?;
    let id = c.identify(&a)?;
    let s = Value::String("spear".into());
    c.set(&id, "k", &s)?;
    fs::remove_file(&a)?;
    assert_eq!(c.removed(&a)?, 0);
    assert_eq!(c.identify(&b)?, id, "the other link is the same file");
    assert_eq!(
        c.get(&id, "k")?,
        Some(s),
        "metadata of a live file was dropped"
    );
    // The last link: gone with it (set again through b, which has one link now).
    c.set(&id, "k", &Value::String("again".into()))?;
    fs::remove_file(&b)?;
    assert_eq!(c.removed(&b)?, 1);
    assert_eq!(c.get(&id, "k")?, None);
    Ok(())
}
