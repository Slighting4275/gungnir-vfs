use std::{
    ffi::OsStr,
    sync::{Arc, Mutex, mpsc},
};

use super::*;
use crate::{md::Value, testdir::TestDir};

/// A store in its own private directory under <repo>/.build/tmp, removed on drop.
struct TestStore {
    path: PathBuf,
    dir: TestDir,
}

impl TestStore {
    fn new(name: &str) -> Result<Self> {
        let dir = TestDir::new(&format!("db-{name}"))?;
        Ok(Self {
            path: dir.join("gungnir/metadata.db"),
            dir,
        })
    }

    fn open(&self) -> Result<Store> {
        Store::open(&self.path, StoreConfig::default())
    }
}

fn id(inode: u64) -> Ident {
    Ident {
        fs_uuid: "0123abcd-0000-4000-8000-00000000beef".into(),
        subvol_id: 256,
        inode_num: inode,
        generation: 3,
        btime_sec: 1_700_000_000,
        btime_nsec: 5,
    }
}

fn enc(v: &Value) -> Vec<u8> {
    v.encode().unwrap_or_default()
}

#[test]
fn round_trip_string_stringv_unset_and_hint() -> Result<()> {
    let t = TestStore::new("rt")?;
    let mut s = t.open()?;
    let a = id(u64::MAX); // high bit set: stored as a negative i64, read back intact
    let sv = Value::String("emblem-\u{e9}".into());
    let vv = Value::Stringv(vec!["one".into(), String::new(), "three".into()]);
    assert_eq!(s.get(&a, "k")?, None);
    s.set(&a, "k", &enc(&sv), Some(b"/some/where"))?;
    s.set(&a, "v", &enc(&vv), None)?;
    assert_eq!(s.get(&a, "k")?.map(|b| Value::decode(&b)), Some(Ok(sv)));
    assert_eq!(s.get(&a, "v")?.map(|b| Value::decode(&b)), Some(Ok(vv)));
    // Another file (other inode) sees nothing.
    assert_eq!(s.get(&id(1), "k")?, None);
    assert_eq!(s.path_hint(&a)?, Some(b"/some/where".to_vec()));
    // Overwrite.
    let n = Value::String("new".into());
    s.set(&a, "k", &enc(&n), Some(b"/moved/here"))?;
    assert_eq!(s.get(&a, "k")?.map(|b| Value::decode(&b)), Some(Ok(n)));
    assert_eq!(s.path_hint(&a)?, Some(b"/moved/here".to_vec()));
    assert_eq!(s.list(&a, "", 100)?, (vec!["k".into(), "v".into()], false));
    s.unset(&a, "k")?;
    s.unset(&a, "k")?; // idempotent
    assert_eq!(s.get(&a, "k")?, None);
    assert!(s.path_hint(&a)?.is_some());
    s.unset(&a, "v")?;
    assert_eq!(s.path_hint(&a)?, None, "the hint goes with the last key");
    // Survives a reopen.
    s.set(&a, "p", &enc(&Value::String("x".into())), None)?;
    drop(s);
    let mut s = t.open()?;
    assert!(s.get(&a, "p")?.is_some());
    Ok(())
}

#[test]
fn list_is_ordered_and_paginates() -> Result<()> {
    let t = TestStore::new("list")?;
    let mut s = t.open()?;
    let a = id(7);
    for k in ["b", "a", "\u{e9}", "c", "aa"] {
        s.set(&a, k, &enc(&Value::String(k.into())), None)?;
    }
    let (p1, more) = s.list(&a, "", 2)?;
    assert_eq!((p1.clone(), more), (vec!["a".into(), "aa".into()], true));
    let (p2, more) = s.list(&a, &p1[1], 2)?;
    assert_eq!((p2.clone(), more), (vec!["b".into(), "c".into()], true));
    let (p3, more) = s.list(&a, &p2[1], 2)?;
    assert_eq!((p3, more), (vec!["\u{e9}".into()], false));
    Ok(())
}

#[test]
fn key_count_limit() -> Result<()> {
    let t = TestStore::new("limit")?;
    let mut s = t.open()?;
    let a = id(9);
    let v = enc(&Value::String("v".into()));
    for i in 0..MAX_KEYS_PER_FILE {
        s.set(&a, &format!("k{i:04}"), &v, None)?;
    }
    assert_eq!(
        s.set(&a, "one-too-many", &v, None),
        Err(MdError::TooManyKeys)
    );
    // Overwriting an existing key at the limit is fine; another file is not affected.
    s.set(&a, "k0000", &v, None)?;
    s.set(&id(10), "k", &v, None)?;
    s.unset(&a, "k0001")?;
    s.set(&a, "now-it-fits", &v, None)?;
    Ok(())
}

#[test]
fn recycled_inode_is_detected_by_btime() -> Result<()> {
    let t = TestStore::new("stale")?;
    let mut s = t.open()?;
    let old = id(42);
    s.set(&old, "k", &enc(&Value::String("old".into())), Some(b"/old"))?;
    let mut new = old.clone();
    new.btime_sec += 10;
    // Requests only see that the btime differs; they never delete.
    assert_eq!(s.get(&new, "k")?, None, "a new file on a recycled inode");
    assert_eq!(s.list(&new, "", 10)?.0, Vec::<String>::new());
    let v = enc(&Value::String("new".into()));
    assert_eq!(s.set(&new, "k", &v, None), Err(MdError::NoSuchFile));
    // identify saw the new btime: the earlier file's rows go.
    assert!(s.purge_stale(&new)?);
    assert_eq!(s.get(&old, "k")?, None, "the stale rows are gone");
    assert_eq!(s.path_hint(&old)?, None);
    s.set(&new, "k", &v, None)?;
    assert_eq!(s.get(&new, "k")?, Some(v));
    assert!(!s.purge_stale(&new)?, "nothing stale any more");
    // An unknown btime (0) on either side never counts as stale.
    s.set(&new, "k", &enc(&Value::String("x".into())), None)?;
    let mut unknown = new.clone();
    unknown.btime_sec = 0;
    unknown.btime_nsec = 0;
    assert!(s.get(&unknown, "k")?.is_some());
    s.set(&unknown, "z", &enc(&Value::String("z".into())), None)?;
    assert!(s.get(&new, "z")?.is_some());
    Ok(())
}

/// A client still holding the identity of a deleted file (its inode now reused by a new
/// file with another btime) must not be able to wipe the new file's metadata by asking
/// for it: only identify, which sees the file, decides that rows are stale.
#[test]
fn a_stale_client_identity_never_deletes_current_rows() -> Result<()> {
    let t = TestStore::new("staleclient")?;
    let mut s = t.open()?;
    let current = id(7);
    let mut stale = current.clone();
    stale.btime_sec -= 100;
    let v = enc(&Value::String("keep".into()));
    s.set(&current, "k", &v, Some(b"/now"))?;
    assert_eq!(s.get(&stale, "k")?, None);
    assert_eq!(s.list(&stale, "", 10)?.0, Vec::<String>::new());
    assert_eq!(s.set(&stale, "k", &v, None), Err(MdError::NoSuchFile));
    assert_eq!(s.unset(&stale, "k"), Err(MdError::NoSuchFile));
    assert_eq!(
        s.get(&current, "k")?,
        Some(v),
        "the current file kept its metadata"
    );
    assert_eq!(s.path_hint(&current)?, Some(b"/now".to_vec()));
    Ok(())
}

#[test]
fn files_are_private_and_wal_is_on() -> Result<()> {
    let t = TestStore::new("wal")?;
    let mut s = t.open()?;
    s.set(&id(1), "k", &enc(&Value::String("v".into())), None)?;
    let mode: String = s.conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    assert_eq!(mode, "wal");
    let sql: String = s.conn.query_row(
        "SELECT sql FROM sqlite_master WHERE name = 'metadata'",
        [],
        |r| r.get(0),
    )?;
    assert!(sql.contains("WITHOUT ROWID"));
    let dir = t.path.parent().ok_or(Error::NoHome)?;
    assert_eq!(fs::symlink_metadata(dir)?.mode() & 0o7777, 0o700);
    for ext in ["", "-wal", "-shm"] {
        let mut p = t.path.clone().into_os_string();
        p.push(ext);
        let md = fs::symlink_metadata(&p)?;
        assert_eq!(md.mode() & 0o7777, 0o600, "{ext}");
    }
    Ok(())
}

#[test]
fn an_existing_database_is_made_private() -> Result<()> {
    let t = TestStore::new("tighten")?;
    let dir = t.path.parent().ok_or(Error::NoHome)?;
    fs::DirBuilder::new().mode(0o700).create(dir)?;
    fs::write(&t.path, b"")?;
    fs::set_permissions(&t.path, fs::Permissions::from_mode(0o644))?;
    drop(t.open()?);
    assert_eq!(fs::symlink_metadata(&t.path)?.mode() & 0o777, 0o600);
    Ok(())
}

#[test]
fn insecure_directory_is_refused() -> Result<()> {
    let t = TestStore::new("insecure")?;
    let dir = t.dir.join("open");
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777))?;
    let r = Store::open(&dir.join("metadata.db"), StoreConfig::default());
    assert!(matches!(r, Err(Error::InsecureDbDir(_))));
    assert!(fs::read_dir(&dir)?.next().is_none(), "nothing was created");
    Ok(())
}

#[test]
fn non_wal_database_is_rejected() {
    let err = open_db(Path::new(":memory:"), Duration::ZERO).err();
    assert!(matches!(err, Some(Error::WalUnavailable(ref m)) if m == "memory"));
}

#[test]
fn default_path_precedence() -> Result<()> {
    let s = |v: &'static str| Some(OsStr::new(v));
    assert_eq!(
        default_db_path(s("/x/data"), s("/h"))?,
        PathBuf::from("/x/data/gungnir/metadata.db")
    );
    assert_eq!(
        default_db_path(s("relative"), s("/h"))?,
        PathBuf::from("/h/.local/share/gungnir/metadata.db")
    );
    assert!(matches!(default_db_path(None, s("")), Err(Error::NoHome)));
    Ok(())
}

/// Another connection holds the write lock: writes answer Busy within the bounded retry
/// (never SQLite's old 5 s), WAL readers keep working, and the store recovers.
#[test]
fn locked_database_answers_busy_quickly() -> Result<()> {
    let t = TestStore::new("busy")?;
    let mut s = t.open()?;
    let a = id(5);
    let v = enc(&Value::String("v".into()));
    s.set(&a, "before", &v, None)?;
    let other = Connection::open(&t.path)?;
    other
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO path_hint VALUES ('x', 0, 0, 0, x'00', 0);")?;
    let t0 = Instant::now();
    assert_eq!(s.set(&a, "k", &v, None), Err(MdError::Busy));
    assert_eq!(s.unset(&a, "before"), Err(MdError::Busy));
    let took = t0.elapsed();
    assert!(took < Duration::from_millis(500), "busy took {took:?}");
    // Readers are not blocked by a writer in WAL mode.
    assert!(s.get(&a, "before")?.is_some());
    assert_eq!(s.list(&a, "", 10)?.0, vec!["before".to_string()]);
    other.execute_batch("ROLLBACK")?;
    s.set(&a, "k", &v, None)?;
    Ok(())
}

/// Several threads hammer the same file through their own stores (as two daemons on one
/// DB would): every call either succeeds or answers Busy, none errors or hangs.
#[test]
fn concurrent_writers_get_busy_not_errors() -> Result<()> {
    let t = TestStore::new("conc")?;
    drop(t.open()?);
    let path = t.path.clone();
    let outcomes = Arc::new(Mutex::new((0u32, 0u32)));
    std::thread::scope(|sc| {
        for w in 0..4u64 {
            let path = path.clone();
            let outcomes = Arc::clone(&outcomes);
            sc.spawn(move || -> Result<()> {
                let mut s = Store::open(&path, StoreConfig::default())?;
                for i in 0..50 {
                    let v = enc(&Value::String(format!("{w}-{i}")));
                    let r = s.set(&id(w), &format!("k{i}"), &v, None);
                    let mut o = outcomes
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    match r {
                        Ok(()) => o.0 += 1,
                        Err(MdError::Busy) => o.1 += 1,
                        Err(e) => panic!("unexpected {e}"),
                    }
                }
                Ok(())
            });
        }
    });
    let (ok, busy) = *outcomes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(ok + busy, 200);
    assert!(ok > 0);
    Ok(())
}

#[test]
fn db_thread_runs_jobs_and_sheds_load() -> Result<()> {
    let t = TestStore::new("thread")?;
    let h = spawn(t.open()?, DbConfig::default())?;
    let (tx, rx) = mpsc::channel();
    let a = id(3);
    let reqs = [
        DbReq::Set(
            a.clone(),
            "k".into(),
            enc(&Value::String("v".into())),
            Some(b"/p".to_vec()),
        ),
        DbReq::Get(a.clone(), "k".into()),
        DbReq::List(a.clone(), String::new()),
        DbReq::Unset(a.clone(), "k".into()),
        DbReq::Get(a.clone(), "k".into()),
    ];
    for (n, req) in reqs.into_iter().enumerate() {
        let tx = tx.clone();
        let job = Job {
            req,
            enqueued: Instant::now(),
            done: Box::new(move |r| {
                let _ = tx.send((n, r));
            }),
        };
        h.submit(job).map_err(|_| Error::Protocol("queue full"))?;
    }
    let mut got: Vec<(usize, DbResult)> = (0..5)
        .map(|_| rx.recv_timeout(Duration::from_secs(5)))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::Protocol("db thread did not answer"))?;
    got.sort_by_key(|g| g.0);
    assert_eq!(got[0].1, Ok(Vec::new()));
    assert_eq!(got[1].1, Ok(enc(&Value::String("v".into()))));
    assert_eq!(got[2].1, Ok(list_body(&["k".to_string()], false)));
    assert_eq!(got[3].1, Ok(Vec::new()));
    assert_eq!(got[4].1, Err(MdError::NotFound));

    // A job that waited longer than max_age is answered Busy without running.
    let (tx2, rx2) = mpsc::channel();
    let stale = Job {
        req: DbReq::Set(
            a.clone(),
            "late".into(),
            enc(&Value::String("v".into())),
            None,
        ),
        enqueued: Instant::now() - Duration::from_secs(10),
        done: Box::new(move |r| {
            let _ = tx2.send(r);
        }),
    };
    h.submit(stale).map_err(|_| Error::Protocol("queue full"))?;
    assert_eq!(
        rx2.recv_timeout(Duration::from_secs(5)).ok(),
        Some(Err(MdError::Busy))
    );
    Ok(())
}

#[test]
fn full_queue_answers_busy_without_waiting() -> Result<()> {
    let t = TestStore::new("queue")?;
    let store = t.open()?;
    // Hold the store's DB thread inside a job until released.
    let h = spawn(
        store,
        DbConfig {
            queue: 1,
            max_age: Duration::from_secs(60),
        },
    )?;
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let blocker = Job {
        req: DbReq::Get(id(1), "k".into()),
        enqueued: Instant::now(),
        done: Box::new(move |_| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        }),
    };
    h.submit(blocker)
        .map_err(|_| Error::Protocol("queue full"))?;
    started_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| Error::Protocol("blocker never ran"))?;
    let mk = || Job {
        req: DbReq::Get(id(1), "k".into()),
        enqueued: Instant::now(),
        done: Box::new(|_| {}),
    };
    h.submit(mk())
        .map_err(|_| Error::Protocol("first queued job refused"))?;
    let t0 = Instant::now();
    assert_eq!(h.submit(mk()), Err(MdError::Busy));
    assert!(t0.elapsed() < Duration::from_millis(50));
    let _ = release_tx.send(());
    Ok(())
}

#[test]
fn foreign_rows_never_reach_the_client_unvalidated() -> Result<()> {
    let t = TestStore::new("foreign")?;
    let mut s = t.open()?;
    let a = id(11);
    s.set(&a, "good", &enc(&Value::String("v".into())), None)?;
    // Rows written behind the daemon's back: an oversized blob and an oversized key.
    let (u, sv, i, g) = Store::id_params(&a);
    s.conn.execute(
        "INSERT INTO metadata (fs_uuid, subvol_id, inode_num, generation, key, value) \
         VALUES (?1, ?2, ?3, ?4, 'huge', zeroblob(100000))",
        params![u, sv, i, g],
    )?;
    let long = "k".repeat(5000);
    s.conn.execute(
        "INSERT INTO metadata (fs_uuid, subvol_id, inode_num, generation, key, value) \
         VALUES (?1, ?2, ?3, ?4, ?5, x'01')",
        params![u, sv, i, g, long],
    )?;
    assert_eq!(
        execute(&mut s, &DbReq::Get(a.clone(), "huge".into())),
        Err(MdError::Db)
    );
    let body = execute(&mut s, &DbReq::List(a.clone(), String::new()))?;
    assert_eq!(
        body,
        list_body(&["good".to_string(), "huge".to_string()], false)
    );
    Ok(())
}

/// Startup is not on the hot path: a brief lock held by another process (a second daemon,
/// a backup, a `sqlite3` shell) must not make the daemon fail to start.
#[test]
fn open_waits_out_a_brief_lock() -> Result<()> {
    let t = TestStore::new("openlock")?;
    drop(t.open()?);
    let other = Connection::open(&t.path)?;
    other
        .execute_batch("BEGIN EXCLUSIVE; INSERT INTO path_hint VALUES ('x', 0, 0, 0, x'00', 0);")?;
    let path = t.path.clone();
    let h = thread::spawn(move || Store::open(&path, StoreConfig::default()).map(drop));
    thread::sleep(Duration::from_millis(200));
    other.execute_batch("ROLLBACK")?;
    h.join().map_err(|_| Error::Protocol("open panicked"))??;
    Ok(())
}

/// Two daemons (different sockets, same default database) starting at once on a fresh file.
#[test]
fn concurrent_first_opens_all_succeed() -> Result<()> {
    for round in 0..5 {
        let t = TestStore::new(&format!("firstopen{round}"))?;
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let p = t.path.clone();
                thread::spawn(move || Store::open(&p, StoreConfig::default()).map(drop))
            })
            .collect();
        for h in hs {
            h.join().map_err(|_| Error::Protocol("open panicked"))??;
        }
    }
    Ok(())
}
