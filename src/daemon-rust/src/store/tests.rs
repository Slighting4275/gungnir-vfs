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
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO path_hint (fs_uuid, subvol_id, inode_num, generation, path, updated) VALUES ('x', 0, 0, 0, x'00', 0);")?;
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
            Some((b"/p".to_vec(), 1)),
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
        .execute_batch("BEGIN EXCLUSIVE; INSERT INTO path_hint (fs_uuid, subvol_id, inode_num, generation, path, updated) VALUES ('x', 0, 0, 0, x'00', 0);")?;
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

#[test]
fn removed_drops_the_files_last_seen_at_the_path() -> Result<()> {
    let t = TestStore::new("removed")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    let (a, b, c) = (id(10), id(11), id(12));
    s.set(&a, "k", &v, Some(b"/d/a"))?;
    s.set(&b, "k", &v, Some(b"/d/b"))?;
    s.set(&c, "k", &v, None)?; // no hint: cannot be found by path
    assert_eq!(s.removed(b"/d/nothing-here", None)?, 0);
    assert_eq!(s.removed(b"/d/a", None)?, 1);
    assert_eq!(s.get(&a, "k")?, None);
    assert_eq!(s.path_hint(&a)?, None);
    assert!(s.get(&b, "k")?.is_some(), "other files keep their metadata");
    // The same file still at the path (e.g. another hard link removed): kept, even
    // with another btime in the request (btime is not part of the key).
    let mut b_now = b.clone();
    b_now.btime_nsec = 0;
    assert_eq!(s.removed(b"/d/b", Some(&b_now))?, 0);
    assert!(s.get(&b, "k")?.is_some());
    // A new file at the path: the old one is dropped, the new one is not touched.
    assert_eq!(s.removed(b"/d/b", Some(&c))?, 1);
    assert_eq!(s.get(&b, "k")?, None);
    assert!(s.get(&c, "k")?.is_some());
    Ok(())
}

#[test]
fn moved_rewrites_hints_and_drops_replaced_files() -> Result<()> {
    let t = TestStore::new("moved")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    let (file, dir, child, deep, sibling, target) = (id(1), id(2), id(3), id(4), id(5), id(6));
    s.set(&file, "k", &v, Some(b"/a/file"))?;
    s.set(&dir, "k", &v, Some(b"/a/dir"))?;
    s.set(&child, "k", &v, Some(b"/a/dir/child"))?;
    s.set(&deep, "k", &v, Some(b"/a/dir/sub/deep"))?;
    s.set(&sibling, "k", &v, Some(b"/a/dir2/x"))?; // shares the prefix, not below dir/
    s.set(&target, "k", &v, Some(b"/b/file"))?;
    // A file renamed over another one: its hint moves, the replaced file is dropped.
    assert_eq!(s.moved(b"/a/file", b"/b/file", &file)?, (1, 1));
    assert_eq!(s.path_hint(&file)?, Some(b"/b/file".to_vec()));
    assert!(
        s.get(&file, "k")?.is_some(),
        "metadata follows the identity"
    );
    assert_eq!(s.get(&target, "k")?, None);
    // A directory: itself and everything below it, nothing beside it.
    assert_eq!(s.moved(b"/a/dir", b"/c/renamed", &dir)?, (3, 0));
    assert_eq!(s.path_hint(&dir)?, Some(b"/c/renamed".to_vec()));
    assert_eq!(s.path_hint(&child)?, Some(b"/c/renamed/child".to_vec()));
    assert_eq!(s.path_hint(&deep)?, Some(b"/c/renamed/sub/deep".to_vec()));
    assert_eq!(s.path_hint(&sibling)?, Some(b"/a/dir2/x".to_vec()));
    // A file without metadata gets no hint row.
    assert_eq!(s.moved(b"/x/plain", b"/y/plain", &id(99))?, (0, 0));
    assert_eq!(s.path_hint(&id(99))?, None);
    // Then a delete at the new path finds it.
    assert_eq!(s.removed(b"/c/renamed/child", None)?, 1);
    assert_eq!(s.get(&child, "k")?, None);
    Ok(())
}

#[test]
fn hint_paths_are_bytes_not_text() -> Result<()> {
    let t = TestStore::new("bytes")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    let a = id(7);
    s.set(&a, "k", &v, Some(b"/d/\xff\xfe/f"))?;
    assert_eq!(s.moved(b"/d/\xff\xfe", b"/e/\xc3", &id(8))?, (1, 0));
    assert_eq!(s.path_hint(&a)?, Some(b"/e/\xc3/f".to_vec()));
    assert_eq!(s.removed(b"/e/\xc3/f", None)?, 1);
    Ok(())
}

/// Review: the key is the inode, not the name. Deleting (or renaming over) one of several
/// hard links must not drop the metadata the other links still show.
#[test]
fn deleting_one_of_several_hard_links_keeps_the_metadata() -> Result<()> {
    let t = TestStore::new("hardlink")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    let (linked, single, over) = (id(20), id(21), id(22));
    s.set_linked(&linked, "k", &v, Some((b"/d/a", 2)))?;
    s.set_linked(&single, "k", &v, Some((b"/d/b", 1)))?;
    s.set_linked(&over, "k", &v, Some((b"/d/c", 3)))?;
    assert_eq!(s.removed(b"/d/a", None)?, 0);
    assert!(
        s.get(&linked, "k")?.is_some(),
        "the other link lost its metadata"
    );
    assert_eq!(s.path_hint(&linked)?, None, "the outdated hint stays");
    assert_eq!(s.removed(b"/d/b", None)?, 1);
    assert_eq!(s.get(&single, "k")?, None);
    // Renamed over: same rule.
    assert_eq!(s.moved(b"/d/new", b"/d/c", &id(23))?, (0, 0));
    assert!(s.get(&over, "k")?.is_some());
    assert_eq!(s.path_hint(&over)?, None);
    Ok(())
}

/// Review: a directory with more than 4096 hinted files below it. Every hint follows the
/// rename (a stale one would let a later delete at the old path drop the moved file's
/// metadata), in one transaction, and the paths stay BLOBs (byte ranges still match).
#[test]
fn moved_rewrites_every_hint_below_a_large_directory() -> Result<()> {
    const N: u64 = 5000;
    let t = TestStore::new("bigmove")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    for i in 0..N {
        let p = format!("/big/dir/sub/f{i}\u{e9}");
        s.set(&id(1000 + i), "k", &v, Some(p.as_bytes()))?;
    }
    let t0 = Instant::now();
    let (rewritten, forgotten) = s.moved(b"/big/dir", b"/big/moved", &id(1))?;
    let took = t0.elapsed();
    eprintln!("moved {N} hints in {took:?}");
    assert_eq!((rewritten, forgotten), (u32::try_from(N).unwrap_or(0), 0));
    for i in [0, 4095, 4096, N - 1] {
        let want = format!("/big/moved/sub/f{i}\u{e9}");
        assert_eq!(s.path_hint(&id(1000 + i))?, Some(want.into_bytes()));
    }
    // Still found by the byte-range and equality lookups.
    assert_eq!(
        s.moved(b"/big/moved", b"/big/again", &id(1))?.0,
        u32::try_from(N).unwrap_or(0)
    );
    let last = format!("/big/again/sub/f{}\u{e9}", N - 1);
    assert_eq!(s.removed(last.as_bytes(), None)?, 1);
    Ok(())
}

/// A milestone 5 database (path_hint without `links`) opens and gains the column.
#[test]
fn milestone_5_database_gains_the_link_count() -> Result<()> {
    let t = TestStore::new("m5schema")?;
    if let Some(dir) = t.path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    }
    {
        let c = Connection::open(&t.path)?;
        c.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE path_hint (fs_uuid TEXT NOT NULL, subvol_id INTEGER NOT NULL,
               inode_num INTEGER NOT NULL, generation INTEGER NOT NULL, path BLOB NOT NULL,
               updated INTEGER NOT NULL,
               PRIMARY KEY (fs_uuid, subvol_id, inode_num, generation)) WITHOUT ROWID;
             INSERT INTO path_hint (fs_uuid, subvol_id, inode_num, generation, path, updated) VALUES ('0123abcd-0000-4000-8000-00000000beef', 256, 30, 3,
               x'2f642f6f6c64', 0);",
        )?;
    }
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    s.set(&id(30), "k", &v, None)?;
    assert_eq!(s.removed(b"/d/old", None)?, 1, "old rows count as one link");
    drop(s);
    drop(t.open()?); // and opens again with the column present
    Ok(())
}

// ---- milestone 8: metadata follows file-op copies and recursive deletes ------------

#[test]
fn copy_meta_duplicates_rows_and_optionally_forgets_the_source() -> Result<()> {
    let t = TestStore::new("copy")?;
    let mut s = t.open()?;
    let (a, b, c) = (id(10), id(11), id(12));
    let v = enc(&Value::String("x".into()));
    s.set(&a, "k1", &v, Some(b"/d/a"))?;
    s.set(&a, "k2", &v, Some(b"/d/a"))?;
    // Stale rows of a recycled inode at the copy's identity are replaced.
    s.set(&b, "old", &v, Some(b"/d/old"))?;
    assert_eq!(s.copy_meta(&a, &b, b"/d/b", false)?, 2);
    assert_eq!(
        s.list(&b, "", 100)?.0,
        vec!["k1".to_owned(), "k2".to_owned()]
    );
    assert_eq!(s.path_hint(&b)?, Some(b"/d/b".to_vec()));
    assert_eq!(
        s.list(&a, "", 100)?.0.len(),
        2,
        "a copy keeps the source's rows"
    );
    // A move across filesystems: the source's rows go.
    assert_eq!(s.copy_meta(&a, &c, b"/e/c", true)?, 2);
    assert!(s.list(&a, "", 100)?.0.is_empty());
    assert_eq!(s.path_hint(&a)?, None);
    assert_eq!(s.list(&c, "", 100)?.0.len(), 2);
    // Same key, or nothing to copy: no rows.
    assert_eq!(s.copy_meta(&c, &c, b"/e/c", false)?, 0);
    assert_eq!(s.copy_meta(&id(99), &id(98), b"/x", false)?, 0);
    assert_eq!(s.path_hint(&id(98))?, None);
    Ok(())
}

#[test]
fn removed_tree_drops_the_path_and_everything_below_only() -> Result<()> {
    let t = TestStore::new("tree")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    s.set(&id(1), "k", &v, Some(b"/t/dir"))?;
    s.set(&id(2), "k", &v, Some(b"/t/dir/f"))?;
    s.set(&id(3), "k", &v, Some(b"/t/dir/sub/g"))?;
    s.set(&id(4), "k", &v, Some(b"/t/dir2/f"))?; // a sibling with the same prefix
    s.set(&id(5), "k", &v, Some(b"/t/dir0"))?;
    assert_eq!(s.removed_tree(b"/t/dir")?, 3);
    for gone in [1, 2, 3] {
        assert!(s.get(&id(gone), "k")?.is_none());
    }
    for kept in [4, 5] {
        assert!(s.get(&id(kept), "k")?.is_some());
    }
    assert_eq!(s.removed_tree(b"/t/dir")?, 0);
    Ok(())
}

/// Review: a recursive delete follows the hard link rule (a file in the tree with another
/// link outside keeps its metadata) and has no cap (every row below goes, in one call).
#[test]
fn removed_tree_follows_the_hard_link_rule_without_a_cap() -> Result<()> {
    const N: u64 = 5000;
    let t = TestStore::new("treelinks")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    for i in 0..N {
        let p = format!("/t/big/sub/f{i}");
        s.set(&id(1000 + i), "k", &v, Some(p.as_bytes()))?;
    }
    s.set_linked(&id(7), "k", &v, Some((b"/t/big/linked", 2)))?;
    assert_eq!(
        s.removed_tree(b"/t/big")?,
        u32::try_from(N).unwrap_or(0),
        "every row below the deleted tree, beyond 4096 too"
    );
    for i in [0, 4095, 4096, N - 1] {
        assert_eq!(s.get(&id(1000 + i), "k")?, None);
    }
    assert!(
        s.get(&id(7), "k")?.is_some(),
        "the other link lost its metadata"
    );
    assert_eq!(s.path_hint(&id(7))?, None, "the outdated hint goes");
    Ok(())
}

/// Review: what a failed recursive delete reports, in one transaction: trees, single
/// entries, the hard link rule; a survivor's metadata stays.
#[test]
fn removed_paths_drops_exactly_the_reported_paths() -> Result<()> {
    let t = TestStore::new("paths")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    s.set(&id(1), "k", &v, Some(b"/r/a"))?;
    s.set(&id(2), "k", &v, Some(b"/r/d/x"))?;
    s.set(&id(3), "k", &v, Some(b"/r/d/y/z"))?;
    s.set(&id(4), "k", &v, Some(b"/r/survivor"))?;
    s.set_linked(&id(5), "k", &v, Some((b"/r/b", 3)))?;
    let paths = [
        (b"/r/a".to_vec(), false),
        (b"/r/d".to_vec(), true),
        (b"/r/b".to_vec(), false),
    ];
    assert_eq!(s.removed_paths(&paths)?, 3);
    for gone in [1, 2, 3] {
        assert_eq!(s.get(&id(gone), "k")?, None);
    }
    assert!(s.get(&id(4), "k")?.is_some());
    assert!(s.get(&id(5), "k")?.is_some());
    assert_eq!(s.removed_paths(&paths)?, 0);
    Ok(())
}

/// Review: a copy that replaces a file (OVERWRITE) takes its name: the replaced file's
/// rows go, unless it has other links; a move across filesystems of a file with other
/// links keeps the source's metadata (it still exists under them).
#[test]
fn copy_meta_follows_the_hard_link_rule() -> Result<()> {
    let t = TestStore::new("copylinks")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("x".into()));
    s.set(&id(1), "k", &v, Some(b"/c/src"))?;
    s.set(&id(2), "old", &v, Some(b"/c/dest"))?; // replaced by the copy
    s.set_linked(&id(3), "old", &v, Some((b"/c/dest2", 2)))?; // replaced, other link
    assert_eq!(s.copy_meta(&id(1), &id(10), b"/c/dest", false)?, 1);
    assert_eq!(
        s.get(&id(2), "old")?,
        None,
        "the replaced file's rows stayed"
    );
    assert_eq!(s.copy_meta(&id(1), &id(11), b"/c/dest2", false)?, 1);
    assert!(s.get(&id(3), "old")?.is_some());
    assert_eq!(s.path_hint(&id(3))?, None);
    // Cross-filesystem move of a file with two links: the source's rows stay.
    s.set_linked(&id(4), "k", &v, Some((b"/c/m", 2)))?;
    assert_eq!(s.copy_meta(&id(4), &id(12), b"/e/m", true)?, 1);
    assert!(s.get(&id(4), "k")?.is_some());
    assert_eq!(s.path_hint(&id(4))?, None);
    assert_eq!(s.path_hint(&id(12))?, Some(b"/e/m".to_vec()));
    // With one link: gone.
    assert_eq!(s.copy_meta(&id(12), &id(13), b"/f/m", true)?, 1);
    assert_eq!(s.get(&id(12), "k")?, None);
    Ok(())
}

#[test]
fn wal_checkpoint_flushes_and_truncates() -> Result<()> {
    let t = TestStore::new("checkpoint")?;
    let mut s = t.open()?;
    let v = enc(&Value::String("persisted".into()));
    for i in 0..100 {
        s.set(&id(i), "key", &v, None)?;
    }
    s.checkpoint()?;

    let handle = spawn(s, DbConfig::default())?;
    handle.flush_and_checkpoint()?;
    drop(handle);

    let mut s2 = t.open()?;
    for i in 0..100 {
        assert_eq!(s2.get(&id(i), "key")?, Some(v.clone()));
    }
    Ok(())
}

/// T-010 (PR-F008): metadata follow-ups of file ops and GIO notifications record what
/// already happened on disk; one that waited past max_age still runs (in order), where a
/// client's own request of the same age is answered Busy.
#[test]
fn follow_ups_run_even_after_waiting_past_max_age() -> Result<()> {
    let t = TestStore::new("followups")?;
    let store = t.open()?;
    let h = spawn(
        store,
        DbConfig {
            queue: 16,
            max_age: Duration::from_millis(1),
        },
    )?;
    let long_ago = Instant::now() - Duration::from_secs(10);
    let run = |req: DbReq, enqueued: Instant| -> Result<DbResult> {
        let (tx, rx) = mpsc::channel();
        h.submit(Job {
            req,
            enqueued,
            done: Box::new(move |r| {
                let _ = tx.send(r);
            }),
        })
        .map_err(|_| Error::Protocol("queue full"))?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|_| Error::Protocol("db thread did not answer"))
    };
    let v = enc(&Value::String("note".into()));
    let set = DbReq::Set(id(1), "k".into(), v.clone(), Some((b"/a".to_vec(), 1)));
    assert_eq!(run(set, Instant::now())?, Ok(Vec::new()));

    // A client's request that waited too long: shed.
    assert_eq!(
        run(DbReq::Get(id(1), "k".into()), long_ago)?,
        Err(MdError::Busy)
    );
    // Follow-ups that waited too long: still run.
    let copied = DbReq::Copied(id(1), id(2), b"/b".to_vec(), false);
    assert!(
        run(copied, long_ago)?.is_ok(),
        "a late copy follow-up was dropped"
    );
    assert_eq!(
        run(DbReq::Get(id(2), "k".into()), Instant::now())?,
        Ok(v.clone())
    );
    let moved = DbReq::Moved(b"/b".to_vec(), b"/c".to_vec(), id(2));
    assert!(
        run(moved, long_ago)?.is_ok(),
        "a late move follow-up was dropped"
    );
    let removed = DbReq::RemovedPaths(vec![(b"/c".to_vec(), false)]);
    assert!(
        run(removed, long_ago)?.is_ok(),
        "a late remove follow-up was dropped"
    );
    assert!(run(DbReq::RemovedTree(b"/x".to_vec()), long_ago)?.is_ok());
    assert!(run(DbReq::Removed(b"/a".to_vec(), None), long_ago)?.is_ok());
    Ok(())
}

/// T-010: a worker's follow-up waits for room in a full queue (within its bound) rather
/// than being dropped; past the bound it is refused.
#[test]
fn submit_wait_gets_room_when_the_queue_drains() -> Result<()> {
    let t = TestStore::new("submitwait")?;
    let h = spawn(
        t.open()?,
        DbConfig {
            queue: 1,
            max_age: Duration::from_secs(60),
        },
    )?;
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (started_tx, started_rx) = mpsc::channel::<()>();
    h.submit(Job {
        req: DbReq::Get(id(1), "k".into()),
        enqueued: Instant::now(),
        done: Box::new(move |_| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        }),
    })
    .map_err(|_| Error::Protocol("blocker refused"))?;
    started_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| Error::Protocol("blocker never ran"))?;
    let mk = || Job {
        req: DbReq::RemovedTree(b"/x".to_vec()),
        enqueued: Instant::now(),
        done: Box::new(|_| {}),
    };
    h.submit(mk())
        .map_err(|_| Error::Protocol("queue slot refused"))?;
    // Full now: a short wait gives up...
    assert_eq!(
        h.submit_wait(mk(), Duration::from_millis(30)),
        Err(MdError::Busy)
    );
    // ...and a longer one gets in once the blocker is released.
    let release = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        let _ = release_tx.send(());
    });
    assert_eq!(h.submit_wait(mk(), Duration::from_secs(5)), Ok(()));
    let _ = release.join();
    Ok(())
}
