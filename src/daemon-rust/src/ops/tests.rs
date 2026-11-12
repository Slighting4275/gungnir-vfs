//! Unit tests of the file-op engines and scheduler. Every behavioural test runs on both
//! engines: the thread pool and io_uring. Where io_uring is unavailable (old kernels,
//! seccomp, containers) they fail, unless `GUNGNIR_ALLOW_NO_URING=1` asks to skip its
//! half on purpose (each prints a SKIP line; `GUNGNIR_REQUIRE_URING` overrides that).
//! `GUNGNIR_NO_URING` only changes which engine the daemon picks ([`choose_engine`]);
//! these tests name their engine, so they run both whatever it says.

use std::{
    ffi::CString,
    fs,
    io::Write as _,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use super::*;
use crate::testdir::TestDir;

type R<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn engines() -> Vec<EngineKind> {
    let mut v = vec![EngineKind::Threads];
    if io::uring_for_tests_env("its engine tests") {
        v.push(EngineKind::Uring);
    }
    v
}

#[derive(Default)]
struct Events {
    progress: Vec<Progress>,
    done: Option<Done>,
    dones: usize,
}

#[derive(Default)]
struct ChanSink {
    ev: Mutex<Events>,
    cv: Condvar,
}

impl Sink for ChanSink {
    fn progress(&self, _: u64, p: &Progress) {
        self.ev.lock().unwrap().progress.push(*p);
        self.cv.notify_all();
    }
    fn done(&self, d: &Done) {
        let mut e = self.ev.lock().unwrap();
        e.done = Some(*d);
        e.dones += 1;
        self.cv.notify_all();
    }
}

impl ChanSink {
    fn wait(&self, limit: Duration) -> Option<Done> {
        let t0 = Instant::now();
        let mut e = self.ev.lock().unwrap();
        while e.done.is_none() {
            let left = limit.checked_sub(t0.elapsed())?;
            e = self.cv.wait_timeout(e, left).unwrap().0;
        }
        e.done
    }

    fn wait_progress(&self, limit: Duration) -> bool {
        let t0 = Instant::now();
        let mut e = self.ev.lock().unwrap();
        while e.progress.is_empty() && e.done.is_none() {
            let Some(left) = limit.checked_sub(t0.elapsed()) else {
                return false;
            };
            e = self.cv.wait_timeout(e, left).unwrap().0;
        }
        !e.progress.is_empty()
    }
}

/// Records the metadata hook calls.
#[derive(Default)]
struct RecMeta(Mutex<Vec<String>>);

impl MetaHooks for RecMeta {
    fn identify(&self, path: &[u8]) -> Option<Ident> {
        self.0
            .lock()
            .unwrap()
            .push(format!("identify {}", String::from_utf8_lossy(path)));
        Some(Ident {
            fs_uuid: "u".into(),
            subvol_id: 0,
            inode_num: 1,
            generation: 0,
            btime_sec: 0,
            btime_nsec: 0,
        })
    }
    fn moved(&self, src: &[u8], dest: &[u8]) {
        self.0.lock().unwrap().push(format!(
            "moved {} {}",
            String::from_utf8_lossy(src),
            String::from_utf8_lossy(dest)
        ));
    }
    fn copied(&self, _: &Ident, dest: &[u8], forget: bool) {
        self.0
            .lock()
            .unwrap()
            .push(format!("copied {} {forget}", String::from_utf8_lossy(dest)));
    }
    fn removed(&self, path: &[u8], tree: bool) {
        self.0
            .lock()
            .unwrap()
            .push(format!("removed {} {tree}", String::from_utf8_lossy(path)));
    }
}

/// Refuses paths below `hung`; every path is on mount `mount`.
struct FakeGate {
    hung: Mutex<Option<PathBuf>>,
    mount: PathBuf,
}

impl Gate for FakeGate {
    fn blocking(&self, path: &[u8]) -> Option<PathBuf> {
        let h = self.hung.lock().unwrap().clone()?;
        under(path, h.as_os_str().as_bytes()).then_some(h)
    }
    fn mount_of(&self, path: &[u8]) -> Option<PathBuf> {
        under(path, self.mount.as_os_str().as_bytes()).then(|| self.mount.clone())
    }
}

fn test_cfg() -> OpsConfig {
    OpsConfig {
        progress_every: Duration::ZERO,
        ..OpsConfig::default()
    }
}

fn start(engine: EngineKind, cfg: OpsConfig) -> R<Ops> {
    Ok(Ops::start(cfg, engine, Arc::new(NoGate), Arc::new(NoMeta))?)
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
        src_at: None,
        dest_at: None,
    }
}

fn run(ops: &Ops, r: OpRequest) -> R<(Done, Vec<Progress>)> {
    let sink = Arc::new(ChanSink::default());
    let ctl = ops
        .submit(r, sink.clone())
        .map_err(|e| format!("submit: {e}"))?;
    let d = sink
        .wait(Duration::from_secs(60))
        .ok_or("op did not finish in 60 s")?;
    assert_eq!(d.id, ctl.id);
    std::thread::sleep(Duration::from_millis(5));
    let e = sink.ev.lock().unwrap();
    assert_eq!(e.dones, 1, "done reported exactly once");
    Ok((d, e.progress.clone()))
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9 ^ u32::from(seed);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn set_times(p: &Path, sec: i64, nsec: i64) -> R {
    let c = CString::new(p.as_os_str().as_bytes())?;
    let t = [
        libc::timespec {
            tv_sec: sec - 100,
            tv_nsec: nsec,
        },
        libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        },
    ];
    // SAFETY: valid path and timespec array.
    let r = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), t.as_ptr(), 0) };
    if r != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn no_temp_files(dir: &Path) -> R<bool> {
    Ok(fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .all(|e| !e.file_name().as_bytes().starts_with(b".gungnir-")))
}

fn os(d: &Done) -> Option<i32> {
    match d.result {
        Err(OpError::Os(e)) => Some(e),
        _ => None,
    }
}

// ---- protocol --------------------------------------------------------------------

#[test]
fn start_requests_round_trip_and_bad_ones_are_refused() {
    let good = OpRequest {
        kind: OpKind::Copy,
        flags: FLAG_OVERWRITE | FLAG_ALL_METADATA,
        timeout_ms: 1234,
        src: b"/a/b".to_vec(),
        dest: b"/c/d".to_vec(),
        src_at: None,
        dest_at: None,
    };
    assert_eq!(OpRequest::parse(&good.encode()), Ok(good.clone()));
    let fsync_root = OpRequest {
        kind: OpKind::Fsync,
        flags: 0,
        timeout_ms: 0,
        src: b"/".to_vec(),
        dest: Vec::new(),
        src_at: None,
        dest_at: None,
    };
    assert_eq!(OpRequest::parse(&fsync_root.encode()), Ok(fsync_root));
    let bad = |f: &dyn Fn(&mut OpRequest)| {
        let mut r = good.clone();
        f(&mut r);
        OpRequest::parse(&r.encode())
    };
    for p in [
        &b"rel"[..],
        b"/a/../b",
        b"/a/./b",
        b"/a//b",
        b"/a/",
        b"/",
        b"/a\0b",
        b"",
    ] {
        assert_eq!(
            bad(&|r| r.src = p.to_vec()),
            Err(OpError::BadRequest),
            "{p:?}"
        );
    }
    assert_eq!(bad(&|r| r.dest = r.src.clone()), Err(OpError::BadRequest));
    assert_eq!(bad(&|r| r.dest.clear()), Err(OpError::BadRequest));
    assert_eq!(bad(&|r| r.flags = 1 << 7), Err(OpError::BadRequest));
    assert_eq!(bad(&|r| r.flags = FLAG_BACKUP), Err(OpError::Unsupported));
    assert_eq!(
        bad(&|r| {
            r.kind = OpKind::Delete;
        }),
        Err(OpError::BadRequest),
        "delete takes no destination"
    );
    assert_eq!(
        bad(&|r| {
            r.kind = OpKind::Delete;
            r.dest.clear();
            r.src = b"/".to_vec();
        }),
        Err(OpError::BadRequest),
        "never delete /"
    );
    let mut p = good.encode();
    p.push(0);
    assert_eq!(
        OpRequest::parse(&p),
        Err(OpError::BadRequest),
        "trailing byte"
    );
    p[0] = 9;
    assert_eq!(
        OpRequest::parse(&p[..p.len() - 1]),
        Err(OpError::BadRequest)
    );
    assert_eq!(OpRequest::parse(&[]), Err(OpError::BadRequest));
}

#[test]
fn done_and_progress_payloads_round_trip() {
    let pr = Progress {
        bytes_done: 5,
        bytes_total: 9,
        files_done: 2,
    };
    assert_eq!(parse_progress(&progress_payload(7, &pr)), Some((7, pr)));
    for result in [
        Ok(()),
        Err(OpError::Os(libc::ENOSPC)),
        Err(OpError::Cancelled),
        Err(OpError::TimedOut),
        Err(OpError::SuspectMount),
        Err(OpError::WouldRecurse),
        Err(OpError::Busy),
    ] {
        let d = Done {
            id: 3,
            result,
            progress: Progress {
                bytes_total: 0,
                ..pr
            },
        };
        assert_eq!(parse_done(&done_payload(&d)), Some(d));
    }
    assert_eq!(parse_done(&[0; 31]), None);
}

// ---- copies ----------------------------------------------------------------------

#[test]
fn copy_keeps_data_mode_and_times_on_every_path() -> R {
    for engine in engines() {
        // (reflink/copy_file_range allowed, forced read/write through the engine)
        for rw in [false, true] {
            let t = TestDir::new("op-copy")?;
            let cfg = OpsConfig {
                no_clone: rw,
                no_cfr: rw,
                cfr_chunk: 1 << 20,
                buf_size: 256 << 10,
                ..test_cfg()
            };
            let ops = start(engine, cfg)?;
            let src = t.join("src");
            let data = pattern(3 * (1 << 20) + 12345, 1);
            fs::write(&src, &data)?;
            fs::set_permissions(&src, fs::Permissions::from_mode(0o640))?;
            set_times(&src, 1_600_000_000, 123_456_789)?;
            let dest = t.join("dest");
            let (d, progress) = run(&ops, req(OpKind::Copy, 0, &src, Some(&dest)))?;
            assert_eq!(d.result, Ok(()), "{engine:?} rw={rw}");
            assert_eq!(fs::read(&dest)?, data, "{engine:?} rw={rw}");
            let (ms, md) = (fs::metadata(&src)?, fs::metadata(&dest)?);
            assert_eq!(md.mode() & 0o7777, 0o640);
            assert_eq!((md.mtime(), md.mtime_nsec()), (ms.mtime(), ms.mtime_nsec()));
            assert_eq!(d.progress.bytes_done, data.len() as u64);
            assert_eq!(d.progress.files_done, 1);
            let last = progress.last().ok_or("no progress event")?;
            assert_eq!(last.bytes_done, data.len() as u64, "a final progress event");
            assert_eq!(last.bytes_total, data.len() as u64);
            assert!(
                progress
                    .windows(2)
                    .all(|w| w[0].bytes_done <= w[1].bytes_done)
            );
            if rw {
                assert!(progress.len() >= 3, "chunked progress: {}", progress.len());
            }
            // Target defaults: umask'ed mode, mtime now.
            let dest2 = t.join("dest2");
            let flags = FLAG_TARGET_DEFAULT_PERMS | FLAG_TARGET_DEFAULT_MODIFIED_TIME;
            let (d, _) = run(&ops, req(OpKind::Copy, flags, &src, Some(&dest2)))?;
            assert_eq!(d.result, Ok(()));
            assert_ne!(fs::metadata(&dest2)?.mtime(), ms.mtime());
            assert!(no_temp_files(t.path())?);
        }
    }
    Ok(())
}

#[test]
fn large_sparse_file_stays_sparse_and_equal() -> R {
    for engine in engines() {
        for rw in [false, true] {
            let t = TestDir::new("op-sparse")?;
            let ops = start(
                engine,
                OpsConfig {
                    no_clone: rw,
                    no_cfr: rw,
                    ..test_cfg()
                },
            )?;
            let src = t.join("sparse");
            let size: u64 = 256 << 20;
            {
                let mut f = fs::File::create(&src)?;
                f.write_all(&pattern(1 << 20, 2))?;
                f.set_len(size)?;
                use std::os::unix::fs::FileExt;
                f.write_all_at(&pattern(1 << 20, 3), 100 << 20)?;
                f.write_all_at(b"tail", size - 4)?;
            }
            let dest = t.join("copy");
            let (d, _) = run(&ops, req(OpKind::Copy, 0, &src, Some(&dest)))?;
            assert_eq!(d.result, Ok(()), "{engine:?} rw={rw}");
            assert_eq!(d.progress.bytes_done, size, "holes count as done");
            let md = fs::metadata(&dest)?;
            assert_eq!(md.len(), size);
            assert_eq!(fs::read(&src)?, fs::read(&dest)?);
            let src_alloc = fs::metadata(&src)?.blocks() * 512;
            if src_alloc < size / 4 {
                assert!(
                    md.blocks() * 512 < 16 << 20,
                    "{engine:?} rw={rw}: copy allocates {} bytes",
                    md.blocks() * 512
                );
            } else {
                eprintln!("note: this filesystem does not keep holes; sparseness unchecked");
            }
        }
    }
    Ok(())
}

#[test]
fn copy_errors_map_to_errnos() -> R {
    for engine in engines() {
        let t = TestDir::new("op-err")?;
        let ops = start(engine, test_cfg())?;
        let src = t.join("src");
        fs::write(&src, b"new")?;
        let dest = t.join("dest");
        fs::write(&dest, b"old")?;
        let (d, _) = run(&ops, req(OpKind::Copy, 0, &t.join("missing"), Some(&dest)))?;
        assert_eq!(os(&d), Some(libc::ENOENT));
        let (d, _) = run(&ops, req(OpKind::Copy, 0, &src, Some(&dest)))?;
        assert_eq!(os(&d), Some(libc::EEXIST), "no overwrite without the flag");
        assert_eq!(fs::read(&dest)?, b"old");
        let (d, _) = run(&ops, req(OpKind::Copy, FLAG_OVERWRITE, &src, Some(&dest)))?;
        assert_eq!(d.result, Ok(()));
        assert_eq!(fs::read(&dest)?, b"new");
        let (d, _) = run(
            &ops,
            req(
                OpKind::Copy,
                FLAG_OVERWRITE,
                &src,
                Some(&src.with_extension("")),
            ),
        )?;
        assert_eq!(os(&d), Some(libc::EINVAL), "onto itself");
        let dir = t.join("dir");
        fs::create_dir(&dir)?;
        let (d, _) = run(&ops, req(OpKind::Copy, 0, &dir, Some(&t.join("dir2"))))?;
        assert_eq!(d.result, Err(OpError::WouldRecurse));
        let (d, _) = run(&ops, req(OpKind::Copy, FLAG_OVERWRITE, &src, Some(&dir)))?;
        assert_eq!(os(&d), Some(libc::EISDIR));
        let (d, _) = run(&ops, req(OpKind::Copy, 0, &src, Some(&t.join("no/such"))))?;
        assert_eq!(os(&d), Some(libc::ENOENT));
        let fifo = t.join("fifo");
        let c = CString::new(fifo.as_os_str().as_bytes())?;
        // SAFETY: valid path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (d, _) = run(&ops, req(OpKind::Copy, 0, &fifo, Some(&t.join("f2"))))?;
        assert_eq!(
            os(&d),
            Some(libc::EOPNOTSUPP),
            "special files are not copied"
        );
        let (d, _) = run(&ops, req(OpKind::Delete, 0, &t.join("missing"), None))?;
        assert_eq!(os(&d), Some(libc::ENOENT));
        fs::write(dir.join("x"), b"")?;
        let (d, _) = run(&ops, req(OpKind::Delete, 0, &dir, None))?;
        assert_eq!(os(&d), Some(libc::ENOTEMPTY));
        assert!(no_temp_files(t.path())?);
    }
    Ok(())
}

#[test]
fn symlinks_copy_as_links_with_nofollow_and_as_files_without() -> R {
    for engine in engines() {
        let t = TestDir::new("op-link")?;
        let ops = start(engine, test_cfg())?;
        fs::write(t.join("target"), b"data")?;
        std::os::unix::fs::symlink("target", t.join("link"))?;
        let (d, _) = run(
            &ops,
            req(
                OpKind::Copy,
                FLAG_NOFOLLOW_SYMLINKS,
                &t.join("link"),
                Some(&t.join("l2")),
            ),
        )?;
        assert_eq!(d.result, Ok(()));
        assert_eq!(fs::read_link(t.join("l2"))?, Path::new("target"));
        let (d, _) = run(
            &ops,
            req(OpKind::Copy, 0, &t.join("link"), Some(&t.join("f2"))),
        )?;
        assert_eq!(d.result, Ok(()));
        assert!(fs::symlink_metadata(t.join("f2"))?.is_file());
        assert_eq!(fs::read(t.join("f2"))?, b"data");
    }
    Ok(())
}

#[test]
fn all_metadata_copies_xattrs_best_effort() -> R {
    for engine in engines() {
        let t = TestDir::new("op-xattr")?;
        let ops = start(engine, test_cfg())?;
        let src = t.join("src");
        fs::write(&src, b"x")?;
        let c = CString::new(src.as_os_str().as_bytes())?;
        // SAFETY: valid strings and value buffer.
        let r = unsafe {
            libc::setxattr(
                c.as_ptr(),
                c"user.gungnir-test".as_ptr(),
                b"v1".as_ptr().cast(),
                2,
                0,
            )
        };
        if r != 0 {
            eprintln!("note: no user xattrs on this filesystem; xattr copy unchecked");
            return Ok(());
        }
        for (flags, want) in [(FLAG_ALL_METADATA, true), (0, false)] {
            let dest = t.join(&format!("d{flags}"));
            let (d, _) = run(&ops, req(OpKind::Copy, flags, &src, Some(&dest)))?;
            assert_eq!(d.result, Ok(()));
            let cd = CString::new(dest.as_os_str().as_bytes())?;
            let mut buf = [0u8; 8];
            // SAFETY: valid strings and buffer.
            let n = unsafe {
                libc::getxattr(
                    cd.as_ptr(),
                    c"user.gungnir-test".as_ptr(),
                    buf.as_mut_ptr().cast(),
                    8,
                )
            };
            assert_eq!(
                n == 2 && &buf[..2] == b"v1",
                want,
                "{engine:?} flags {flags}"
            );
        }
    }
    Ok(())
}

// ---- moves -----------------------------------------------------------------------

#[test]
fn move_renames_and_falls_back_across_devices() -> R {
    for engine in engines() {
        let t = TestDir::new("op-move")?;
        let meta = Arc::new(RecMeta::default());
        let ops = Ops::start(test_cfg(), engine, Arc::new(NoGate), meta.clone())?;
        let src = t.join("a");
        fs::write(&src, b"moved")?;
        fs::create_dir(t.join("sub"))?;
        let dest = t.join("sub/b");
        let (d, _) = run(&ops, req(OpKind::Move, 0, &src, Some(&dest)))?;
        assert_eq!(d.result, Ok(()));
        assert!(!src.exists());
        assert_eq!(fs::read(&dest)?, b"moved");
        fs::write(&src, b"again")?;
        let (d, _) = run(&ops, req(OpKind::Move, 0, &src, Some(&dest)))?;
        assert_eq!(os(&d), Some(libc::EEXIST));
        let (d, _) = run(&ops, req(OpKind::Move, FLAG_OVERWRITE, &src, Some(&dest)))?;
        assert_eq!(d.result, Ok(()));
        assert_eq!(fs::read(&dest)?, b"again");
        let calls = meta.0.lock().unwrap().clone();
        assert!(
            calls.iter().filter(|c| c.starts_with("moved ")).count() == 2,
            "{calls:?}"
        );

        // Simulated EXDEV: copy + fsync + unlink, mode/times kept, metadata copied.
        let xops = Ops::start(
            OpsConfig {
                force_exdev: true,
                ..test_cfg()
            },
            engine,
            Arc::new(NoGate),
            meta.clone(),
        )?;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o604))?;
        set_times(&dest, 1_500_000_000, 7)?;
        let back = t.join("back");
        let (d, _) = run(&xops, req(OpKind::Move, 0, &dest, Some(&back)))?;
        assert_eq!(d.result, Ok(()));
        assert!(!dest.exists());
        let md = fs::metadata(&back)?;
        assert_eq!(
            (md.mode() & 0o7777, md.mtime(), md.mtime_nsec()),
            (0o604, 1_500_000_000, 7)
        );
        let calls = meta.0.lock().unwrap().clone();
        assert!(calls.iter().any(|c| c.ends_with("/back true")), "{calls:?}");
        let (d, _) = run(
            &xops,
            req(
                OpKind::Move,
                FLAG_NO_FALLBACK_FOR_MOVE,
                &back,
                Some(&t.join("c")),
            ),
        )?;
        assert_eq!(os(&d), Some(libc::EXDEV));
        assert!(back.exists());
        let (d, _) = run(
            &xops,
            req(OpKind::Move, 0, &t.join("sub"), Some(&t.join("sub2"))),
        )?;
        assert_eq!(d.result, Err(OpError::WouldRecurse));
        assert!(no_temp_files(t.path())?);
    }
    Ok(())
}

/// A real second filesystem: the one mounted at `<repo>/.build/xdev` if there is one,
/// else a tmpfs this test mounts for itself in a user+mount namespace (review: the CI
/// job mounts nothing at `.build/xdev`, so the test was always skipped); skipped only
/// where neither exists.
#[test]
fn copy_and_move_across_a_real_device_boundary() -> R {
    let xdev = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build/xdev");
    let t = TestDir::new("op-xdev")?;
    let mut _tmpfs = None;
    let other = match fs::metadata(&xdev) {
        Ok(m) if m.dev() != fs::metadata(t.path())?.dev() => xdev,
        _ => {
            if !in_mount_namespace("ops::tests::copy_and_move_across_a_real_device_boundary")? {
                return Ok(());
            }
            let mnt = t.join("tmpfs");
            fs::create_dir(&mnt)?;
            _tmpfs = Some(Mount::tmpfs(&mnt)?);
            assert_ne!(fs::metadata(&mnt)?.dev(), fs::metadata(t.path())?.dev());
            mnt
        }
    };
    let there = other.join(format!("op-{}", std::process::id()));
    fs::create_dir_all(&there)?;
    struct Rm(PathBuf);
    impl Drop for Rm {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _rm = Rm(there.clone());
    for engine in engines() {
        let ops = start(engine, test_cfg())?;
        let src = t.join(&format!("src-{engine:?}"));
        let data = pattern(5 << 20, 4);
        fs::write(&src, &data)?;
        let copy = there.join(format!("copy-{engine:?}"));
        let (d, _) = run(&ops, req(OpKind::Copy, 0, &src, Some(&copy)))?;
        assert_eq!(d.result, Ok(()), "{engine:?}");
        assert_eq!(fs::read(&copy)?, data);
        let moved = there.join(format!("moved-{engine:?}"));
        let (d, _) = run(&ops, req(OpKind::Move, 0, &src, Some(&moved)))?;
        assert_eq!(d.result, Ok(()), "{engine:?}");
        assert!(!src.exists());
        assert_eq!(fs::read(&moved)?, data);
        let (d, _) = run(
            &ops,
            req(OpKind::Move, FLAG_NO_FALLBACK_FOR_MOVE, &moved, Some(&src)),
        )?;
        assert_eq!(os(&d), Some(libc::EXDEV));
    }
    Ok(())
}

// ---- deletes and fsync -----------------------------------------------------------

#[test]
fn delete_tree_removes_everything_without_following_links() -> R {
    for engine in engines() {
        let t = TestDir::new("op-tree")?;
        let meta = Arc::new(RecMeta::default());
        let ops = Ops::start(test_cfg(), engine, Arc::new(NoGate), meta.clone())?;
        let outside = t.join("outside");
        fs::create_dir(&outside)?;
        fs::write(outside.join("keep"), b"k")?;
        let root = t.join("tree");
        let mut n = 0;
        for d in ["a", "a/b", "a/b/c", "d"] {
            fs::create_dir_all(root.join(d))?;
            for i in 0..5 {
                fs::write(root.join(d).join(format!("f{i}")), b"x")?;
                n += 1;
            }
        }
        std::os::unix::fs::symlink(&outside, root.join("a/link"))?;
        let (d, progress) = run(&ops, req(OpKind::DeleteTree, 0, &root, None))?;
        assert_eq!(d.result, Ok(()), "{engine:?}");
        assert!(!root.exists());
        assert!(
            outside.join("keep").exists(),
            "the symlink was not followed"
        );
        // files + the link + 4 directories + the root
        assert_eq!(d.progress.files_done, n + 1 + 4 + 1);
        assert!(!progress.is_empty());
        assert!(
            meta.0
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.ends_with("/tree true"))
        );
        // A plain file through delete-tree, and delete of an empty directory.
        let (d, _) = run(
            &ops,
            req(OpKind::DeleteTree, 0, &outside.join("keep"), None),
        )?;
        assert_eq!(d.result, Ok(()));
        let (d, _) = run(&ops, req(OpKind::Delete, 0, &outside, None))?;
        assert_eq!(d.result, Ok(()));
        assert!(!outside.exists());
    }
    Ok(())
}

#[test]
fn fsync_files_and_directories() -> R {
    for engine in engines() {
        let t = TestDir::new("op-fsync")?;
        let ops = start(engine, test_cfg())?;
        fs::write(t.join("f"), b"x")?;
        let (d, _) = run(&ops, req(OpKind::Fsync, 0, &t.join("f"), None))?;
        assert_eq!(d.result, Ok(()));
        let (d, _) = run(&ops, req(OpKind::Fsync, 0, t.path(), None))?;
        assert_eq!(d.result, Ok(()));
        let (d, _) = run(&ops, req(OpKind::Fsync, 0, &t.join("nope"), None))?;
        assert_eq!(os(&d), Some(libc::ENOENT));
    }
    Ok(())
}

#[test]
fn metadata_hooks_follow_copies_only_with_all_metadata() -> R {
    let t = TestDir::new("op-meta")?;
    let meta = Arc::new(RecMeta::default());
    let ops = Ops::start(
        test_cfg(),
        EngineKind::Threads,
        Arc::new(NoGate),
        meta.clone(),
    )?;
    fs::write(t.join("s"), b"x")?;
    run(
        &ops,
        req(OpKind::Copy, 0, &t.join("s"), Some(&t.join("plain"))),
    )?;
    assert!(
        meta.0.lock().unwrap().is_empty(),
        "a plain copy has no metadata"
    );
    run(
        &ops,
        req(
            OpKind::Copy,
            FLAG_ALL_METADATA,
            &t.join("s"),
            Some(&t.join("full")),
        ),
    )?;
    run(&ops, req(OpKind::Delete, 0, &t.join("plain"), None))?;
    let calls = meta.0.lock().unwrap().clone();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[0].starts_with("identify ") && calls[0].ends_with("/s"));
    assert!(calls[1].starts_with("copied ") && calls[1].ends_with("/full false"));
    assert!(calls[2].starts_with("removed ") && calls[2].ends_with("/plain false"));
    Ok(())
}

// ---- scheduling: cancel, deadlines, the health gate, bounds -------------------------

#[test]
fn cancel_mid_copy_leaves_no_destination() -> R {
    for engine in engines() {
        let t = TestDir::new("op-cancel")?;
        let ops = start(
            engine,
            OpsConfig {
                no_clone: true,
                cfr_chunk: 1 << 20,
                buf_size: 1 << 20,
                slow: Duration::from_millis(50),
                ..test_cfg()
            },
        )?;
        let src = t.join("big");
        fs::write(&src, pattern(16 << 20, 5))?;
        let dest = t.join("dest");
        let sink = Arc::new(ChanSink::default());
        let ctl = ops
            .submit(req(OpKind::Copy, 0, &src, Some(&dest)), sink.clone())
            .map_err(|e| format!("{e}"))?;
        assert!(
            sink.wait_progress(Duration::from_secs(10)),
            "no progress before cancel"
        );
        let t0 = Instant::now();
        ops.cancel(&ctl);
        let d = sink
            .wait(Duration::from_secs(5))
            .ok_or("no done after cancel")?;
        assert_eq!(d.result, Err(OpError::Cancelled), "{engine:?}");
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "{:?}",
            t0.elapsed()
        );
        assert!(d.progress.bytes_done < 16 << 20, "stopped mid-copy");
        std::thread::sleep(Duration::from_millis(100)); // the worker cleans up after done
        assert!(!dest.exists(), "{engine:?}: no partial destination");
        assert!(no_temp_files(t.path())?, "{engine:?}: temp file removed");
    }
    Ok(())
}

#[test]
fn hung_mounts_are_refused_at_submission_without_a_syscall() -> R {
    let t = TestDir::new("op-gate")?;
    let gate = Arc::new(FakeGate {
        hung: Mutex::new(Some(t.join("hung"))),
        mount: t.path().to_path_buf(),
    });
    let ops = Ops::start(
        test_cfg(),
        EngineKind::Threads,
        gate.clone(),
        Arc::new(NoMeta),
    )?;
    let sink = Arc::new(ChanSink::default());
    let t0 = Instant::now();
    // Nothing exists there: a syscall would say ENOENT, the gate says SuspectMount.
    let r = ops.submit(
        req(OpKind::Copy, 0, &t.join("hung/a"), Some(&t.join("b"))),
        sink.clone(),
    );
    assert!(matches!(r, Err(OpError::SuspectMount)));
    let r = ops.submit(
        req(OpKind::Copy, 0, &t.join("a"), Some(&t.join("hung/b"))),
        sink.clone(),
    );
    assert!(matches!(r, Err(OpError::SuspectMount)));
    let r = ops.submit(
        req(OpKind::DeleteTree, 0, &t.join("hung"), None),
        sink.clone(),
    );
    assert!(matches!(r, Err(OpError::SuspectMount)));
    assert!(t0.elapsed() < Duration::from_millis(10));
    assert!(
        sink.ev.lock().unwrap().done.is_none(),
        "refused ops have no done event"
    );
    // Next to it: fine.
    let (d, _) = run(&ops, req(OpKind::Fsync, 0, t.path(), None))?;
    assert_eq!(d.result, Ok(()));
    Ok(())
}

/// Thread pool only: io_uring opens a FIFO without blocking (and its waits are
/// interruptible, see `uring_waits_stop_on_cancel_even_if_the_kernel_does_not_answer`).
#[test]
fn a_stuck_syscall_times_out_marks_the_mount_and_keeps_the_pool_alive() -> R {
    {
        let engine = EngineKind::Threads;
        let t = TestDir::new("op-stuck")?;
        let gate = Arc::new(FakeGate {
            hung: Mutex::new(None),
            mount: t.path().to_path_buf(),
        });
        let ops = Ops::start(
            OpsConfig {
                workers: 2,
                max_threads: 4,
                ..test_cfg()
            },
            engine,
            gate.clone(),
            Arc::new(NoMeta),
        )?;
        // open(2) of a FIFO without a writer blocks: a stand-in for a hung NFS server.
        let fifo = t.join("fifo");
        let c = CString::new(fifo.as_os_str().as_bytes())?;
        // SAFETY: valid path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let mut r = req(OpKind::Fsync, 0, &fifo, None);
        r.timeout_ms = 300;
        let t0 = Instant::now();
        let (d, _) = run(&ops, r)?;
        assert_eq!(d.result, Err(OpError::TimedOut), "{engine:?}");
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_millis(290) && took < Duration::from_secs(2),
            "{engine:?}: {took:?}"
        );
        // The mount is suspect now: further ops on it are refused at once.
        let sink = Arc::new(ChanSink::default());
        let refused = ops.submit(req(OpKind::Fsync, 0, t.path(), None), sink);
        assert!(matches!(refused, Err(OpError::SuspectMount)), "{engine:?}");
        let (alive, stuck) = ops.threads();
        assert_eq!(stuck, 1, "the worker is still in open(2)");
        assert_eq!(alive - stuck, 2, "a replacement took its place");
        // Unblock the stuck open (a writer appears); its thread then returns to the pool.
        // SAFETY: valid path; non-blocking open succeeds once a reader waits.
        let w = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if w >= 0 {
            // SAFETY: our own fd.
            unsafe { libc::close(w) };
        }
        let t0 = Instant::now();
        while ops.threads().1 != 0 && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(ops.threads().1, 0, "{engine:?}: the stuck worker came back");
    }
    Ok(())
}

#[test]
fn queue_is_bounded_and_queued_ops_can_be_cancelled() -> R {
    let t = TestDir::new("op-queue")?;
    let ops = start(
        EngineKind::Threads,
        OpsConfig {
            workers: 1,
            max_threads: 1,
            queue: 1,
            no_clone: true,
            no_cfr: true,
            buf_size: 64 << 10,
            slow: Duration::from_millis(20),
            ..test_cfg()
        },
    )?;
    fs::write(t.join("s"), pattern(1 << 20, 6))?;
    let s1 = Arc::new(ChanSink::default());
    let a = ops
        .submit(
            req(OpKind::Copy, 0, &t.join("s"), Some(&t.join("d1"))),
            s1.clone(),
        )
        .map_err(|e| format!("{e}"))?;
    assert!(s1.wait_progress(Duration::from_secs(5)), "first op running");
    let s2 = Arc::new(ChanSink::default());
    let b = ops
        .submit(
            req(OpKind::Copy, 0, &t.join("s"), Some(&t.join("d2"))),
            s2.clone(),
        )
        .map_err(|e| format!("{e}"))?;
    let s3 = Arc::new(ChanSink::default());
    let c = ops.submit(req(OpKind::Copy, 0, &t.join("s"), Some(&t.join("d3"))), s3);
    assert!(matches!(c, Err(OpError::Busy)), "queue of 1 is full");
    ops.cancel(&b);
    let d = s2
        .wait(Duration::from_secs(2))
        .ok_or("queued op not cancelled")?;
    assert_eq!(d.result, Err(OpError::Cancelled));
    assert_eq!(d.progress.bytes_done, 0, "it never ran");
    ops.cancel(&a);
    assert_eq!(
        s1.wait(Duration::from_secs(2)).map(|d| d.result),
        Some(Err(OpError::Cancelled))
    );
    Ok(())
}

#[test]
fn deadline_applies_to_queued_and_running_ops() -> R {
    let t = TestDir::new("op-deadline")?;
    let ops = start(
        EngineKind::Threads,
        OpsConfig {
            no_clone: true,
            no_cfr: true,
            buf_size: 64 << 10,
            slow: Duration::from_millis(20),
            ..test_cfg()
        },
    )?;
    fs::write(t.join("s"), pattern(4 << 20, 7))?;
    let mut r = req(OpKind::Copy, 0, &t.join("s"), Some(&t.join("d")));
    r.timeout_ms = 200;
    let t0 = Instant::now();
    let (d, _) = run(&ops, r)?;
    assert_eq!(d.result, Err(OpError::TimedOut));
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    std::thread::sleep(Duration::from_millis(100));
    assert!(!t.join("d").exists());
    assert!(no_temp_files(t.path())?);
    // A slow (but working) worker is not abandoned for a deadline it notices itself.
    assert_eq!(ops.threads().1, 0);
    Ok(())
}

#[test]
fn engine_choice_honours_the_environment_switch() {
    let (k, why) = choose_engine(Some(std::ffi::OsStr::new("1")));
    assert_eq!(k, EngineKind::Threads);
    assert!(why.contains(NO_URING_ENV));
    let (k, why) = choose_engine(Some(std::ffi::OsStr::new("0")));
    match io::probe() {
        Ok(()) => assert_eq!(k, EngineKind::Uring),
        Err(_) => {
            // Without io_uring this fails unless a skip was asked for (RC-F027).
            assert!(!io::uring_for_tests_env("the engine choice"));
            assert_eq!(
                (k, why.starts_with("io_uring unavailable")),
                (EngineKind::Threads, true)
            );
        }
    }
}

struct StopAfter(Instant);

impl Watch for StopAfter {
    fn stopped(&self) -> Option<Stop> {
        (Instant::now() >= self.0).then_some(Stop::TimedOut)
    }
}

/// A read that never completes (an empty pipe whose write end stays open, like a dead
/// server): the io_uring engine notices the stop within a wait slice, cancels the
/// request, and stays usable; the cancel never takes the engine down with it.
#[test]
fn uring_waits_stop_on_cancel_even_if_the_kernel_does_not_answer() -> R {
    if !engines().contains(&EngineKind::Uring) {
        return Ok(());
    }
    let mut fds = [0i32; 2];
    // SAFETY: a two-element array for the pipe fds.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: fresh fds owned by nobody else.
    let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let mut u = UringIo::new(4096)?;
    let t0 = Instant::now();
    let w = StopAfter(t0 + Duration::from_millis(150));
    let r = u.read(&w, rd.as_raw_fd(), 16, 0);
    let took = t0.elapsed();
    assert_eq!(r, Err(StepError::Stop(Stop::TimedOut)));
    assert!(
        took >= Duration::from_millis(140) && took < Duration::from_millis(600),
        "{took:?}"
    );
    if u.healthy() {
        // Still works after the cancel.
        let t = TestDir::new("op-uring")?;
        fs::write(t.join("f"), b"hello")?;
        let c = CString::new(t.join("f").as_os_str().as_bytes())?;
        let never = StopAfter(Instant::now() + Duration::from_secs(3600));
        let fd = u
            .open(&never, libc::AT_FDCWD, &c, libc::O_RDONLY, 0)
            .map_err(OpError::from)?;
        assert_eq!(u.read(&never, fd.as_raw_fd(), 16, 0), Ok(5));
    } else {
        eprintln!("note: the kernel did not cancel the read; the engine was abandoned (by design)");
    }
    drop(wr);
    Ok(())
}

// ---- review: delete-tree must stay inside its own mount and report only what it deleted

/// Run the named test again in a fresh user+mount namespace (`unshare -rm`), where it
/// may bind-mount. Returns true in the inner run; false (the outer run is done: passed,
/// or skipped, with a SKIP line, where namespaces are not available) otherwise. A failed
/// inner run's output is part of the error.
fn in_mount_namespace(test: &str) -> R<bool> {
    const INNER: &str = "GUNGNIR_TEST_IN_MOUNT_NS";
    if std::env::var_os(INNER).is_some() {
        return Ok(true);
    }
    let usable = std::process::Command::new("unshare")
        .args(["-rm", "true"])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    // Straight to stderr, not eprintln!: the harness swallows that for passing tests.
    let say = |line: &str| {
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    };
    if !usable {
        say(&format!(
            "SKIP: no user+mount namespace here: {test} did not run"
        ));
        return Ok(false);
    }
    let out = std::process::Command::new("unshare")
        .arg("-rm")
        .arg(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(INNER, "1")
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The inner run's own SKIP lines (an io_uring half skipped on purpose) must show.
    text.lines().filter(|l| l.starts_with("SKIP")).for_each(say);
    if !out.status.success() {
        return Err(format!(
            "{test} failed inside its mount namespace ({}):\n{text}",
            out.status
        )
        .into());
    }
    Ok(false)
}

/// Unmounts on drop (before the TestDir holding it is removed).
struct Mount(CString);

impl Mount {
    fn bind(src: &Path, dst: &Path) -> R<Self> {
        let (s, d) = (
            CString::new(src.as_os_str().as_bytes())?,
            CString::new(dst.as_os_str().as_bytes())?,
        );
        // SAFETY: valid NUL-terminated paths; a bind mount takes no fstype or data.
        let r = unsafe {
            libc::mount(
                s.as_ptr(),
                d.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if r != 0 {
            return Err(format!("bind mount: {}", std::io::Error::last_os_error()).into());
        }
        Ok(Self(d))
    }
}

impl Mount {
    /// A fresh tmpfs at `dst` (a second filesystem).
    fn tmpfs(dst: &Path) -> R<Self> {
        let d = CString::new(dst.as_os_str().as_bytes())?;
        // SAFETY: valid NUL-terminated strings.
        let r = unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                d.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if r != 0 {
            return Err(format!("tmpfs mount: {}", std::io::Error::last_os_error()).into());
        }
        Ok(Self(d))
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        // SAFETY: valid path.
        unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
    }
}

/// A bind mount of a directory of the SAME filesystem has the tree's `st_dev`, so an
/// `st_dev` comparison does not see it. delete-tree must stop there all the same: what
/// is below it lives outside the tree (here: in `outside/`).
#[test]
fn delete_tree_never_descends_into_a_bind_mount_of_the_same_filesystem() -> R {
    if !in_mount_namespace(
        "ops::tests::delete_tree_never_descends_into_a_bind_mount_of_the_same_filesystem",
    )? {
        return Ok(());
    }
    for engine in engines() {
        let t = TestDir::new("op-bind")?;
        let ops = start(engine, test_cfg())?;
        let outside = t.join("outside");
        fs::create_dir_all(outside.join("deep"))?;
        fs::write(outside.join("precious"), b"p")?;
        fs::write(outside.join("deep/precious2"), b"p")?;
        let root = t.join("tree");
        fs::create_dir_all(root.join("sub/bind"))?;
        fs::write(root.join("sub/f"), b"x")?;
        let m = Mount::bind(&outside, &root.join("sub/bind"))?;
        assert_eq!(
            fs::metadata(root.join("sub/bind"))?.dev(),
            fs::metadata(&root)?.dev(),
            "the bind mount shares st_dev with the tree"
        );
        let (d, _) = run(&ops, req(OpKind::DeleteTree, 0, &root, None))?;
        assert!(
            outside.join("precious").exists() && outside.join("deep/precious2").exists(),
            "{engine:?}: delete-tree deleted files outside the tree through a bind mount"
        );
        assert_eq!(os(&d), Some(libc::EXDEV), "{engine:?}: {:?}", d.result);
        drop(m);
    }
    Ok(())
}

/// A path through a symlinked parent on another mount is not a mount-point root.
#[test]
fn delete_tree_works_through_a_symlinked_parent_on_another_mount() -> R {
    if !in_mount_namespace(
        "ops::tests::delete_tree_works_through_a_symlinked_parent_on_another_mount",
    )? {
        return Ok(());
    }
    for engine in engines() {
        let t = TestDir::new("op-linkparent")?;
        let ops = start(engine, test_cfg())?;
        let (real, mounted) = (t.join("real"), t.join("mounted"));
        fs::create_dir_all(real.join("tree/sub"))?;
        fs::write(real.join("tree/sub/f"), b"x")?;
        fs::create_dir(&mounted)?;
        let m = Mount::bind(&real, &mounted)?;
        std::os::unix::fs::symlink(&mounted, t.join("link"))?;
        let (d, _) = run(&ops, req(OpKind::DeleteTree, 0, &t.join("link/tree"), None))?;
        assert_eq!(d.result, Ok(()), "{engine:?}");
        assert!(!real.join("tree").exists(), "{engine:?}");
        drop(m);
    }
    Ok(())
}

/// A root that is itself a mount point: nothing on it is deleted, EXDEV (DIB-F001).
#[test]
fn delete_tree_refuses_a_root_that_is_a_mount_point() -> R {
    if !in_mount_namespace("ops::tests::delete_tree_refuses_a_root_that_is_a_mount_point")? {
        return Ok(());
    }
    for engine in engines() {
        let t = TestDir::new("op-bindroot")?;
        let ops = start(engine, test_cfg())?;
        let outside = t.join("outside");
        fs::create_dir_all(outside.join("deep"))?;
        fs::write(outside.join("deep/precious"), b"p")?;
        let root = t.join("mounted");
        fs::create_dir(&root)?;
        let m = Mount::bind(&outside, &root)?;
        let (d, _) = run(&ops, req(OpKind::DeleteTree, 0, &root, None))?;
        assert_eq!(os(&d), Some(libc::EXDEV), "{engine:?}: {:?}", d.result);
        assert!(outside.join("deep/precious").exists(), "{engine:?}");
        drop(m);
    }
    Ok(())
}

/// A delete-tree that fails part-way (here: deeper than MAX_DEPTH) must not report the
/// whole tree as removed: files it never deleted keep their metadata.
#[test]
fn a_failed_delete_tree_reports_only_what_it_deleted() -> R {
    for engine in engines() {
        let t = TestDir::new("op-partial")?;
        let meta = Arc::new(RecMeta::default());
        let ops = Ops::start(test_cfg(), engine, Arc::new(NoGate), meta.clone())?;
        let root = t.join("tree");
        fs::create_dir(&root)?;
        let gone = root.join("gone");
        fs::write(&gone, b"x")?;
        let mut d_name = "d0".to_string();
        let mut d_path = root.join(&d_name);
        fs::create_dir(&d_path)?;

        // Ensure `gone` is returned by readdir before the deep directory on any filesystem
        // (btrfs is creation-order FIFO; tmpfs is LIFO; ext4 is hash-based).
        let first_entry = |dir: &Path| -> std::io::Result<Option<std::ffi::OsString>> {
            Ok(fs::read_dir(dir)?
                .next()
                .transpose()?
                .map(|e| e.file_name()))
        };
        if first_entry(&root)?.as_deref() != Some(std::ffi::OsStr::new("gone")) {
            // On tmpfs / LIFO filesystems, recreating `gone` makes it the newest entry.
            fs::remove_file(&gone)?;
            fs::write(&gone, b"x")?;
        }
        let mut counter = 1;
        while first_entry(&root)?.as_deref() != Some(std::ffi::OsStr::new("gone")) {
            // For hash-based ordering (like ext4 dir_index), rotate candidate directory names
            // until `gone` sorts before the directory.
            fs::remove_dir(&d_path)?;
            d_name = format!("d{counter}");
            d_path = root.join(&d_name);
            fs::create_dir(&d_path)?;
            counter += 1;
        }

        let mut deep = d_path;
        for i in 1..MAX_DEPTH {
            deep.push(format!("d{i}"));
        }
        fs::create_dir_all(&deep)?;
        let survivor = deep.join("survivor");
        fs::write(&survivor, b"s")?;
        let (d, _) = run(&ops, req(OpKind::DeleteTree, 0, &root, None))?;
        assert_eq!(os(&d), Some(libc::ELOOP), "{engine:?}: {:?}", d.result);
        assert!(survivor.exists() && !root.join("gone").exists());
        let calls = meta.0.lock().unwrap().clone();
        let s = survivor.to_string_lossy().into_owned();
        for c in &calls {
            let Some(rest) = c.strip_prefix("removed ") else {
                continue;
            };
            let (p, tree) = rest.rsplit_once(' ').unwrap_or((rest, "false"));
            let covers = p == s || (tree == "true" && s.starts_with(&format!("{p}/")));
            assert!(!covers, "{engine:?}: `{c}` drops the survivor's metadata");
        }
        let g = format!("removed {} false", root.join("gone").display());
        assert!(
            calls.contains(&g),
            "{engine:?}: deleted file not reported: {calls:?}"
        );
        // Clean up what is left (deeper than MAX_DEPTH: by path, from the bottom).
        fs::remove_file(&survivor)?;
        let mut p = deep;
        while p != root {
            fs::remove_dir(&p)?;
            p.pop();
        }
    }
    Ok(())
}

/// A trash-style directory re-aimed at another one after its descriptor was taken.
fn swapped_dir(t: &TestDir) -> R<(Anchor, PathBuf, PathBuf)> {
    let files = t.join("files");
    let (old, other) = (t.join("old"), t.join("other"));
    fs::create_dir(&files)?;
    fs::create_dir(&other)?;
    fs::write(files.join("e"), b"item")?;
    fs::write(other.join("e"), b"precious")?;
    let dir = OwnedFd::from(fs::OpenOptions::new().read(true).open(&files)?);
    fs::rename(&files, &old)?;
    std::os::unix::fs::symlink(&other, &files)?;
    let a = Anchor {
        dir: Arc::new(dir),
        leaf: CString::new("e")?,
    };
    Ok((a, files.join("e"), other.join("e")))
}

/// REV-3: an anchored delete acts on the checked directory, not on what the path became.
#[test]
fn an_anchored_delete_ignores_a_swapped_path() -> R {
    for engine in engines() {
        let t = TestDir::new("op-anchor-del")?;
        let ops = start(engine, test_cfg())?;
        let (a, src, other) = swapped_dir(&t)?;
        let mut r = req(OpKind::DeleteTree, 0, &src, None);
        r.src_at = Some(a);
        let (d, _) = run(&ops, r)?;
        assert!(d.result.is_ok(), "{engine:?}: {:?}", d.result);
        assert_eq!(fs::read(&other)?, b"precious", "{engine:?}");
        assert!(!t.join("old/e").exists(), "{engine:?}");
    }
    Ok(())
}

/// REV-3: the same for a move, by rename and through the copy fallback.
#[test]
fn an_anchored_move_ignores_a_swapped_path() -> R {
    for engine in engines() {
        for force_exdev in [false, true] {
            let t = TestDir::new("op-anchor-mv")?;
            let mut cfg = test_cfg();
            cfg.force_exdev = force_exdev;
            let ops = start(engine, cfg)?;
            let (a, src, other) = swapped_dir(&t)?;
            let landed = t.join("landed");
            let mut r = req(OpKind::Move, 0, &src, Some(&landed));
            r.src_at = Some(a);
            let (d, _) = run(&ops, r)?;
            assert!(d.result.is_ok(), "{engine:?}: {:?}", d.result);
            assert_eq!(fs::read(&landed)?, b"item", "{engine:?}");
            assert_eq!(fs::read(&other)?, b"precious", "{engine:?}");
            assert!(!t.join("old/e").exists(), "{engine:?}");
        }
    }
    Ok(())
}

/// REV-3: the destination too: the file lands where the descriptor points.
#[test]
fn an_anchored_destination_ignores_a_swapped_path() -> R {
    for engine in engines() {
        let t = TestDir::new("op-anchor-to")?;
        let ops = start(engine, test_cfg())?;
        let (a, swapped, _) = swapped_dir(&t)?;
        let from = t.join("from");
        fs::write(&from, b"new")?;
        fs::remove_file(t.join("old/e"))?;
        let mut r = req(OpKind::Move, 0, &from, Some(&swapped));
        r.dest_at = Some(a);
        let (d, _) = run(&ops, r)?;
        assert!(d.result.is_ok(), "{engine:?}: {:?}", d.result);
        assert_eq!(fs::read(t.join("old/e"))?, b"new", "{engine:?}");
        assert_eq!(fs::read(t.join("other/e"))?, b"precious", "{engine:?}");
    }
    Ok(())
}

/// REV-4: same inode, but opened through a mount that appeared after the first look.
#[test]
fn a_root_bound_over_itself_counts_as_another_mount() {
    // SAFETY: an all-zero statx is valid.
    let mut before: libc::statx = unsafe { std::mem::zeroed() };
    before.stx_mask = libc::STATX_MNT_ID;
    before.stx_mnt_id = 7;
    let mut after = before;
    assert!(!other_mount(&before, &after));
    after.stx_mnt_id = 8;
    assert!(same_file(&before, &after) && other_mount(&before, &after));
    let mut root = before;
    root.stx_attributes_mask = libc::STATX_ATTR_MOUNT_ROOT as u64;
    root.stx_attributes = libc::STATX_ATTR_MOUNT_ROOT as u64;
    assert!(other_mount(&before, &root));
}

/// REV2-2: the no-replace path of a filesystem without RENAME_NOREPLACE.
#[test]
fn no_replace_without_kernel_support_never_replaces() -> R {
    for engine in engines() {
        let t = TestDir::new("op-noreplace")?;
        let mut cfg = test_cfg();
        cfg.force_no_noreplace = true;
        let ops = start(engine, cfg)?;
        let (src, dest) = (t.join("s"), t.join("d"));
        fs::write(&src, b"new")?;
        fs::write(&dest, b"precious")?;
        let (d, _) = run(&ops, req(OpKind::Move, 0, &src, Some(&dest)))?;
        assert_eq!(os(&d), Some(libc::EEXIST), "{engine:?}: {:?}", d.result);
        assert_eq!(fs::read(&dest)?, b"precious", "{engine:?}");
        assert_eq!(fs::read(&src)?, b"new", "{engine:?}");
        fs::remove_file(&dest)?;
        let (d, _) = run(&ops, req(OpKind::Move, 0, &src, Some(&dest)))?;
        assert!(d.result.is_ok(), "{engine:?}: {:?}", d.result);
        assert_eq!(fs::read(&dest)?, b"new", "{engine:?}");
        assert!(!src.exists(), "{engine:?}");
    }
    Ok(())
}

/// REV2-9: an anchored destination is rename-only, and a refused move loses nothing.
#[test]
fn an_anchored_destination_never_falls_back_to_a_copy() -> R {
    for engine in engines() {
        let t = TestDir::new("op-anchor-exdev")?;
        let mut cfg = test_cfg();
        cfg.force_exdev = true;
        let ops = start(engine, cfg)?;
        let (a, swapped, _) = swapped_dir(&t)?;
        let from = t.join("from");
        fs::write(&from, b"new")?;
        fs::remove_file(t.join("old/e"))?;
        let mut r = req(OpKind::Move, 0, &from, Some(&swapped));
        r.dest_at = Some(a);
        let (d, _) = run(&ops, r)?;
        assert_eq!(os(&d), Some(libc::EXDEV), "{engine:?}: {:?}", d.result);
        assert_eq!(fs::read(&from)?, b"new", "{engine:?}");
    }
    Ok(())
}

/// REV2-6: the sweep is off startup's path, and still does its work.
#[test]
fn the_detached_sweep_moves_the_ledger_aside_and_sweeps() -> R {
    let t = TestDir::new("op-detach")?;
    let ledger = t.join("ops-pending");
    let dest = t.join("dest");
    let tmp = t.join(".gungnir-00000000000000ab-0.tmp");
    fs::write(&tmp, b"x")?;
    fs::write(&ledger, ledger_start(0xab, &b(&dest)))?;
    detach_temp_sweep(&ledger)?;
    assert!(!ledger.exists());
    let aside = ledger.with_extension("sweep");
    let t0 = std::time::Instant::now();
    while (tmp.exists() || aside.exists()) && t0.elapsed() < Duration::from_secs(10) {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!tmp.exists() && !aside.exists());
    Ok(())
}

/// REV2-6: a run's op ids cannot collide with the last run's temp names.
#[test]
fn op_ids_differ_between_runs() {
    assert_ne!(first_op_id(), first_op_id());
}

/// REV4: abandoned ops' entries live in their own file, and the next start sweeps them.
#[test]
fn the_kept_file_is_swept_at_the_next_start() -> R {
    let t = TestDir::new("op-kept")?;
    let ledger = t.join("ops-pending");
    let tmp = t.join(".gungnir-00000000000000cd-0.tmp");
    fs::write(&tmp, b"x")?;
    fs::write(
        ledger.with_extension("kept"),
        ledger_start(0xcd, &b(&t.join("dest"))),
    )?;
    detach_temp_sweep(&ledger)?;
    assert!(!ledger.with_extension("kept").exists());
    let t0 = std::time::Instant::now();
    while tmp.exists() && t0.elapsed() < Duration::from_secs(10) {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!tmp.exists());
    Ok(())
}

/// REV4: an EXDEV move of a symlink copies the link it examined.
#[test]
fn a_symlink_moves_across_devices_intact() -> R {
    for engine in engines() {
        let t = TestDir::new("op-link-mv")?;
        let mut cfg = test_cfg();
        cfg.force_exdev = true;
        let ops = start(engine, cfg)?;
        let (src, dest) = (t.join("l"), t.join("m"));
        std::os::unix::fs::symlink("target", &src)?;
        let (d, _) = run(&ops, req(OpKind::Move, 0, &src, Some(&dest)))?;
        assert!(d.result.is_ok(), "{engine:?}: {:?}", d.result);
        assert_eq!(fs::read_link(&dest)?, Path::new("target"), "{engine:?}");
        assert!(fs::symlink_metadata(&src).is_err(), "{engine:?}");
    }
    Ok(())
}

/// A long flush is no stall: the limit that would stop a copy leaves an fsync alone.
#[test]
fn a_slow_fsync_is_not_a_stall() -> R {
    for engine in engines() {
        let t = TestDir::new("op-flush")?;
        let mut cfg = test_cfg();
        cfg.stall = Duration::from_millis(100);
        cfg.grace = Duration::from_millis(50);
        cfg.fsync_delay = Duration::from_millis(600);
        let ops = start(engine, cfg)?;
        let f = t.join("f");
        fs::write(&f, b"x")?;
        let (d, _) = run(&ops, req(OpKind::Fsync, 0, &f, None))?;
        assert!(d.result.is_ok(), "{engine:?}: {:?}", d.result);
    }
    Ok(())
}

/// SEC-R-014 / DIR-C1-F01 fixture: `<t>/parent/dest` is a partial tree copy (op 0xe1)
/// with a temp file in `dest/sub`; `<t>/outside` holds a lookalike temp file the sweep
/// must never reach. Directory listing order: 1 parent, 2 dest, 3 dest/sub.
struct SwapFixture {
    t: TestDir,
    ledger: PathBuf,
    sub: PathBuf,
    lookalike: PathBuf,
}

const SWAP_TEMP: &str = ".gungnir-00000000000000e1-0.tmp";

fn swap_fixture(name: &str) -> R<SwapFixture> {
    let t = TestDir::new(name)?;
    let dest = t.join("parent/dest");
    let sub = dest.join("sub");
    fs::create_dir_all(&sub)?;
    fs::create_dir(t.join("outside"))?;
    fs::write(sub.join(SWAP_TEMP), b"partial copy")?;
    let lookalike = t.join("outside").join(SWAP_TEMP);
    fs::write(&lookalike, b"user data")?;
    let ledger = t.join("ops-pending");
    fs::write(&ledger, ledger_start(0xe1, &b(&dest)))?;
    Ok(SwapFixture {
        t,
        ledger,
        sub,
        lookalike,
    })
}

impl SwapFixture {
    /// Replace `dest/sub` by a symlink to `outside`, keeping the real directory aside.
    fn swap(&self) {
        let aside = self.sub.with_file_name("sub.real");
        fs::rename(&self.sub, aside).expect("move sub aside");
        std::os::unix::fs::symlink(self.t.join("outside"), &self.sub).expect("symlink sub");
    }
}

/// SEC-R-014: a directory swapped for a symlink after it was listed, before the sweep
/// descends into it, must not lead the sweep outside the destination tree.
#[test]
fn the_sweep_does_not_descend_into_a_directory_swapped_for_a_symlink() -> R {
    let f = swap_fixture("op-sweep-swap-descend")?;
    let removed = sweep_temp_ledger_with(&f.ledger, &mut |p| {
        if p == SweepPoint::Open(3) {
            f.swap();
        }
    })?;
    assert_eq!(
        fs::read(&f.lookalike)?,
        b"user data",
        "the sweep followed a swapped-in symlink out of the destination"
    );
    assert_eq!(removed, 0);
    Ok(())
}

/// SEC-R-014: a directory swapped for a symlink after its entries were listed, before the
/// temp file in it is unlinked: the unlink must hit the directory that was listed.
#[test]
fn the_sweep_unlinks_in_the_directory_it_listed_not_through_a_swapped_path() -> R {
    let f = swap_fixture("op-sweep-swap-unlink")?;
    let removed = sweep_temp_ledger_with(&f.ledger, &mut |p| {
        if p == SweepPoint::Listed(3) {
            f.swap();
        }
    })?;
    assert_eq!(
        fs::read(&f.lookalike)?,
        b"user data",
        "the sweep unlinked through a swapped-in symlink"
    );
    let moved_temp = f.sub.with_file_name("sub.real").join(SWAP_TEMP);
    assert!(!moved_temp.exists(), "the listed temp file was not removed");
    assert_eq!(removed, 1);
    Ok(())
}

/// SEC-R-014: without any race, the anchored sweep removes exactly the op's temp files,
/// next to the destination and anywhere below it, and nothing else; it does not follow
/// a symlink inside the tree, nor remove a directory with a temp-file name.
#[test]
fn the_sweep_removes_only_the_ops_temp_files() -> R {
    let t = TestDir::new("op-sweep-only-ours")?;
    let parent = t.join("parent");
    let dest = parent.join("dest");
    fs::create_dir_all(dest.join("a/b/c"))?;
    fs::create_dir(t.join("outside"))?;
    let ours = [
        parent.join(".gungnir-00000000000000e2-0.tmp"),
        dest.join(".gungnir-00000000000000e2-1.tmp"),
        dest.join("a/b/c/.gungnir-00000000000000e2-7.tmp"),
    ];
    let keep = [
        parent.join(".gungnir-00000000000000e3-0.tmp"), // another op's (it ended)
        dest.join("a/.gungnir-00000000000000e2-0.txt"),
        dest.join("a/b/gungnir-00000000000000e2-0.tmp"),
        dest.join("a/b/c/file"),
        t.join("outside").join(".gungnir-00000000000000e2-0.tmp"),
    ];
    for p in ours.iter().chain(keep.iter()) {
        fs::write(p, b"x")?;
    }
    let dir_named_like_temp = dest.join(".gungnir-00000000000000e2-9.tmp");
    fs::create_dir(&dir_named_like_temp)?;
    std::os::unix::fs::symlink(t.join("outside"), dest.join("a/link"))?;
    let ledger = t.join("ops-pending");
    let mut text = ledger_start(0xe2, &b(&dest));
    text.extend(ledger_start(0xe3, &b(&parent.join("other"))));
    text.extend(ledger_end(0xe3));
    fs::write(&ledger, text)?;
    let removed = sweep_temp_ledger(&ledger)?;
    for p in &ours {
        assert!(!p.exists(), "not swept: {}", p.display());
    }
    for p in &keep {
        assert!(p.exists(), "swept but not ours: {}", p.display());
    }
    assert!(dir_named_like_temp.is_dir());
    assert_eq!(removed, ours.len());
    assert_eq!(fs::metadata(&ledger)?.len(), 0, "the ledger is emptied");
    Ok(())
}

/// F6: a delete-tree deeper than TREE_OPEN_MAX closes its shallow levels and reopens them
/// by name on the way back. A level swapped for a symlink to another tree meanwhile is
/// never followed: the op fails and the other tree is untouched, on both engines.
#[test]
fn a_reopened_level_swapped_for_a_symlink_is_never_followed() -> R {
    for engine in engines() {
        let t = TestDir::new("op-deltree-swap")?;
        let root = t.join("root");
        let mut p = root.join("l1");
        for i in 1..=12 {
            fs::create_dir_all(&p)?;
            fs::write(p.join(format!("f{i}")), b"x")?;
            p.push(format!("l{}", i + 1));
        }
        let outside = t.join("outside");
        fs::create_dir_all(outside.join("l2"))?;
        fs::write(outside.join("keep"), b"user data")?;
        fs::write(outside.join("l2/keep2"), b"user data")?;
        let mut cfg = test_cfg();
        cfg.slow = Duration::from_millis(40);
        let ops = start(engine, cfg)?;
        let swapper = {
            let (l1, moved, outside) = (root.join("l1"), root.join("l1.moved"), outside.clone());
            thread::spawn(move || {
                // The walk has gone deep by now; l1 is closed or about to be.
                thread::sleep(Duration::from_millis(900));
                fs::rename(&l1, moved).expect("move l1 aside");
                std::os::unix::fs::symlink(outside, l1).expect("symlink l1");
            })
        };
        let (d, _) = run(&ops, req(OpKind::DeleteTree, 0, &root, None))?;
        let _ = swapper.join();
        assert!(
            d.result.is_err(),
            "{engine:?}: the swapped tree was deleted: {:?}",
            d.result
        );
        assert_eq!(fs::read(outside.join("keep"))?, b"user data", "{engine:?}");
        assert_eq!(
            fs::read(outside.join("l2/keep2"))?,
            b"user data",
            "{engine:?}"
        );
    }
    Ok(())
}
