//! The trash and recent rules as a client sees them, in process: the service's own
//! session over an in-memory port, the same wire encoding as the socket, no daemon
//! process, no sandbox. `tests/trash_ipc.rs` keeps what needs the real daemon: the
//! sandbox (one smoke test of every operation), lost clients, request bounds, hung,
//! FUSE, btrfs and bind mounts, another user, the fuzzer.

use std::{
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::Path,
};

use super::*;
use crate::{
    ipc::{Msg, Port, Session, Shm},
    ops::{NoGate, NoMeta, OpsConfig, io::EngineKind},
    testdir::TestDir,
};

type R<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// An empty mount table: only the test's own volumes exist.
struct NoMounts;

impl MountTable for NoMounts {
    fn read(&self) -> std::io::Result<Vec<MountEntry>> {
        Ok(Vec::new())
    }
}

/// A client of one trash service, in process.
struct Local {
    session: Box<dyn Session>,
    port: Arc<Port>,
    seq: u64,
    _shm: OwnedFd,
}

/// The service over `d` (home `d`, data `d/data`) on `engine`, plus the volume `top`.
fn local(d: &TestDir, engine: EngineKind, top: Option<&Path>) -> R<Local> {
    let ops = Ops::start(
        OpsConfig::default(),
        engine,
        Arc::new(NoGate),
        Arc::new(NoMeta),
    )?;
    let svc = Svc::new(
        Arc::new(ops),
        SvcConfig {
            xdg_data: Some(d.join("data").into_os_string()),
            home: Some(d.path().as_os_str().to_owned()),
            // SAFETY: plain getter.
            uid: unsafe { libc::geteuid() },
            extra_tops: top.map(Path::to_path_buf).into_iter().collect(),
            host_subvols: false,
            mounts: Box::new(NoMounts),
        },
    );
    let (shm, fd) = Shm::create()?;
    Ok(Local {
        session: VfsService::new(svc).session(),
        port: Arc::new(Port::for_test(shm)),
        seq: 0,
        _shm: fd,
    })
}

/// Both engines; io_uring only where it works (or the test fails, AGENTS.md skip policy).
fn engines() -> Vec<EngineKind> {
    let mut e = vec![EngineKind::Threads];
    if crate::ops::io::uring_for_tests_env("the in-process trash tests on io_uring") {
        e.push(EngineKind::Uring);
    }
    e
}

fn call(c: &mut Local, kind: u32, payload: &[u8]) -> R<(u32, Vec<u8>)> {
    c.seq += 1;
    let seq = c.seq;
    c.session
        .request(&c.port, &Msg::for_test(kind, seq, payload));
    let t0 = Instant::now();
    loop {
        // Beats and replies to other requests are skipped, as a client does.
        while let Some(m) = c.port.take_reply() {
            if m.kind == MSG_REPLY && m.seq == seq {
                let p = m.payload();
                return Ok((u32::from_le_bytes(p[..4].try_into()?), p[4..].to_vec()));
            }
        }
        if t0.elapsed() > Duration::from_secs(70) {
            return Err("no reply in time".into());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

#[derive(Debug)]
struct Row {
    name: Vec<u8>,
    orig: Vec<u8>,
    kind: u8,
}

fn str16(b: &mut &[u8]) -> Vec<u8> {
    let n = usize::from(u16::from_le_bytes([b[0], b[1]]));
    let s = b[2..2 + n].to_vec();
    *b = &b[2 + n..];
    s
}

fn list(c: &mut Local, scheme: u8) -> R<Vec<Row>> {
    let mut out = Vec::new();
    let mut cursor = 0u32;
    loop {
        let mut p = vec![scheme];
        p.extend_from_slice(&cursor.to_le_bytes());
        let (st, body) = call(c, MSG_VFS_LIST, &p)?;
        assert_eq!(st, ST_OK, "list");
        let next = u32::from_le_bytes(body[..4].try_into()?);
        let n = u16::from_le_bytes(body[4..6].try_into()?);
        let mut b = &body[7..];
        for _ in 0..n {
            let name = str16(&mut b);
            let orig = str16(&mut b);
            let _target = str16(&mut b);
            let _deleted = str16(&mut b);
            let _link = str16(&mut b);
            let kind = b[0];
            b = &b[17..];
            out.push(Row { name, orig, kind });
        }
        if next == 0 {
            return Ok(out);
        }
        cursor = next;
    }
}

fn len16(s: &[u8]) -> Vec<u8> {
    let mut v = (s.len() as u16).to_le_bytes().to_vec();
    v.extend_from_slice(s);
    v
}

fn delete(c: &mut Local, scheme: u8, name: &[u8]) -> R<u32> {
    let mut p = vec![scheme];
    p.extend(len16(name));
    Ok(call(c, MSG_VFS_DELETE, &p)?.0)
}

fn restore(c: &mut Local, name: &[u8], dest: &[u8]) -> R<u32> {
    let mut p = len16(name);
    p.extend(len16(dest));
    Ok(call(c, MSG_VFS_RESTORE, &p)?.0)
}

fn trash_dir(d: &TestDir) -> R<PathBuf> {
    let t = d.join("data/Trash");
    fs::create_dir_all(t.join("files"))?;
    fs::create_dir_all(t.join("info"))?;
    Ok(t)
}

fn trashed(t: &Path, e: &str, orig: &Path) -> R {
    fs::write(t.join("files").join(e), b"payload")?;
    fs::write(
        t.join("info").join(format!("{e}.trashinfo")),
        format!(
            "[Trash Info]\nPath={}\nDeletionDate=2026-10-31T10:00:00\n",
            orig.display()
        ),
    )?;
    Ok(())
}

fn volume_trash(vol: &Path) -> R<PathBuf> {
    // SAFETY: plain getter.
    let vt = vol.join(format!(".Trash-{}", unsafe { libc::geteuid() }));
    fs::create_dir_all(vt.join("files"))?;
    fs::create_dir_all(vt.join("info"))?;
    Ok(vt)
}

#[test]
fn listing_restoring_and_deleting() -> R {
    for engine in engines() {
        let d = TestDir::new("loc-basic")?;
        let t = trash_dir(&d)?;
        let back = d.join("restored");
        trashed(&t, "keep", &back)?;
        trashed(&t, "drop", &d.join("gone"))?;
        fs::create_dir_all(t.join("files/tree/sub"))?;
        fs::write(t.join("files/tree/sub/f"), b"x")?;
        fs::write(
            t.join("info/tree.trashinfo"),
            "[Trash Info]\nPath=/x/tree\n",
        )?;
        let mut c = local(&d, engine, None)?;
        let rows = list(&mut c, SCHEME_TRASH)?;
        assert_eq!(rows.len(), 3, "{rows:?}");
        let name = |e: &str| format!("h-{e}").into_bytes();
        assert!(rows.iter().any(|r| r.name == name("tree") && r.kind == 2));
        let keep = rows.iter().find(|r| r.name == name("keep")).ok_or("keep")?;
        assert_eq!(keep.orig, back.as_os_str().as_bytes());

        assert_eq!(restore(&mut c, &name("keep"), b"")?, ST_OK);
        assert_eq!(fs::read(&back)?, b"payload");
        assert!(!t.join("info/keep.trashinfo").exists());
        assert!(!t.join("files/keep").exists());

        assert_eq!(delete(&mut c, SCHEME_TRASH, &name("drop"))?, ST_OK);
        assert_eq!(delete(&mut c, SCHEME_TRASH, &name("tree"))?, ST_OK);
        assert!(!t.join("files/tree").exists() && !t.join("info/tree.trashinfo").exists());
        assert_eq!(delete(&mut c, SCHEME_TRASH, &name("drop"))?, ST_NOT_FOUND);
        assert!(list(&mut c, SCHEME_TRASH)?.is_empty());
    }
    Ok(())
}

/// Restoring never replaces what is at the destination, and the item stays.
#[test]
fn a_restore_onto_an_existing_file_keeps_both() -> R {
    let d = TestDir::new("loc-noclobber")?;
    let t = trash_dir(&d)?;
    let there = d.join("there");
    fs::write(&there, b"newer")?;
    trashed(&t, "e", &there)?;
    let mut c = local(&d, EngineKind::Threads, None)?;
    assert_ne!(restore(&mut c, b"h-e", b"")?, ST_OK);
    assert_eq!(fs::read(&there)?, b"newer");
    assert_eq!(list(&mut c, SCHEME_TRASH)?.len(), 1);
    Ok(())
}

/// BC-T005-F1: with a non-empty directory at the info path nothing is touched.
#[test]
fn an_item_whose_info_cannot_go_keeps_its_payload() -> R {
    let d = TestDir::new("loc-infodir")?;
    let t = trash_dir(&d)?;
    fs::write(t.join("files/e"), b"payload")?;
    fs::create_dir_all(t.join("info/e.trashinfo/x"))?;
    let mut c = local(&d, EngineKind::Threads, None)?;
    assert_ne!(delete(&mut c, SCHEME_TRASH, b"h-e")?, ST_OK);
    assert!(t.join("files/e").exists());
    assert_eq!(list(&mut c, SCHEME_TRASH)?.len(), 1);
    Ok(())
}

/// F05: a symlink at Trash/files never aims a delete anywhere.
#[test]
fn a_symlinked_files_directory_is_never_followed() -> R {
    let d = TestDir::new("loc-link")?;
    let t = d.join("data/Trash");
    fs::create_dir_all(t.join("info"))?;
    let elsewhere = d.join("elsewhere");
    fs::create_dir(&elsewhere)?;
    fs::write(elsewhere.join("precious"), b"p")?;
    std::os::unix::fs::symlink(&elsewhere, t.join("files"))?;
    fs::write(t.join("info/precious.trashinfo"), "[Trash Info]\nPath=/p\n")?;
    let mut c = local(&d, EngineKind::Threads, None)?;
    assert!(list(&mut c, SCHEME_TRASH)?.is_empty());
    assert_ne!(delete(&mut c, SCHEME_TRASH, b"h-precious")?, ST_OK);
    let (st, _) = call(&mut c, MSG_TRASH_EMPTY, &[])?;
    assert_ne!(st, ST_OK);
    assert!(elsewhere.join("precious").exists());
    Ok(())
}

/// REV-1: a trash that cannot be used is not an empty trash.
#[test]
fn empty_does_not_report_success_past_an_unusable_trash() -> R {
    let d = TestDir::new("loc-rev1")?;
    let t = d.join("data/Trash");
    fs::create_dir_all(t.join("info"))?;
    let elsewhere = d.join("elsewhere");
    fs::create_dir(&elsewhere)?;
    fs::write(elsewhere.join("kept"), b"p")?;
    std::os::unix::fs::symlink(&elsewhere, t.join("files"))?;
    let mut c = local(&d, EngineKind::Threads, None)?;
    let (st, _) = call(&mut c, MSG_TRASH_EMPTY, &[])?;
    assert_ne!(st, ST_OK, "items remain behind a trash that was skipped");
    assert!(elsewhere.join("kept").exists());
    Ok(())
}

/// REV-2: a payload whose name leaves no room for ".trashinfo" can still be deleted.
#[test]
fn a_payload_with_a_maximum_length_name_can_be_deleted() -> R {
    let d = TestDir::new("loc-rev2")?;
    let t = trash_dir(&d)?;
    let e = "n".repeat(250);
    fs::write(t.join("files").join(&e), b"x")?;
    let mut c = local(&d, EngineKind::Threads, None)?;
    assert_eq!(list(&mut c, SCHEME_TRASH)?.len(), 1);
    let name = format!("h-{e}");
    assert_eq!(delete(&mut c, SCHEME_TRASH, name.as_bytes())?, ST_OK);
    assert!(list(&mut c, SCHEME_TRASH)?.is_empty());
    Ok(())
}

/// REV-3: a hostile volume's symlink cannot steer a restore off the volume.
#[test]
fn a_restore_cannot_follow_a_volume_symlink_off_the_volume() -> R {
    let d = TestDir::new("loc-rev3")?;
    trash_dir(&d)?;
    let vol = d.join("vol");
    let vt = volume_trash(&vol)?;
    let victim = d.join("autostart");
    fs::create_dir(&victim)?;
    std::os::unix::fs::symlink(&victim, vol.join("link"))?;
    fs::write(vt.join("files/evil"), b"payload")?;
    fs::write(
        vt.join("info/evil.trashinfo"),
        "[Trash Info]\nPath=link/evil\n",
    )?;
    let mut c = local(&d, EngineKind::Threads, Some(&vol))?;
    let rows = list(&mut c, SCHEME_TRASH)?;
    assert_ne!(restore(&mut c, &rows[0].name, b"")?, ST_OK);
    assert!(!victim.join("evil").exists(), "escaped the volume");
    // What every real client sends: g_file_move names the item's own orig-path.
    assert_ne!(restore(&mut c, &rows[0].name, &rows[0].orig)?, ST_OK);
    assert!(
        !victim.join("evil").exists(),
        "escaped the volume by its own path"
    );
    // A path through the volume is checked however it came to be spelled.
    fs::write(
        vt.join("info/evil.trashinfo"),
        "[Trash Info]\nPath=link//evil\n",
    )?;
    let rows = list(&mut c, SCHEME_TRASH)?;
    let there = vol.join("link/evil");
    let spelled = there.to_str().ok_or("path")?.as_bytes();
    assert_ne!(restore(&mut c, &rows[0].name, spelled)?, ST_OK);
    assert!(!victim.join("evil").exists(), "escaped by respelling");
    assert!(vt.join("files/evil").exists(), "the item stays");
    Ok(())
}

/// A failed item keeps everything listed; empty never reports success (SEC-F-001).
#[test]
fn empty_never_reports_success_with_items_left() -> R {
    let d = TestDir::new("loc-left")?;
    let t = trash_dir(&d)?;
    trashed(&t, "good", &d.join("g"))?;
    fs::write(t.join("files/stuck"), b"x")?;
    fs::create_dir_all(t.join("info/stuck.trashinfo/x"))?;
    fs::write(t.join("info/orphan.trashinfo"), "[Trash Info]\nPath=/o\n")?;
    let then = std::time::SystemTime::now() - Duration::from_secs(60);
    fs::File::options()
        .write(true)
        .open(t.join("info/orphan.trashinfo"))?
        .set_modified(then)?;
    let mut c = local(&d, EngineKind::Threads, None)?;
    let (st, body) = call(&mut c, MSG_TRASH_EMPTY, &[])?;
    assert_ne!(st, ST_OK, "{body:?}");
    assert_eq!(u32::from_le_bytes(body[..4].try_into()?), 1, "deleted");
    assert_eq!(u32::from_le_bytes(body[4..8].try_into()?), 1, "failed");
    assert!(t.join("files/stuck").exists() && !t.join("files/good").exists());
    assert!(!t.join("info/orphan.trashinfo").exists(), "orphan removed");
    Ok(())
}

/// A volume trash: the entry's name carries the volume, and paths are relative to it.
#[test]
fn a_volume_trash_is_listed_and_restored_relative_to_its_top() -> R {
    let d = TestDir::new("loc-vol")?;
    trash_dir(&d)?;
    let vol = d.join("vol");
    let vt = volume_trash(&vol)?;
    fs::write(vt.join("files/v"), b"payload")?;
    fs::write(vt.join("info/v.trashinfo"), "[Trash Info]\nPath=sub/v\n")?;
    fs::create_dir(vol.join("sub"))?;
    let mut c = local(&d, EngineKind::Threads, Some(&vol))?;
    let rows = list(&mut c, SCHEME_TRASH)?;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].orig, vol.join("sub/v").as_os_str().as_bytes());
    assert_eq!(restore(&mut c, &rows[0].name, b"")?, ST_OK);
    assert_eq!(fs::read(vol.join("sub/v"))?, b"payload");
    Ok(())
}

#[test]
fn recent_lists_and_forgets_without_touching_the_file() -> R {
    let d = TestDir::new("loc-recent")?;
    fs::create_dir_all(d.join("data"))?;
    let f = d.join("doc.txt");
    fs::write(&f, b"keep me")?;
    let xbel = format!(
        "<?xml version=\"1.0\"?>\n<xbel version=\"1.0\">\n\
         <bookmark href=\"file://{}\" added=\"x\"/>\n\
         <bookmark href=\"https://example.invalid/\" added=\"x\"/>\n</xbel>\n",
        f.display()
    );
    fs::write(d.join("data/recently-used.xbel"), &xbel)?;
    let mut c = local(&d, EngineKind::Threads, None)?;
    let rows = list(&mut c, SCHEME_RECENT)?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].kind, 1);
    assert_eq!(delete(&mut c, SCHEME_RECENT, &rows[0].name)?, ST_OK);
    assert_eq!(list(&mut c, SCHEME_RECENT)?.len(), 1);
    assert_eq!(fs::read(&f)?, b"keep me");
    assert_eq!(delete(&mut c, SCHEME_RECENT, b"zz")?, ST_BAD_REQUEST);
    Ok(())
}

/// SEC H-007: a restore destination with `.` or `..` components (or an empty one) is
/// refused, the item left in the trash. GIO only ever sends canonical paths, and the
/// lexical "lands on the trash's volume" test that picks the volume's checks means
/// nothing for a path that climbs back with `..`.
#[test]
fn a_restore_destination_with_dot_components_is_refused() -> R {
    for engine in engines() {
        let d = TestDir::new("loc-dotdest")?;
        let t = trash_dir(&d)?;
        trashed(&t, "item", &d.join("orig"))?;
        let mut c = local(&d, engine, None)?;
        let base = d.path().as_os_str().as_bytes();
        for bad in [
            [base, b"/sub/../landed"].concat(),
            [base, b"/./landed"].concat(),
            [base, b"//landed"].concat(),
            [base, b"/landed/.."].concat(),
            [base, b"/landed/."].concat(),
        ] {
            let st = restore(&mut c, b"h-item", &bad)?;
            assert_eq!(
                st,
                ST_BAD_REQUEST,
                "{engine:?}: {}",
                String::from_utf8_lossy(&bad)
            );
            assert!(t.join("files/item").exists() && t.join("info/item.trashinfo").exists());
        }
        assert!(!d.join("landed").exists());
        // A canonical destination still restores.
        let good = [base, b"/landed"].concat();
        assert_eq!(restore(&mut c, b"h-item", &good)?, ST_OK);
        assert_eq!(fs::read(d.join("landed"))?, b"payload");
    }
    Ok(())
}
