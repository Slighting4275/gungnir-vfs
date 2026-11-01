//! `trash://` and `recent://` through a real, sandboxed gungnird, on both engines
//! (milestone 9): the promises of `trash.rs` as a client sees them.

use std::{
    ffi::CString,
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};

use gungnird::{
    md::{Client, MSG_MD_REPLY, ST_BUSY, ST_NOT_FOUND, ST_OK},
    ops,
    vfssvc::{
        MSG_TRASH_EMPTY, MSG_VFS_DELETE, MSG_VFS_LIST, MSG_VFS_RESTORE, SCHEME_RECENT,
        SCHEME_TRASH, ST_MOUNT_INSIDE,
    },
};

type R<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

static N: AtomicU32 = AtomicU32::new(0);

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> R<Self> {
        let base = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?
            .join(".build/tmp");
        fs::create_dir_all(&base)?;
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = base.join(format!("it-trash-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&p)?;
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
    c: Client,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(d: &Dir, no_uring: bool, env: &[(&str, &str)]) -> R<Daemon> {
    let sock = d.join("s.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
    cmd.arg("--seccomp")
        .arg("-s")
        .arg(&sock)
        .arg("-d")
        .arg(d.join("data/gungnir/metadata.db"))
        .env("HOME", &d.0)
        .env("XDG_DATA_HOME", d.join("data"))
        .env(ops::NO_URING_ENV, if no_uring { "1" } else { "0" })
        .env_remove("GUNGNIR_SECCOMP")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(d.join("log"))?);
    let child = cmd.spawn()?;
    let t0 = Instant::now();
    while !sock.exists() {
        if t0.elapsed() > Duration::from_secs(10) {
            return Err("gungnird did not start".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(30));
    let c = Client::connect(&sock, Duration::from_secs(5))?;
    Ok(Daemon { child, c })
}

fn call(c: &mut Client, kind: u32, payload: &[u8]) -> R<(u32, Vec<u8>)> {
    let seq = c.send(kind, payload)?;
    let t0 = Instant::now();
    loop {
        let left = Duration::from_secs(70)
            .checked_sub(t0.elapsed())
            .ok_or("no reply in time")?;
        let m = c.recv(left)?;
        if m.kind == MSG_MD_REPLY && m.seq == seq {
            let p = m.payload();
            return Ok((u32::from_le_bytes(p[..4].try_into()?), p[4..].to_vec()));
        }
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

fn list(c: &mut Client, scheme: u8) -> R<Vec<Row>> {
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

fn delete(c: &mut Client, scheme: u8, name: &[u8]) -> R<u32> {
    let mut p = vec![scheme];
    p.extend(len16(name));
    Ok(call(c, MSG_VFS_DELETE, &p)?.0)
}

fn restore(c: &mut Client, name: &[u8], dest: &[u8]) -> R<u32> {
    let mut p = len16(name);
    p.extend(len16(dest));
    Ok(call(c, MSG_VFS_RESTORE, &p)?.0)
}

fn trash_dir(d: &Dir) -> R<PathBuf> {
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

#[cfg(feature = "test-hooks")]
fn hexed(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn engines() -> [bool; 2] {
    [false, true]
}

#[test]
fn listing_restoring_and_deleting() -> R {
    for no_uring in engines() {
        let d = Dir::new("basic")?;
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
        let mut dm = start(&d, no_uring, &[])?;
        let rows = list(&mut dm.c, SCHEME_TRASH)?;
        assert_eq!(rows.len(), 3, "{rows:?}");
        let name = |e: &str| format!("h-{e}").into_bytes();
        assert!(rows.iter().any(|r| r.name == name("tree") && r.kind == 2));
        let keep = rows.iter().find(|r| r.name == name("keep")).ok_or("keep")?;
        assert_eq!(keep.orig, back.as_os_str().as_bytes());

        assert_eq!(restore(&mut dm.c, &name("keep"), b"")?, ST_OK);
        assert_eq!(fs::read(&back)?, b"payload");
        assert!(!t.join("info/keep.trashinfo").exists());
        assert!(!t.join("files/keep").exists());

        assert_eq!(delete(&mut dm.c, SCHEME_TRASH, &name("drop"))?, ST_OK);
        assert_eq!(delete(&mut dm.c, SCHEME_TRASH, &name("tree"))?, ST_OK);
        assert!(!t.join("files/tree").exists() && !t.join("info/tree.trashinfo").exists());
        assert_eq!(
            delete(&mut dm.c, SCHEME_TRASH, &name("drop"))?,
            ST_NOT_FOUND
        );
        assert!(list(&mut dm.c, SCHEME_TRASH)?.is_empty());
    }
    Ok(())
}

/// Restoring never replaces what is at the destination, and the item stays.
#[test]
fn a_restore_onto_an_existing_file_keeps_both() -> R {
    let d = Dir::new("noclobber")?;
    let t = trash_dir(&d)?;
    let there = d.join("there");
    fs::write(&there, b"newer")?;
    trashed(&t, "e", &there)?;
    let mut dm = start(&d, false, &[])?;
    assert_ne!(restore(&mut dm.c, b"h-e", b"")?, ST_OK);
    assert_eq!(fs::read(&there)?, b"newer");
    assert_eq!(list(&mut dm.c, SCHEME_TRASH)?.len(), 1);
    Ok(())
}

/// BC-T005-F1: with a non-empty directory at the info path nothing is touched.
#[test]
fn an_item_whose_info_cannot_go_keeps_its_payload() -> R {
    let d = Dir::new("infodir")?;
    let t = trash_dir(&d)?;
    fs::write(t.join("files/e"), b"payload")?;
    fs::create_dir_all(t.join("info/e.trashinfo/x"))?;
    let mut dm = start(&d, false, &[])?;
    assert_ne!(delete(&mut dm.c, SCHEME_TRASH, b"h-e")?, ST_OK);
    assert!(t.join("files/e").exists());
    assert_eq!(list(&mut dm.c, SCHEME_TRASH)?.len(), 1);
    Ok(())
}

/// F05: a symlink at Trash/files never aims a delete anywhere.
#[test]
fn a_symlinked_files_directory_is_never_followed() -> R {
    let d = Dir::new("link")?;
    let t = d.join("data/Trash");
    fs::create_dir_all(t.join("info"))?;
    let elsewhere = d.join("elsewhere");
    fs::create_dir(&elsewhere)?;
    fs::write(elsewhere.join("precious"), b"p")?;
    std::os::unix::fs::symlink(&elsewhere, t.join("files"))?;
    fs::write(t.join("info/precious.trashinfo"), "[Trash Info]\nPath=/p\n")?;
    let mut dm = start(&d, false, &[])?;
    assert!(list(&mut dm.c, SCHEME_TRASH)?.is_empty());
    assert_ne!(delete(&mut dm.c, SCHEME_TRASH, b"h-precious")?, ST_OK);
    let (st, _) = call(&mut dm.c, MSG_TRASH_EMPTY, &[])?;
    assert_ne!(st, ST_OK);
    assert!(elsewhere.join("precious").exists());
    Ok(())
}

/// REV-1: a trash that cannot be used is not an empty trash.
#[test]
fn empty_does_not_report_success_past_an_unusable_trash() -> R {
    let d = Dir::new("rev1")?;
    let t = d.join("data/Trash");
    fs::create_dir_all(t.join("info"))?;
    let elsewhere = d.join("elsewhere");
    fs::create_dir(&elsewhere)?;
    fs::write(elsewhere.join("kept"), b"p")?;
    std::os::unix::fs::symlink(&elsewhere, t.join("files"))?;
    let mut dm = start(&d, false, &[])?;
    let (st, _) = call(&mut dm.c, MSG_TRASH_EMPTY, &[])?;
    assert_ne!(st, ST_OK, "items remain behind a trash that was skipped");
    assert!(elsewhere.join("kept").exists());
    Ok(())
}

/// REV-2: a payload whose name leaves no room for ".trashinfo" can still be deleted.
#[test]
fn a_payload_with_a_maximum_length_name_can_be_deleted() -> R {
    let d = Dir::new("rev2")?;
    let t = trash_dir(&d)?;
    let e = "n".repeat(250);
    fs::write(t.join("files").join(&e), b"x")?;
    let mut dm = start(&d, false, &[])?;
    assert_eq!(list(&mut dm.c, SCHEME_TRASH)?.len(), 1);
    let name = format!("h-{e}");
    assert_eq!(delete(&mut dm.c, SCHEME_TRASH, name.as_bytes())?, ST_OK);
    assert!(list(&mut dm.c, SCHEME_TRASH)?.is_empty());
    Ok(())
}

/// REV-3: a hostile volume's symlink cannot steer a restore off the volume.
#[cfg(feature = "test-hooks")]
#[test]
fn a_restore_cannot_follow_a_volume_symlink_off_the_volume() -> R {
    let d = Dir::new("rev3")?;
    trash_dir(&d)?;
    let vol = d.join("vol");
    // SAFETY: plain getter.
    let vt = vol.join(format!(".Trash-{}", unsafe { libc::geteuid() }));
    fs::create_dir_all(vt.join("files"))?;
    fs::create_dir_all(vt.join("info"))?;
    let victim = d.join("autostart");
    fs::create_dir(&victim)?;
    std::os::unix::fs::symlink(&victim, vol.join("link"))?;
    fs::write(vt.join("files/evil"), b"payload")?;
    fs::write(
        vt.join("info/evil.trashinfo"),
        "[Trash Info]\nPath=link/evil\n",
    )?;
    let mut dm = start(
        &d,
        false,
        &[(gungnird::vfssvc::TEST_TOP_ENV, vol.to_str().ok_or("path")?)],
    )?;
    let rows = list(&mut dm.c, SCHEME_TRASH)?;
    assert_ne!(restore(&mut dm.c, &rows[0].name, b"")?, ST_OK);
    assert!(!victim.join("evil").exists(), "escaped the volume");
    // What every real client sends: g_file_move names the item's own orig-path.
    assert_ne!(restore(&mut dm.c, &rows[0].name, &rows[0].orig)?, ST_OK);
    assert!(
        !victim.join("evil").exists(),
        "escaped the volume by its own path"
    );
    // A path through the volume is checked however it came to be spelled.
    fs::write(
        vt.join("info/evil.trashinfo"),
        "[Trash Info]\nPath=link//evil\n",
    )?;
    let rows = list(&mut dm.c, SCHEME_TRASH)?;
    let there = vol.join("link/evil");
    let spelled = there.to_str().ok_or("path")?.as_bytes();
    assert_ne!(restore(&mut dm.c, &rows[0].name, spelled)?, ST_OK);
    assert!(!victim.join("evil").exists(), "escaped by respelling");
    assert!(vt.join("files/evil").exists(), "the item stays");
    Ok(())
}

/// REV-12: a delete with a scheme that does not exist deletes nothing.
#[test]
fn an_unknown_scheme_deletes_nothing() -> R {
    let d = Dir::new("rev12")?;
    let t = trash_dir(&d)?;
    trashed(&t, "e", &d.join("e"))?;
    let mut dm = start(&d, false, &[])?;
    assert_eq!(delete(&mut dm.c, 2, b"h-e")?, 6);
    assert!(t.join("files/e").exists());
    Ok(())
}

/// A trash on a subvolume with no mount, however deep, is listed and emptied.
#[cfg(feature = "test-hooks")]
#[test]
fn a_deep_subvolume_trash_is_listed_and_emptied() -> R {
    use gungnird::btrfs::create_subvolume;
    let d = Dir::new("subvol")?;
    trash_dir(&d)?;
    let vol = d.join("vol");
    if create_subvolume(&vol).is_err() {
        eprintln!("skipped: no btrfs here");
        return Ok(());
    }
    fs::create_dir_all(vol.join("a/b/c"))?;
    let deep = vol.join("a/b/c/deep");
    create_subvolume(&deep)?;
    // SAFETY: plain getter.
    let vt = deep.join(format!(".Trash-{}", unsafe { libc::geteuid() }));
    fs::create_dir_all(vt.join("files"))?;
    fs::create_dir_all(vt.join("info"))?;
    fs::write(vt.join("files/e"), b"x")?;
    fs::write(vt.join("info/e.trashinfo"), "[Trash Info]\nPath=e\n")?;
    let mut dm = start(
        &d,
        false,
        &[(gungnird::vfssvc::TEST_TOP_ENV, vol.to_str().ok_or("path")?)],
    )?;
    assert_eq!(list(&mut dm.c, SCHEME_TRASH)?.len(), 1, "not found");
    let (st, body) = call(&mut dm.c, MSG_TRASH_EMPTY, &[])?;
    assert_eq!(st, ST_OK, "{body:?}");
    assert!(!vt.join("files/e").exists(), "not emptied");
    drop(dm);
    let _ = fs::remove_dir_all(&deep);
    let _ = fs::remove_dir_all(&vol);
    Ok(())
}

/// A mounted snapshot nobody lives on is a backup: not listed, not emptied.
#[cfg(feature = "test-hooks")]
#[test]
fn a_mounted_snapshot_is_a_backup() -> R {
    use gungnird::btrfs::{create_snapshot, create_subvolume};
    let d = Dir::new("snap-top")?;
    trash_dir(&d)?;
    let live = d.join("live");
    if create_subvolume(&live).is_err() {
        eprintln!("skipped: no btrfs here");
        return Ok(());
    }
    // SAFETY: plain getter.
    let name = format!(".Trash-{}", unsafe { libc::geteuid() });
    fs::create_dir_all(live.join(&name).join("files"))?;
    fs::create_dir_all(live.join(&name).join("info"))?;
    fs::write(live.join(&name).join("files/e"), b"x")?;
    fs::write(
        live.join(&name).join("info/e.trashinfo"),
        "[Trash Info]\nPath=e\n",
    )?;
    let snap = d.join("snap");
    if create_snapshot(&live, &snap).is_err() {
        eprintln!("skipped: no snapshot allowed here");
        return Ok(());
    }
    let mut dm = start(
        &d,
        false,
        &[(gungnird::vfssvc::TEST_TOP_ENV, snap.to_str().ok_or("path")?)],
    )?;
    assert_eq!(
        list(&mut dm.c, SCHEME_TRASH)?.len(),
        0,
        "a backup was listed"
    );
    let (st, _) = call(&mut dm.c, MSG_TRASH_EMPTY, &[])?;
    assert_eq!(st, ST_OK);
    assert!(
        snap.join(&name).join("files/e").exists(),
        "a backup was emptied"
    );
    drop(dm);
    let _ = fs::remove_dir_all(&snap);
    let _ = fs::remove_dir_all(&live);
    Ok(())
}

/// An empty stops with its client, between items as well as inside one.
#[cfg(feature = "test-hooks")]
#[test]
fn a_lost_client_stops_an_empty() -> R {
    let d = Dir::new("empty-gone")?;
    let t = trash_dir(&d)?;
    for n in 0..40 {
        fs::create_dir(t.join(format!("files/d{n}")))?;
        fs::write(
            t.join(format!("info/d{n}.trashinfo")),
            "[Trash Info]\nPath=/d\n",
        )?;
    }
    let mut dm = start(&d, false, &[(ops::SLOW_OPS_ENV, "100")])?;
    dm.c.send(MSG_TRASH_EMPTY, &[])?;
    thread::sleep(Duration::from_millis(500));
    dm.c = Client::connect(&d.join("s.sock"), Duration::from_secs(5))?;
    thread::sleep(Duration::from_millis(400));
    let left = fs::read_dir(t.join("files"))?.count();
    assert!(left > 0, "the empty ran to its end");
    thread::sleep(Duration::from_secs(1));
    assert_eq!(fs::read_dir(t.join("files"))?.count(), left, "it went on");
    Ok(())
}

/// A long op says it is alive, and a client that goes away stops it.
#[cfg(feature = "test-hooks")]
#[test]
fn a_long_delete_beats_and_a_lost_client_cancels_it() -> R {
    let d = Dir::new("beat")?;
    let t = trash_dir(&d)?;
    fs::create_dir(t.join("files/big"))?;
    for n in 0..4 {
        fs::write(t.join(format!("files/big/f{n}")), b"x")?;
    }
    fs::write(t.join("info/big.trashinfo"), "[Trash Info]\nPath=/big\n")?;
    let mut dm = start(&d, false, &[(ops::SLOW_OPS_ENV, "8000")])?;
    let mut req = vec![SCHEME_TRASH];
    req.extend(len16(b"h-big"));
    let seq = dm.c.send(gungnird::vfssvc::MSG_VFS_DELETE, &req)?;
    let t0 = Instant::now();
    loop {
        let left = Duration::from_secs(7)
            .checked_sub(t0.elapsed())
            .ok_or("no beat in time")?;
        let m = dm.c.recv(left)?;
        if m.seq == seq {
            assert_eq!(m.kind, gungnird::vfssvc::MSG_VFS_BEAT, "answered early");
            break;
        }
    }
    let sock = d.join("s.sock");
    dm.c = Client::connect(&sock, Duration::from_secs(5))?;
    thread::sleep(Duration::from_secs(1));
    assert_eq!(list(&mut dm.c, SCHEME_TRASH)?.len(), 1, "still listed");
    let names = fs::read_dir(t.join("files/big"))?.count();
    thread::sleep(Duration::from_secs(9));
    assert_eq!(
        fs::read_dir(t.join("files/big"))?.count(),
        names,
        "the op went on with nobody listening"
    );
    assert!(t.join("info/big.trashinfo").exists());
    Ok(())
}

/// A failed item keeps everything listed; empty never reports success (SEC-F-001).
#[test]
fn empty_never_reports_success_with_items_left() -> R {
    let d = Dir::new("left")?;
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
    let mut dm = start(&d, false, &[])?;
    let (st, body) = call(&mut dm.c, MSG_TRASH_EMPTY, &[])?;
    assert_ne!(st, ST_OK, "{body:?}");
    assert_eq!(u32::from_le_bytes(body[..4].try_into()?), 1, "deleted");
    assert_eq!(u32::from_le_bytes(body[4..8].try_into()?), 1, "failed");
    assert!(t.join("files/stuck").exists() && !t.join("files/good").exists());
    assert!(!t.join("info/orphan.trashinfo").exists(), "orphan removed");
    Ok(())
}

/// F06: a hung volume is skipped and named; the reachable trash is emptied; nothing
/// hangs; other requests are answered meanwhile.
#[cfg(feature = "test-hooks")]
#[test]
fn a_hung_volume_is_skipped_and_named() -> R {
    let d = Dir::new("hung")?;
    let t = trash_dir(&d)?;
    trashed(&t, "e", &d.join("e"))?;
    let vol = d.join("vol");
    // SAFETY: plain getter.
    let vt = vol.join(format!(".Trash-{}", unsafe { libc::geteuid() }));
    fs::create_dir_all(vt.join("files"))?;
    fs::create_dir_all(vt.join("info"))?;
    trashed(&vt, "v", &vol.join("v"))?;
    let v = vol.to_str().ok_or("path")?;
    let mut dm = start(
        &d,
        false,
        &[
            ("GUNGNIR_TEST_FAKE_HUNG_MOUNT", v),
            (gungnird::vfssvc::TEST_TOP_ENV, v),
        ],
    )?;
    // The fake mount's probe takes its deadline to be declared hung: from then on the
    // list leaves that volume out.
    let t0 = Instant::now();
    while list(&mut dm.c, SCHEME_TRASH)?.len() > 1 {
        assert!(t0.elapsed() < Duration::from_secs(5), "never declared hung");
        thread::sleep(Duration::from_millis(50));
    }
    let (st, body) = call(&mut dm.c, MSG_TRASH_EMPTY, &[])?;
    assert_eq!(st, gungnird::md::ST_SUSPECT_MOUNT, "{body:?}");
    let names = String::from_utf8_lossy(&body[10..]).into_owned();
    assert!(names.contains(v), "{names}");
    let mut name = hexed(vt.as_os_str().as_bytes()).into_bytes();
    name.extend_from_slice(b"-v");
    assert_eq!(
        delete(&mut dm.c, SCHEME_TRASH, &name)?,
        gungnird::md::ST_SUSPECT_MOUNT,
        "an item on a hung volume is not a missing item"
    );
    assert!(
        !t.join("files/e").exists(),
        "the reachable trash is emptied"
    );
    assert!(
        vt.join("files/v").exists(),
        "the hung volume is not touched"
    );
    Ok(())
}

/// A volume trash: the entry's name carries the volume, and paths are relative to it.
#[cfg(feature = "test-hooks")]
#[test]
fn a_volume_trash_is_listed_and_restored_relative_to_its_top() -> R {
    let d = Dir::new("vol")?;
    trash_dir(&d)?;
    let vol = d.join("vol");
    // SAFETY: plain getter.
    let vt = vol.join(format!(".Trash-{}", unsafe { libc::geteuid() }));
    fs::create_dir_all(vt.join("files"))?;
    fs::create_dir_all(vt.join("info"))?;
    fs::write(vt.join("files/v"), b"payload")?;
    fs::write(vt.join("info/v.trashinfo"), "[Trash Info]\nPath=sub/v\n")?;
    fs::create_dir(vol.join("sub"))?;
    let mut dm = start(
        &d,
        false,
        &[(gungnird::vfssvc::TEST_TOP_ENV, vol.to_str().ok_or("path")?)],
    )?;
    let rows = list(&mut dm.c, SCHEME_TRASH)?;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].orig, vol.join("sub/v").as_os_str().as_bytes());
    assert_eq!(restore(&mut dm.c, &rows[0].name, b"")?, ST_OK);
    assert_eq!(fs::read(vol.join("sub/v"))?, b"payload");
    Ok(())
}

#[test]
fn recent_lists_and_forgets_without_touching_the_file() -> R {
    let d = Dir::new("recent")?;
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
    let mut dm = start(&d, false, &[])?;
    let rows = list(&mut dm.c, SCHEME_RECENT)?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].kind, 1);
    assert_eq!(delete(&mut dm.c, SCHEME_RECENT, &rows[0].name)?, ST_OK);
    assert_eq!(list(&mut dm.c, SCHEME_RECENT)?.len(), 1);
    assert_eq!(fs::read(&f)?, b"keep me");
    assert_eq!(delete(&mut dm.c, SCHEME_RECENT, b"zz")?, 6, "bad request");
    Ok(())
}

/// Bad requests are answered, never a panic.
#[test]
fn malformed_requests_are_refused() -> R {
    let d = Dir::new("bad")?;
    let mut dm = start(&d, false, &[])?;
    for (k, p) in [
        (MSG_VFS_LIST, &[][..]),
        (MSG_VFS_LIST, &[9, 0, 0, 0, 0]),
        (MSG_VFS_DELETE, &[]),
        (MSG_VFS_DELETE, &[0, 255, 255]),
        (MSG_VFS_RESTORE, &[1]),
    ] {
        assert_eq!(call(&mut dm.c, k, p)?.0, 6, "kind {k}");
    }
    assert_eq!(delete(&mut dm.c, SCHEME_TRASH, b"h-..")?, ST_NOT_FOUND);
    assert_eq!(delete(&mut dm.c, SCHEME_TRASH, b"h-a/b")?, ST_NOT_FOUND);
    assert!(dm.child.try_wait()?.is_none(), "the daemon died");
    Ok(())
}

fn mount_namespace(test: &str) -> R<bool> {
    const INNER: &str = "GUNGNIR_TEST_IN_MOUNT_NS";
    if std::env::var_os(INNER).is_some() {
        return Ok(true);
    }
    let usable = Command::new("unshare")
        .args(["-rm", "true"])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !usable {
        eprintln!("note: no user+mount namespace here: {test} skipped");
        return Ok(false);
    }
    let st = Command::new("unshare")
        .arg("-rm")
        .arg(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(INNER, "1")
        .status()?;
    if !st.success() {
        return Err(format!("{test} failed in its mount namespace ({st})").into());
    }
    Ok(false)
}

fn bind(src: &Path, dst: &Path) -> R {
    let (s, t) = (
        CString::new(src.as_os_str().as_bytes())?,
        CString::new(dst.as_os_str().as_bytes())?,
    );
    // SAFETY: valid NUL-terminated paths; a bind mount takes no fstype or data.
    let r = unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if r != 0 {
        return Err(format!("bind: {}", std::io::Error::last_os_error()).into());
    }
    Ok(())
}

/// DIB-F001, the critical one: a bind mount inside a trashed directory. Delete and empty,
/// on both engines: the foreign file survives, the item stays listed, the status says why.
#[test]
fn a_bind_mount_inside_a_trashed_directory_is_never_crossed() -> R {
    if !mount_namespace("a_bind_mount_inside_a_trashed_directory_is_never_crossed")? {
        return Ok(());
    }
    for no_uring in engines() {
        for use_empty in [false, true] {
            let d = Dir::new("bind")?;
            let t = trash_dir(&d)?;
            let outside = d.join("outside");
            fs::create_dir_all(outside.join("deep"))?;
            fs::write(outside.join("deep/precious"), b"p")?;
            let dir = t.join("files/dir");
            fs::create_dir_all(dir.join("m"))?;
            fs::write(t.join("info/dir.trashinfo"), "[Trash Info]\nPath=/x/dir\n")?;
            bind(&outside, &dir.join("m"))?;
            let mut dm = start(&d, no_uring, &[])?;
            let st = if use_empty {
                call(&mut dm.c, MSG_TRASH_EMPTY, &[])?.0
            } else {
                delete(&mut dm.c, SCHEME_TRASH, b"h-dir")?
            };
            assert_eq!(st, ST_MOUNT_INSIDE, "engine no_uring={no_uring}");
            assert!(outside.join("deep/precious").exists(), "crossed the mount");
            assert_eq!(list(&mut dm.c, SCHEME_TRASH)?.len(), 1, "item still listed");
            assert!(t.join("info/dir.trashinfo").exists());
            // SAFETY: a valid NUL-terminated path.
            let target = CString::new(dir.join("m").as_os_str().as_bytes())?;
            assert_eq!(unsafe { libc::umount(target.as_ptr()) }, 0);
            assert_eq!(delete(&mut dm.c, SCHEME_TRASH, b"h-dir")?, ST_OK, "retry");
            assert!(outside.join("deep/precious").exists());
        }
    }
    Ok(())
}

/// More requests than request threads: the rest are `busy` at once, never queued.
#[test]
fn request_threads_are_bounded() -> R {
    let d = Dir::new("bound")?;
    fs::create_dir_all(d.join("data"))?;
    let mut text = String::from("<xbel>\n");
    for i in 0..60_000 {
        text.push_str(&format!("<bookmark href=\"file:///nonexistent/{i}\"/>\n"));
    }
    text.push_str("</xbel>\n");
    fs::write(d.join("data/recently-used.xbel"), text)?;
    let mut dm = start(&d, false, &[])?;
    let mut seqs = Vec::new();
    for _ in 0..24 {
        let p = [SCHEME_RECENT, 0, 0, 0, 0];
        seqs.push(dm.c.send(MSG_VFS_LIST, &p)?);
    }
    let (mut ok, mut busy) = (0, 0);
    for _ in 0..seqs.len() {
        let m = loop {
            let m = dm.c.recv(Duration::from_secs(20))?;
            if m.kind == MSG_MD_REPLY {
                break m;
            }
        };
        match u32::from_le_bytes(m.payload()[..4].try_into()?) {
            ST_OK => ok += 1,
            ST_BUSY => busy += 1,
            st => return Err(format!("status {st}").into()),
        }
    }
    assert!(ok >= 1, "nothing answered");
    assert!(busy >= 1, "no request was refused: ok {ok}");
    Ok(())
}
