use super::*;
use crate::testdir::TestDir;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    sync::{Condvar, atomic::AtomicBool},
};

// A trimmed real-world mountinfo: optional fields, escaped paths, an anonymous btrfs
// device, an over-mounted /dev/shm and lines that must be skipped.
const FIXTURE: &[u8] = b"\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
24 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=8k
25 24 0:23 / /dev/shm rw,nosuid,nodev shared:3 - tmpfs tmpfs rw
26 25 0:47 / /dev/shm rw,nosuid,nodev - tmpfs shm rw
30 22 0:35 /@home /home rw,relatime shared:30 master:7 - btrfs /dev/mapper/root rw,subvol=/@home
31 22 0:50 / /mnt/my\\040disk rw - ext4 /dev/sdb1 rw
32 22 0:51 / /mnt/tab\\011and\\134back rw - vfat /dev/sdc1 rw
33 22 0:52 / /srv/nfs rw - nfs4 server:/export rw,vers=4.2
34 22 0:53 / /mnt/fuse rw,nosuid - fuse.sshfs host:/dir rw,user_id=1000
35 22 0:54 / /mnt/ab rw - tmpfs tmpfs rw
this line is garbage
36 22 0:55 / /broken rw shared:9 ext4 /dev/sdz1 rw
37 22 x:1 / /baddev rw - ext4 /dev/sdy1 rw

";

fn entry(t: &[MountEntry], id: u64) -> &MountEntry {
    t.iter().find(|e| e.mnt_id == id).expect("fixture entry")
}

#[test]
fn ioctl_number_matches_the_kernel_header() {
    // _IOR(0x15, 0, struct fsuuid2) from <linux/fs.h>
    assert_eq!(FS_IOC_GETFSUUID, 0x8011_1500);
}

#[test]
fn mountinfo_fixture_parses_fields_and_skips_garbage() {
    let t = parse_mountinfo(FIXTURE);
    assert_eq!(
        t.iter().map(|e| e.mnt_id).collect::<Vec<_>>(),
        [22, 23, 24, 25, 26, 30, 31, 32, 33, 34, 35]
    );
    let root = entry(&t, 22);
    assert_eq!((root.parent_id, root.major, root.minor), (1, 259, 2));
    assert_eq!(root.fstype, b"ext4");
    assert_eq!(root.source, b"/dev/nvme0n1p2");
    let home = entry(&t, 30);
    assert_eq!(home.root, b"/@home");
    assert_eq!((home.major, home.minor), (0, 35));
    assert_eq!(home.source, b"/dev/mapper/root");
    assert_eq!(entry(&t, 31).mount_point, b"/mnt/my disk");
    assert_eq!(entry(&t, 32).mount_point, b"/mnt/tab\tand\\back");
    assert_eq!(entry(&t, 33).source, b"server:/export");
    assert_eq!(entry(&t, 34).fstype, b"fuse.sshfs");
}

#[test]
fn unescape_leaves_invalid_sequences_alone() {
    assert_eq!(unescape(b"a\\040b"), b"a b");
    assert_eq!(unescape(b"a\\04"), b"a\\04");
    assert_eq!(unescape(b"a\\9999"), b"a\\9999");
    assert_eq!(unescape(b"\\777x"), b"\\777x"); // > 255: kept literally
    assert_eq!(unescape(b"end\\"), b"end\\");
}

#[test]
fn mount_lookup_is_longest_prefix_on_component_boundaries() {
    let t = parse_mountinfo(FIXTURE);
    let id = |p: &str| mount_for_path(&t, Path::new(p)).map(|e| e.mnt_id);
    assert_eq!(id("/"), Some(22));
    assert_eq!(id("/etc/passwd"), Some(22));
    assert_eq!(id("/mnt/ab/x"), Some(35));
    assert_eq!(id("/mnt/abc/x"), Some(22)); // not under /mnt/ab
    assert_eq!(id("/mnt/my disk/f"), Some(31));
    assert_eq!(id("/dev/shm/x"), Some(26)); // the later mount is on top
    assert_eq!(id("/srv/nfs/../nfs/a/./b"), Some(33));
    assert_eq!(id("/srv/nfs/.."), Some(22));
}

#[test]
fn mount_cache_drops_uuids_of_replaced_or_vanished_mounts() {
    let mut c = MountCache::from_text(FIXTURE);
    let nfs = entry(c.table(), 33).clone();
    let fuse = entry(c.table(), 34).clone();
    let cm = |entry: &MountEntry, uuid: &str| CachedMount {
        entry: entry.clone(),
        uuid: uuid.into(),
        source: UuidSource::Synthetic,
        f_type: 0,
    };
    c.uuids.insert(33, cm(&nfs, "u33"));
    c.uuids.insert(34, cm(&fuse, "u34"));
    assert_eq!(
        c.cached_uuid(&nfs),
        Some(("u33".into(), UuidSource::Synthetic))
    );
    // Mount 33 unmounted and its id reused by another export; 34 untouched.
    let mut table = c.table().to_vec();
    table.retain(|e| e.mnt_id != 33);
    let mut reused = nfs.clone();
    reused.source = b"other:/export".to_vec();
    table.push(reused.clone());
    c.apply(table);
    assert_eq!(c.cached_uuid(&reused), None);
    assert!(c.cached_uuid(&fuse).is_some());
    c.apply(Vec::new());
    assert!(c.uuids.is_empty());
}

#[test]
fn real_mountinfo_reads_and_poll_never_waits() -> std::result::Result<(), io::Error> {
    let mut c = MountCache::open()?;
    assert!(c.table().iter().any(|e| e.mount_point == b"/"));
    let t0 = Instant::now();
    for _ in 0..100 {
        c.refresh()?;
    }
    assert!(t0.elapsed() < Duration::from_secs(1));
    assert!(mount_for_path(c.table(), Path::new("/proc/self")).is_some());
    Ok(())
}

#[test]
fn classes_follow_statfs_magic() {
    assert_eq!(classify(magic::TMPFS), FsClass::Volatile);
    assert_eq!(classify(magic::RAMFS), FsClass::Volatile);
    for m in [magic::NFS, magic::CIFS, magic::SMB2, magic::SMB] {
        assert_eq!(classify(m), FsClass::Network);
    }
    assert_eq!(classify(magic::FUSE), FsClass::Other);
    assert_eq!(classify(0xEF53), FsClass::Other); // ext4
}

#[test]
fn synthetic_ids_hash_the_right_inputs_per_class() {
    let le = |m: u32| u64::from(m).to_le_bytes();
    // Volatile: f_type || mount_point || boot_id; the source is ignored.
    let v = synth_id(magic::TMPFS, b"/run/user/1", b"tmpfs", b"boot-a");
    assert_eq!(
        v,
        synth_fs_id(&[&le(magic::TMPFS), b"/run/user/1", b"boot-a"])
    );
    assert_eq!(
        v,
        synth_id(magic::TMPFS, b"/run/user/1", b"other", b"boot-a")
    );
    assert_ne!(
        v,
        synth_id(magic::TMPFS, b"/run/user/1", b"tmpfs", b"boot-b")
    );
    assert_ne!(
        v,
        synth_id(magic::TMPFS, b"/run/user/2", b"tmpfs", b"boot-a")
    );
    assert_ne!(
        v,
        synth_id(magic::RAMFS, b"/run/user/1", b"tmpfs", b"boot-a")
    );
    // Network: f_type || source; mount point and boot id are ignored.
    let n = synth_id(magic::NFS, b"/mnt/a", b"server:/export", b"boot-a");
    assert_eq!(n, synth_fs_id(&[&le(magic::NFS), b"server:/export"]));
    assert_eq!(
        n,
        synth_id(magic::NFS, b"/elsewhere", b"server:/export", b"x")
    );
    assert_ne!(
        n,
        synth_id(magic::NFS, b"/mnt/a", b"server:/other", b"boot-a")
    );
    // FUSE / other: f_type || source || mount_point.
    let f = synth_id(magic::FUSE, b"/mnt/fuse", b"host:/dir", b"boot-a");
    assert_eq!(
        f,
        synth_fs_id(&[&le(magic::FUSE), b"host:/dir", b"/mnt/fuse"])
    );
    assert_eq!(
        f,
        synth_id(magic::FUSE, b"/mnt/fuse", b"host:/dir", b"boot-b")
    );
    assert_ne!(
        f,
        synth_id(magic::FUSE, b"/mnt/fuse2", b"host:/dir", b"boot-a")
    );
    for id in [&v, &n, &f] {
        assert!(id.starts_with("synth-") && id.len() == 38);
    }
}

#[test]
fn fsuuid_formatting() {
    let mut b = [0u8; 16];
    for (i, x) in b.iter_mut().enumerate() {
        *x = u8::try_from(i * 17).unwrap_or(0);
    }
    assert_eq!(
        format_fsuuid(16, &b).as_deref(),
        Some("00112233-4455-6677-8899-aabbccddeeff")
    );
    assert_eq!(format_fsuuid(4, &b).as_deref(), Some("00112233"));
    assert_eq!(format_fsuuid(0, &b), None);
    assert_eq!(format_fsuuid(17, &b), None);
    assert_eq!(format_fsuuid(16, &[0; 16]), None);
}

#[test]
fn by_uuid_matches_device_number_then_source() -> std::result::Result<(), io::Error> {
    let t = TestDir::new("byuuid")?;
    let dir = t.join("by-uuid");
    fs::create_dir(&dir)?;
    // Real device nodes stand in for disks: /dev/null is 1:3, /dev/zero 1:5.
    symlink("/dev/null", dir.join("1111-null"))?;
    symlink("/dev/zero", dir.join("2222-zero"))?;
    symlink("/dev/random", dir.join("ABCD-EF01"))?;
    symlink("/nonexistent", dir.join("3333-dangling"))?;
    fs::write(dir.join("4444-file"), b"")?;
    assert_eq!(by_uuid(&dir, 1, 3, b"").as_deref(), Some("1111-null"));
    assert_eq!(
        by_uuid(&dir, 1, 5, b"/dev/sdq").as_deref(),
        Some("2222-zero")
    );
    // Anonymous device (btrfs 0:N): matched through the mount source instead.
    assert_eq!(
        by_uuid(&dir, 0, 35, b"/dev/zero").as_deref(),
        Some("2222-zero")
    );
    assert_eq!(by_uuid(&dir, 1, 8, b"").as_deref(), Some("abcd-ef01")); // lowercased
    assert_eq!(by_uuid(&dir, 0, 35, b"server:/x"), None);
    assert_eq!(by_uuid(&dir, 1, 9, b"/dev/nope"), None);
    assert_eq!(by_uuid(&t.join("missing"), 1, 3, b""), None);
    Ok(())
}

struct FakeProbe {
    ioctl: Option<&'static str>,
    by_uuid: Option<&'static str>,
    boot: Option<&'static [u8]>,
    calls: Mutex<Vec<&'static str>>,
}

impl UuidProbe for FakeProbe {
    fn ioctl_uuid(&self) -> Option<String> {
        lock(&self.calls).push("ioctl");
        self.ioctl.map(str::to_owned)
    }
    fn by_uuid(&self, _: &MountEntry) -> Option<String> {
        lock(&self.calls).push("by_uuid");
        self.by_uuid.map(str::to_owned)
    }
    fn boot_id(&self) -> Option<Vec<u8>> {
        lock(&self.calls).push("boot_id");
        self.boot.map(<[u8]>::to_vec)
    }
}

fn probe(
    ioctl: Option<&'static str>,
    by_uuid: Option<&'static str>,
    boot: Option<&'static [u8]>,
) -> FakeProbe {
    FakeProbe {
        ioctl,
        by_uuid,
        boot,
        calls: Mutex::new(Vec::new()),
    }
}

#[test]
fn chain_step1_ioctl_wins() -> Result<()> {
    let t = parse_mountinfo(FIXTURE);
    let p = probe(Some("ioctl-uuid"), Some("disk-uuid"), Some(b"b"));
    let r = fs_uuid_chain(&p, 0xEF53, entry(&t, 22))?;
    assert_eq!(r, ("ioctl-uuid".into(), UuidSource::Ioctl));
    assert_eq!(*lock(&p.calls), ["ioctl"]);
    Ok(())
}

#[test]
fn chain_step2_by_uuid_when_ioctl_unsupported() -> Result<()> {
    let t = parse_mountinfo(FIXTURE);
    let p = probe(None, Some("disk-uuid"), Some(b"b"));
    let r = fs_uuid_chain(&p, 0xEF53, entry(&t, 22))?;
    assert_eq!(r, ("disk-uuid".into(), UuidSource::ByUuid));
    assert_eq!(*lock(&p.calls), ["ioctl", "by_uuid"]);
    Ok(())
}

#[test]
fn chain_step3_synthetic_by_class() -> Result<()> {
    let t = parse_mountinfo(FIXTURE);
    // Volatile: hashes the boot id.
    let p = probe(None, None, Some(b"boot-1"));
    let shm = entry(&t, 26);
    let r = fs_uuid_chain(&p, magic::TMPFS, shm)?;
    assert_eq!(
        r,
        (
            synth_id(magic::TMPFS, b"/dev/shm", b"shm", b"boot-1"),
            UuidSource::Synthetic
        )
    );
    assert_eq!(*lock(&p.calls), ["ioctl", "by_uuid", "boot_id"]);
    // Network: no boot id read; mount source only.
    let p = probe(None, None, None);
    let r = fs_uuid_chain(&p, magic::NFS, entry(&t, 33))?;
    assert_eq!(r.0, synth_id(magic::NFS, b"", b"server:/export", b""));
    assert_eq!(*lock(&p.calls), ["ioctl", "by_uuid"]);
    // FUSE: source plus mount point.
    let r = fs_uuid_chain(&probe(None, None, None), magic::FUSE, entry(&t, 34))?;
    assert_eq!(r.0, synth_id(magic::FUSE, b"/mnt/fuse", b"host:/dir", b""));
    // A volatile filesystem without a boot id is an error, never a reboot-stable id.
    let err = fs_uuid_chain(&probe(None, None, None), magic::TMPFS, shm).err();
    assert!(matches!(err, Some(FsidError::NoBootId)));
    Ok(())
}

// ---- real filesystem (whatever .build/tmp is on: ext4 here, overlayfs in CI) ----

fn sys() -> Result<SysBackend> {
    Ok(SysBackend::new()?)
}

#[test]
fn regular_file_identity_matches_stat_and_is_stable() -> Result<()> {
    let t = TestDir::new("fsid-reg")?;
    let f = t.join("file");
    fs::write(&f, b"x")?;
    let b = sys()?;
    let id = b.identify_path(&f)?;
    let md = fs::symlink_metadata(&f)?;
    assert_eq!(id.inode_num, md.ino());
    assert!(!id.fs_uuid.is_empty());
    if let Ok(created) = md.created() {
        let secs = created
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        assert_eq!(u64::try_from(id.btime_sec).ok(), Some(secs));
    }
    // Same answer through an fd, and again (from the per-mount cache).
    let file = fs::File::open(&f)?;
    let id_fd = b.identify_fd(file.as_fd())?;
    assert_eq!(id_fd, id);
    assert_eq!(b.identify_path(&f)?, id);
    // The key must survive chmod, rename and a hard link (ctime changes; we never use it).
    fs::set_permissions(&f, fs::Permissions::from_mode(0o600))?;
    let moved = t.join("moved");
    fs::rename(&f, &moved)?;
    fs::hard_link(&moved, t.join("link"))?;
    let after = b.identify_path(&moved)?;
    assert_eq!(
        (
            after.fs_uuid.as_str(),
            after.subvol_id,
            after.inode_num,
            after.generation
        ),
        (
            id.fs_uuid.as_str(),
            id.subvol_id,
            id.inode_num,
            id.generation
        )
    );
    eprintln!(
        "fsid: .build/tmp file -> source {:?}, subvol {}, generation {}, btime {}",
        id.fs_uuid_source, id.subvol_id, id.generation, id.btime_sec
    );
    Ok(())
}

#[test]
fn real_ioctls_where_supported() -> Result<()> {
    let t = TestDir::new("fsid-ioctl")?;
    let f = t.join("file");
    fs::write(&f, b"x")?;
    let file = fs::File::open(&f)?;
    let b = sys()?;
    let id = b.identify_path(&f)?;
    match ioctl_fsuuid(file.as_fd())? {
        Some(u) => {
            assert_eq!(id.fs_uuid, u);
            assert_eq!(id.fs_uuid_source, UuidSource::Ioctl);
        }
        None => {
            // No uuid ioctl on this filesystem: the whole test runs on a tmpfs instead.
            crate::testenv::rerun_on_tmpfs(
                "fsid::tests::real_ioctls_where_supported",
                &crate::testenv::scratch_base(),
                "FS_IOC_GETFSUUID",
            )
            .unwrap_or_else(|e| panic!("{e}"));
            return Ok(());
        }
    }
    let generation = ioctl_generation(file.as_fd())?;
    assert_eq!(id.generation, generation);
    if generation == 0 {
        // Not a skip: generation 0 is what such a filesystem reports, and is checked.
        crate::testenv::say("note: FS_IOC_GETVERSION unsupported (or 0) on this filesystem");
    }
    // The O_PATH reopen path gives the same generation as a plain fd.
    let opath = open_raw(libc::AT_FDCWD, &cpath(&f)?, libc::O_PATH | libc::O_NOFOLLOW)?;
    assert_eq!(b.identify_fd(opath.as_fd())?.generation, generation);
    Ok(())
}

#[test]
fn symlink_is_identified_as_itself() -> Result<()> {
    let t = TestDir::new("fsid-sym")?;
    let target = t.join("target");
    fs::write(&target, b"x")?;
    let link = t.join("link");
    symlink(&target, &link)?;
    let b = sys()?;
    let l = b.identify_path(&link)?;
    assert_eq!(l.inode_num, fs::symlink_metadata(&link)?.ino());
    assert_ne!(l.inode_num, fs::metadata(&target)?.ino());
    assert_eq!(l.generation, 0); // never opened for an ioctl
    Ok(())
}

#[test]
fn fifo_is_never_opened_for_reading() -> Result<()> {
    let t = TestDir::new("fsid-fifo")?;
    let p = t.join("fifo");
    let c = cpath(&p)?;
    // SAFETY: valid NUL-terminated path.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let start = Instant::now();
    let id = sys()?.identify_path(&p)?;
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(id.generation, 0);
    assert_eq!(id.inode_num, fs::symlink_metadata(&p)?.ino());
    Ok(())
}

#[test]
fn procfs_gets_a_synthetic_id_from_mountinfo() -> Result<()> {
    let b = sys()?;
    let id = b.identify_path(Path::new("/proc/self/mountinfo"))?;
    if id.fs_uuid_source != UuidSource::Synthetic {
        // A kernel that gives procfs a uuid: no skip, the id must then be stable.
        assert_eq!(b.identify_path(Path::new("/proc/self/mountinfo"))?, id);
        return Ok(());
    }
    let c = MountCache::open()?;
    let m = mount_for_path(c.table(), Path::new("/proc/self/mountinfo"))
        .ok_or(FsidError::UnknownMount { major: 0, minor: 0 })?;
    let proc_magic = 0x9fa0;
    assert_eq!(
        id.fs_uuid,
        synth_id(proc_magic, &m.mount_point, &m.source, b"")
    );
    Ok(())
}

#[test]
fn tmpfs_uses_ioctl_or_a_boot_scoped_synthetic_id() -> Result<()> {
    // Read-only: identifies the existing /dev/shm directory, creates nothing there. Where
    // /dev/shm is missing or no tmpfs, the test runs again on a tmpfs of its own.
    let base = crate::testenv::scratch_base();
    let shm = if crate::testenv::on_tmpfs() {
        base.as_path()
    } else {
        Path::new("/dev/shm")
    };
    let b = sys()?;
    let fd = open_raw(
        libc::AT_FDCWD,
        &cpath(shm)?,
        libc::O_PATH | libc::O_NOFOLLOW,
    );
    let is_tmpfs = match &fd {
        Ok(fd) => fstatfs_type(fd.as_fd())? == magic::TMPFS,
        Err(_) => false,
    };
    let fd = match fd {
        Ok(fd) if is_tmpfs => fd,
        _ => {
            crate::testenv::rerun_on_tmpfs(
                "fsid::tests::tmpfs_uses_ioctl_or_a_boot_scoped_synthetic_id",
                &base,
                "tmpfs at /dev/shm",
            )
            .unwrap_or_else(|e| panic!("{e}"));
            return Ok(());
        }
    };
    let id = b.identify_fd(fd.as_fd())?;
    match id.fs_uuid_source {
        UuidSource::Synthetic => {
            let c = MountCache::open()?;
            let m = mount_for_path(c.table(), shm)
                .ok_or(FsidError::UnknownMount { major: 0, minor: 0 })?;
            let mut boot = fs::read("/proc/sys/kernel/random/boot_id")?;
            while boot.last().is_some_and(u8::is_ascii_whitespace) {
                boot.pop();
            }
            assert_eq!(
                id.fs_uuid,
                synth_id(magic::TMPFS, &m.mount_point, &m.source, &boot)
            );
        }
        // A kernel whose tmpfs has a uuid: it must be the ioctl's.
        UuidSource::Ioctl => {
            let dir = fs::File::open(shm)?;
            assert_eq!(ioctl_fsuuid(dir.as_fd())?, Some(id.fs_uuid.clone()));
        }
        UuidSource::ByUuid => panic!("a tmpfs has no /dev/disk/by-uuid entry: {id:?}"),
    }
    assert_eq!(b.identify_fd(fd.as_fd())?, id);
    Ok(())
}

#[test]
fn resolver_runs_the_real_backend() -> Result<()> {
    let t = TestDir::new("fsid-res")?;
    let f = t.join("file");
    fs::write(&f, b"x")?;
    let r = Resolver::new(
        sys()?,
        ResolverConfig {
            deadline: Duration::from_secs(5),
            ..ResolverConfig::default()
        },
    )?;
    let id = r.resolve(Target::Path(f.clone()))?;
    assert_eq!(id.inode_num, fs::metadata(&f)?.ino());
    let fd = OwnedFd::from(fs::File::open(&f)?);
    assert_eq!(r.resolve(Target::Fd(fd))?, id);
    assert!(matches!(
        r.resolve(Target::Path("relative".into())),
        Err(FsidError::NotAbsolute(_))
    ));
    assert!(matches!(
        r.resolve(Target::Path(t.join("missing"))),
        Err(FsidError::Io(ref e)) if e.kind() == io::ErrorKind::NotFound
    ));
    Ok(())
}

// ---- the non-blocking rule, with an injected slow backend ----

/// `/slow/...` blocks until released (a hung NFS/FUSE mount); anything else answers at once.
/// The mount hint is the first path component.
#[derive(Clone, Default)]
struct Stall(Arc<(Mutex<bool>, Condvar, AtomicUsize, AtomicBool)>);

impl Stall {
    fn release(&self) {
        *lock(&self.0.0) = true;
        self.0.1.notify_all();
    }
    fn entered(&self) -> usize {
        self.0.2.load(Ordering::Acquire)
    }
}

fn first(target: &Target) -> PathBuf {
    match target {
        Target::Path(p) => p.components().take(2).collect(),
        Target::Fd(_) => PathBuf::from("/"),
    }
}

impl Backend for Stall {
    fn identify(&self, target: &Target) -> Result<FileIdentity> {
        if first(target) == Path::new("/slow") {
            self.0.2.fetch_add(1, Ordering::AcqRel);
            let mut released = lock(&self.0.0);
            while !*released {
                released = self
                    .0
                    .1
                    .wait(released)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
        self.0.3.store(true, Ordering::Release);
        Ok(FileIdentity {
            fs_uuid: "fake".into(),
            subvol_id: 0,
            inode_num: 1,
            generation: 0,
            btime_sec: 0,
            btime_nsec: 0,
            nlink: 1,
            fs_uuid_source: UuidSource::Synthetic,
        })
    }
    fn mount_hint(&self, target: &Target) -> Option<MountHint> {
        let mp = first(target);
        Some(MountHint {
            mnt_id: u64::from(mp == Path::new("/slow")),
            mount_point: mp,
        })
    }
}

fn path(p: &str) -> Target {
    Target::Path(PathBuf::from(p))
}

#[test]
fn stalled_backend_hits_the_deadline_and_marks_the_mount_suspect() -> Result<()> {
    let stall = Stall::default();
    let deadline = Duration::from_millis(100);
    let r = Resolver::new(
        stall.clone(),
        ResolverConfig {
            workers: 2,
            max_threads: 4,
            deadline,
            ..ResolverConfig::default()
        },
    )?;
    assert!(r.resolve(path("/fast/a")).is_ok());

    let t0 = Instant::now();
    let err = r.resolve(path("/slow/x")).err();
    let took = t0.elapsed();
    assert!(
        matches!(err, Some(FsidError::Timeout(d)) if d == deadline),
        "{err:?}"
    );
    assert!(took >= deadline, "{took:?}");
    assert!(took < deadline * 5, "{took:?}");
    assert_eq!(stall.entered(), 1);

    // The hung mount now fails fast, without dispatching to (and losing) another worker.
    let t0 = Instant::now();
    let err = r.resolve(path("/slow/y")).err();
    assert!(matches!(err, Some(FsidError::SuspectMount(ref p)) if p == Path::new("/slow")));
    assert!(t0.elapsed() < Duration::from_millis(50));
    assert_eq!(stall.entered(), 1);

    // Other mounts are unaffected, and the stuck worker was replaced.
    assert!(r.resolve(path("/fast/b")).is_ok());
    assert_eq!(r.threads(), 3);

    // After an explicit clear the mount is tried again (and times out again).
    let hint = MountHint {
        mnt_id: 1,
        mount_point: "/slow".into(),
    };
    assert!(r.is_suspect(&hint));
    r.clear_suspect(&hint);
    assert!(matches!(
        r.resolve(path("/slow/z")),
        Err(FsidError::Timeout(_))
    ));
    assert_eq!(r.threads(), 4); // capped from here on
    stall.release();
    Ok(())
}

#[test]
fn saturated_pool_answers_busy_within_the_deadline_and_recovers() -> Result<()> {
    let stall = Stall::default();
    let deadline = Duration::from_millis(80);
    let r = Resolver::new(
        stall.clone(),
        ResolverConfig {
            workers: 1,
            max_threads: 1,
            queue: 1,
            deadline,
            suspect_for: Duration::from_millis(1),
        },
    )?;
    assert!(matches!(
        r.resolve(path("/slow/x")),
        Err(FsidError::Timeout(_))
    ));
    // The only worker is stuck: a request for a healthy mount is queued, never started,
    // and must come back Busy (not Timeout: that mount is not to blame) on time.
    let t0 = Instant::now();
    assert!(matches!(r.resolve(path("/fast/a")), Err(FsidError::Busy)));
    assert!(t0.elapsed() < deadline * 5);
    // The suspect mark expired after 1 ms, but the cancelled job still fills the queue
    // (1) until the worker comes back to skip it: Busy at once, nothing more dispatched.
    thread::sleep(Duration::from_millis(5));
    assert!(matches!(r.resolve(path("/slow/y")), Err(FsidError::Busy)));
    stall.release();
    // The worker comes back, skips the cancelled jobs, and serves again.
    let t0 = Instant::now();
    loop {
        match r.resolve(path("/fast/b")) {
            Ok(_) => break,
            Err(FsidError::Busy) if t0.elapsed() < Duration::from_secs(5) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[test]
fn ioctl_and_by_uuid_agree_where_both_exist() -> Result<()> {
    // Steps 1 and 2 must name a filesystem the same way, or a kernel upgrade (or an
    // unreadable file falling through to step 2) would re-key every row.
    let t = TestDir::new("fsid-agree")?;
    let dir = fs::File::open(t.path())?;
    let c = MountCache::open()?;
    let m = mount_for_path(c.table(), t.path())
        .ok_or(FsidError::UnknownMount { major: 0, minor: 0 })?;
    let disk = by_uuid(Path::new("/dev/disk/by-uuid"), m.major, m.minor, &m.source);
    match (ioctl_fsuuid(dir.as_fd())?, disk) {
        (Some(a), Some(b)) => assert_eq!(a, b),
        // The ioctl but no by-uuid entry (a tmpfs): the kernel's real uuid, put in a
        // by-uuid fixture (pointing at /dev/null, 1:3), must come back from step 2 as is.
        (Some(a), None) => {
            assert!(
                a.len() == 36
                    && a.bytes()
                        .enumerate()
                        .all(|(i, c)| if [8, 13, 18, 23].contains(&i) {
                            c == b'-'
                        } else {
                            c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
                        }),
                "the ioctl's uuid is not in by-uuid's form: {a}"
            );
            let fixture = t.join("by-uuid");
            fs::create_dir(&fixture)?;
            std::os::unix::fs::symlink("/dev/null", fixture.join(&a))?;
            assert_eq!(by_uuid(&fixture, 1, 3, b"").as_deref(), Some(a.as_str()));
        }
        // No uuid ioctl here (btrfs): the whole test runs on a tmpfs instead.
        (None, _) => crate::testenv::rerun_on_tmpfs(
            "fsid::tests::ioctl_and_by_uuid_agree_where_both_exist",
            &crate::testenv::scratch_base(),
            "FS_IOC_GETFSUUID",
        )
        .unwrap_or_else(|e| panic!("{e}")),
    }
    Ok(())
}

// ---- regression tests for the M4 review ----

fn euid_is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// The metadata key of an identity (btime is not part of it).
fn key(i: &FileIdentity) -> (&str, u64, u64, u64) {
    (i.fs_uuid.as_str(), i.subvol_id, i.inode_num, i.generation)
}

#[test]
fn unreadable_file_or_dir_never_gets_a_different_key() -> Result<()> {
    // chmod changes ctime, and AGENTS.md forbids keys that change with it. Before the
    // fix an unreadable file silently got generation 0 (ext4: a different key).
    if euid_is_root() {
        crate::testenv::missing(
            "fsid::tests::unreadable_file_or_dir_never_gets_a_different_key",
            "non-root user (root reads a file of mode 000)",
        );
        return Ok(());
    }
    let t = TestDir::new("fsid-unreadable")?;
    let f = t.join("file");
    fs::write(&f, b"x")?;
    let d = t.join("dir");
    fs::create_dir(&d)?;
    let b = sys()?;
    for (p, locked) in [(&f, 0o000), (&d, 0o311)] {
        let before = b.identify_path(p)?;
        fs::set_permissions(p, fs::Permissions::from_mode(locked))?;
        let after = b.identify_path(p);
        let fd = open_raw(libc::AT_FDCWD, &cpath(p)?, libc::O_PATH | libc::O_NOFOLLOW)?;
        let after_fd = b.identify_fd(fd.as_fd());
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
        for r in [after, after_fd] {
            match r {
                Ok(id) => assert_eq!(key(&id), key(&before), "{}", p.display()),
                Err(FsidError::Io(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{}", p.display());
                    assert_ne!(before.generation, 0, "no generations: 0 is the right key");
                }
                Err(e) => return Err(e),
            }
        }
        assert_eq!(key(&b.identify_path(p)?), key(&before));
    }
    Ok(())
}

#[test]
fn unreadable_file_without_generations_keeps_generation_0() -> Result<()> {
    // procfs has no FS_IOC_GETVERSION: an unreadable proc file keeps the readable key.
    // /proc/1/environ alone made the test skip under hidepid=invisible (no /proc/1 at
    // all); root-only files outside the pid directories are never hidden.
    if euid_is_root() {
        crate::testenv::missing(
            "fsid::tests::unreadable_file_without_generations_keeps_generation_0",
            "non-root user (root reads every proc file)",
        );
        return Ok(());
    }
    let candidates = [
        "/proc/kcore",
        "/proc/kmsg",
        "/proc/sysrq-trigger",
        "/proc/1/environ",
    ];
    let Some(p) = candidates
        .iter()
        .map(Path::new)
        .find(|p| fs::symlink_metadata(p).is_ok() && fs::File::open(p).is_err())
    else {
        crate::testenv::missing(
            "fsid::tests::unreadable_file_without_generations_keeps_generation_0",
            &format!("unreadable procfs file (tried {candidates:?})"),
        );
        return Ok(());
    };
    let id = sys()?.identify_path(p)?;
    assert_eq!(id.generation, 0);
    Ok(())
}

#[test]
fn mountinfo_keeps_an_empty_source_field() {
    // `mount -t tmpfs "" /mnt` prints two spaces; the source must not swallow the super
    // options (which change on remount and would change synthetic ids).
    let t = parse_mountinfo(b"295 273 0:60 / /mnt rw,relatime - tmpfs  rw,uid=1000\n");
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].fstype, b"tmpfs");
    assert_eq!(t[0].source, b"");
    // A missing field (truncated line) is still skipped, never a panic.
    assert!(parse_mountinfo(b"295 273 0:60 / /mnt rw - tmpfs").is_empty());
    assert!(parse_mountinfo(b"295  273 0:60 / /mnt rw - tmpfs x rw").is_empty());
}

/// A [`Stall`] whose first `mount_hint` answer is "unknown" (cache busy).
struct FirstHintMissing(Stall, AtomicUsize);

impl Backend for FirstHintMissing {
    fn identify(&self, target: &Target) -> Result<FileIdentity> {
        self.0.identify(target)
    }
    fn mount_hint(&self, target: &Target) -> Option<MountHint> {
        if self.1.fetch_add(1, Ordering::AcqRel) == 0 {
            return None;
        }
        self.0.mount_hint(target)
    }
}

#[test]
fn timeout_blames_the_mount_even_if_the_first_hint_was_skipped() -> Result<()> {
    // SysBackend::mount_hint uses try_lock; before the fix a contended cache at the start
    // of resolve() meant a hung mount was never marked and each retry lost a worker.
    let stall = Stall::default();
    let r = Resolver::new(
        FirstHintMissing(stall.clone(), AtomicUsize::new(0)),
        ResolverConfig {
            workers: 2,
            max_threads: 8,
            deadline: Duration::from_millis(200),
            ..ResolverConfig::default()
        },
    )?;
    assert!(matches!(
        r.resolve(path("/slow/a")),
        Err(FsidError::Timeout(_))
    ));
    let again = r.resolve(path("/slow/b")).err();
    stall.release();
    assert!(
        matches!(again, Some(FsidError::SuspectMount(_))),
        "{again:?}"
    );
    assert_eq!(
        stall.entered(),
        1,
        "a second worker was sent into the hung mount"
    );
    Ok(())
}

#[test]
fn huge_suspect_span_never_panics() -> Result<()> {
    // Before the fix: `Instant + Duration::MAX` panicked on the caller's thread.
    let stall = Stall::default();
    let r = Resolver::new(
        stall.clone(),
        ResolverConfig {
            suspect_for: Duration::MAX,
            ..ResolverConfig::default()
        },
    )?;
    let first = r.resolve(path("/slow/a")).err();
    let second = r.resolve(path("/slow/b")).err();
    stall.release();
    assert!(matches!(first, Some(FsidError::Timeout(_))), "{first:?}");
    assert!(
        matches!(second, Some(FsidError::SuspectMount(_))),
        "{second:?}"
    );
    Ok(())
}

#[test]
fn dropping_the_resolver_lets_idle_workers_exit() -> Result<()> {
    let r = Resolver::new(Stall::default(), ResolverConfig::default())?;
    assert!(r.resolve(path("/fast/a")).is_ok());
    let shared = Arc::clone(&r.shared);
    assert_eq!(shared.threads.load(Ordering::Acquire), 4);
    drop(r);
    let t0 = Instant::now();
    while shared.threads.load(Ordering::Acquire) != 0 {
        assert!(t0.elapsed() < Duration::from_secs(5), "idle workers leaked");
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

#[test]
fn refresh_retries_after_a_failed_reread() -> std::result::Result<(), io::Error> {
    // poll() itself clears the kernel's change flag, so a failed re-read must be retried
    // (a directory fd stands in for a read that fails).
    let t = TestDir::new("fsid-stale")?;
    let mut c = MountCache::from_text(FIXTURE);
    c.file = Some(fs::File::open(t.path())?);
    c.stale = true;
    assert!(c.refresh().is_err());
    assert!(c.stale, "the change was forgotten after a failed read");
    assert!(c.refresh().is_err(), "not retried");
    assert_eq!(c.table().len(), 11, "the old table is kept");
    Ok(())
}

#[test]
fn statx_layout_matches_the_kernel_uapi() {
    // <linux/stat.h>: the kernel writes all 256 bytes; the fields we read are at these
    // offsets (STATX_MNT_ID is the mountinfo id, STATX_MNT_ID_UNIQUE is not requested).
    assert_eq!(mem::size_of::<libc::statx>(), 256);
    assert_eq!(mem::offset_of!(libc::statx, stx_mask), 0);
    assert_eq!(mem::offset_of!(libc::statx, stx_mode), 28);
    assert_eq!(mem::offset_of!(libc::statx, stx_ino), 32);
    assert_eq!(mem::offset_of!(libc::statx, stx_btime), 80);
    assert_eq!(mem::offset_of!(libc::statx, stx_dev_major), 136);
    assert_eq!(mem::offset_of!(libc::statx, stx_mnt_id), 144);
    assert_eq!(mem::offset_of!(libc::statx, stx_subvol), 160);
    assert_eq!(STATX_MASK & 0x4000, 0); // STATX_MNT_ID_UNIQUE
}

#[test]
fn btrfs_ino_lookup_matches_the_kernel_header() {
    // _IOWR(BTRFS_IOCTL_MAGIC 0x94, 18, struct btrfs_ioctl_ino_lookup_args) from
    // <linux/btrfs.h>: { __u64 treeid; __u64 objectid; char name[4080]; }.
    assert_eq!(mem::size_of::<BtrfsInoLookupArgs>(), 4096);
    assert_eq!(BTRFS_IOC_INO_LOOKUP, 0xD000_9412);
    assert_eq!(magic::BTRFS, 0x9123_683E);
}

#[test]
fn btrfs_lookup_on_another_filesystem_is_an_error_not_a_subvolume() -> Result<()> {
    let t = TestDir::new("fsid-btrfs")?;
    let dir = fs::File::open(t.path())?;
    if fstatfs_type(dir.as_fd())? == magic::BTRFS {
        assert!(btrfs_subvol(dir.as_fd())? >= 5);
    } else {
        assert!(btrfs_subvol(dir.as_fd()).is_err());
    }
    Ok(())
}
