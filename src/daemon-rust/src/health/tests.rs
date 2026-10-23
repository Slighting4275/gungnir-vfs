use super::*;
use crate::{
    fsid::{MountCache, ResolverConfig, SysBackend},
    ipc, md, mdsvc,
    store::{self, DbConfig, Store, StoreConfig},
    testdir::TestDir,
};
use std::{collections::HashMap, sync::Condvar};

fn ent(id: u64, mp: &str, fstype: &str) -> MountEntry {
    MountEntry {
        mnt_id: id,
        parent_id: 1,
        major: 0,
        minor: u32::try_from(id).unwrap_or(0),
        root: b"/".to_vec(),
        mount_point: mp.as_bytes().to_vec(),
        fstype: fstype.as_bytes().to_vec(),
        source: format!("src{id}").into_bytes(),
    }
}

fn cfg() -> HealthConfig {
    HealthConfig {
        deadline: Duration::from_millis(100),
        interval: Duration::from_millis(200),
        slow_after: Duration::from_millis(50),
        backoff_base: Duration::from_millis(100),
        backoff_max: Duration::from_millis(400),
        max_threads: 2,
        max_stuck: 3,
    }
}

const MS: Duration = Duration::from_millis(1);

// ---- mountinfo fixtures ----------------------------------------------------------

/// A desktop with every kind of remote mount, a nested and an over-mounted one, and the
/// kernel's octal escapes (proc(5)).
const FIXTURE: &[u8] = b"\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
23 22 0:21 / /proc rw,nosuid shared:5 - proc proc rw
24 22 0:24 / /run rw,nosuid shared:6 - tmpfs tmpfs rw,mode=755
40 22 0:50 / /mnt/nfs rw,relatime shared:20 - nfs4 server:/export rw,vers=4.2
41 40 0:51 / /mnt/nfs/scratch rw shared:21 - tmpfs tmpfs rw
42 22 0:52 / /mnt/smb rw - cifs //nas/share rw
43 22 0:53 / /mnt/my\\040box rw,nosuid,nodev - fuse.sshfs user@host:/srv rw
44 24 0:54 / /run/user/1000/gvfs rw,nosuid,nodev - fuse.gvfsd-fuse gvfsd-fuse rw
45 22 8:17 / /media/usb rw - fuseblk /dev/sdb1 rw
46 22 0:55 / /mnt/nfs rw - tmpfs tmpfs rw
";

#[test]
fn remote_and_fuse_mounts_are_probed_local_ones_never() {
    let t = fsid::parse_mountinfo(FIXTURE);
    assert_eq!(t.len(), 10);
    let probed: Vec<u64> = t
        .iter()
        .filter(|e| is_probed(&e.fstype))
        .map(|e| e.mnt_id)
        .collect();
    assert_eq!(probed, [40, 42, 43, 44, 45]);
    for fs in [
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "fuse",
        "fuse.rclone",
        "9p",
        "ceph",
    ] {
        assert!(is_probed(fs.as_bytes()), "{fs}");
    }
    for fs in [
        "ext4", "btrfs", "xfs", "tmpfs", "proc", "fusectl", "overlay",
    ] {
        assert!(!is_probed(fs.as_bytes()), "{fs}");
    }
    // Only the probed ones get a job, at once.
    let now = Instant::now();
    let mut c = Core::new(
        HealthConfig {
            max_threads: 16,
            ..cfg()
        },
        Vec::new(),
    );
    assert!(c.set_table(t, now).is_empty());
    let jobs: Vec<u64> = c.due(now).iter().map(|j| j.entry.mnt_id).collect();
    assert_eq!(jobs, [40, 42, 43, 44, 45]);
    assert_eq!(c.running(), 5);
    let sshfs = c.lookup(b"/mnt/my box/x").map(|r| r.hint.mnt_id);
    assert_eq!(sshfs, Some(43), "octal escapes are undone");
}

#[test]
fn lookups_are_lexical_longest_prefix_and_later_mounts_win_ties() {
    let now = Instant::now();
    let mut c = Core::new(cfg(), Vec::new());
    c.set_table(fsid::parse_mountinfo(FIXTURE), now);
    let id = |p: &str| c.lookup(p.as_bytes()).map(|r| r.hint.mnt_id);
    assert_eq!(id("/"), Some(22));
    assert_eq!(id("/etc/passwd"), Some(22));
    assert_eq!(id("/mnt/nfs/scratch/f"), Some(41));
    assert_eq!(id("/mnt/nfs/../smb/x"), Some(42));
    assert_eq!(id("//mnt/./smb"), Some(42));
    assert_eq!(id("/mnt/smbx"), Some(22), "not a path prefix");
    // 46 is mounted on top of the NFS mount point: it hides 40.
    assert_eq!(id("/mnt/nfs/a"), Some(46));
    assert_eq!(c.by_id(40).map(|r| r.state), Some(Health::Healthy));
    assert_eq!(c.by_id(9999), None);
}

// ---- the state machine, deterministic ------------------------------------------------

fn core_with(entries: Vec<MountEntry>, now: Instant) -> Core {
    let mut c = Core::new(cfg(), Vec::new());
    c.set_table(entries, now);
    c
}

#[test]
fn a_probe_past_its_deadline_makes_the_mount_hung_once() {
    let t0 = Instant::now();
    let mut c = core_with(vec![ent(1, "/", "ext4"), ent(2, "/n", "nfs")], t0);
    let jobs = c.due(t0);
    assert_eq!(jobs.len(), 1);
    assert!(c.expire(t0 + 99 * MS).is_empty());
    assert_eq!(c.next_wake(), Some(t0 + 100 * MS));
    let ch = c.expire(t0 + 100 * MS);
    assert_eq!(ch.len(), 1);
    assert_eq!(
        (ch[0].from, ch[0].to, ch[0].removed),
        (Health::Healthy, Health::Hung, false)
    );
    assert!(c.expire(t0 + 500 * MS).is_empty(), "reported once");
    assert_eq!(c.lookup(b"/n/f").map(|r| r.state), Some(Health::Hung));
    assert_eq!(c.blocked().len(), 1);
    // Stuck: no second probe for that mount, however long it takes.
    assert!(c.due(t0 + Duration::from_secs(60)).is_empty());
    assert_eq!(c.next_wake(), None, "only its thread can report now");
}

#[test]
fn backoff_doubles_per_failure_up_to_the_cap_and_recovery_resets_it() {
    let t0 = Instant::now();
    let mut c = core_with(vec![ent(2, "/n", "nfs")], t0);
    let mut now = t0;
    let mut waits = Vec::new();
    for _ in 0..5 {
        let j = c.due(now).pop().expect("a probe is due");
        // Answered, but after the deadline: still a failure.
        now += 150 * MS;
        let ch = c.complete(j.token, Outcome::Answered, 150 * MS, now);
        assert!(ch.iter().all(|x| x.to == Health::Hung));
        let next = c.next_wake().expect("scheduled");
        waits.push(next - now);
        assert!(c.due(next - MS).is_empty(), "not before the backoff");
        now = next;
    }
    assert_eq!(waits, [100 * MS, 200 * MS, 400 * MS, 400 * MS, 400 * MS]);
    // A prompt answer: healthy again, back to the normal interval.
    let j = c.due(now).pop().expect("due");
    let ch = c.complete(j.token, Outcome::Answered, 5 * MS, now + 5 * MS);
    assert_eq!(ch.len(), 1);
    assert_eq!((ch[0].from, ch[0].to), (Health::Hung, Health::Healthy));
    assert_eq!(c.next_wake(), Some(now + 5 * MS + 200 * MS));
    assert_eq!(cfg().backoff(1), 100 * MS);
    assert_eq!(cfg().backoff(u32::MAX), 400 * MS, "no overflow");
}

#[test]
fn slow_dead_and_timed_out_answers() {
    let t0 = Instant::now();
    let mut c = core_with(vec![ent(2, "/n", "nfs"), ent(3, "/f", "fuse.sshfs")], t0);
    let jobs = c.due(t0);
    assert_eq!(jobs.len(), 2);
    let ch = c.complete(jobs[0].token, Outcome::Answered, 60 * MS, t0 + 60 * MS);
    assert_eq!(ch[0].to, Health::Slow);
    let ch = c.complete(jobs[1].token, Outcome::Dead(libc::ENOTCONN), MS, t0 + MS);
    assert_eq!(ch[0].to, Health::Gone);
    assert!(Health::Gone.blocks() && Health::Hung.blocks());
    assert!(!Health::Slow.blocks() && !Health::Healthy.blocks());
    let now = t0 + Duration::from_secs(1);
    let jobs = c.due(now);
    let ch = c.complete(jobs[0].token, Outcome::TimedOut, MS, now);
    assert_eq!((ch[0].from, ch[0].to), (Health::Slow, Health::Hung));
    assert_eq!(
        classify_error(&io::Error::from_raw_os_error(libc::ENOTCONN)),
        Outcome::Dead(libc::ENOTCONN)
    );
    assert_eq!(
        classify_error(&io::Error::from_raw_os_error(libc::ESTALE)),
        Outcome::Dead(libc::ESTALE)
    );
    assert_eq!(
        classify_error(&io::Error::from_raw_os_error(libc::ETIMEDOUT)),
        Outcome::TimedOut
    );
    assert_eq!(
        classify_error(&io::Error::from_raw_os_error(libc::EACCES)),
        Outcome::Answered
    );
}

#[test]
fn the_thread_cap_counts_stuck_probes() {
    let t0 = Instant::now();
    let mut c = core_with(
        (2..8).map(|i| ent(i, &format!("/n{i}"), "nfs")).collect(),
        t0,
    );
    let first = c.due(t0);
    assert_eq!(first.len(), 2, "cap of 2 within the deadline");
    assert!(c.due(t0 + 50 * MS).is_empty(), "both still within it");
    assert_eq!(c.next_wake(), Some(t0 + 100 * MS));
    // Both stuck past it: they move to the stuck budget (3), two more may start.
    c.expire(t0 + Duration::from_secs(1));
    assert_eq!((c.running(), c.stuck()), (2, 2));
    let second = c.due(t0 + Duration::from_secs(1));
    assert_eq!(second.len(), 2);
    c.expire(t0 + Duration::from_secs(2));
    // 4 stuck > max_stuck 3: only one more thread in all (2 + 3).
    let third = c.due(t0 + Duration::from_secs(2));
    assert_eq!(third.len(), 1);
    assert_eq!(c.running(), 5);
    c.expire(t0 + Duration::from_secs(3));
    assert!(
        c.due(t0 + Duration::from_secs(3)).is_empty(),
        "budget used up"
    );
    assert_eq!(c.next_wake(), None);
    // One stuck thread finally returns: its slot goes to the next mount.
    c.complete(
        first[0].token,
        Outcome::Answered,
        Duration::from_secs(3),
        t0 + Duration::from_secs(3),
    );
    let next = c.due(t0 + Duration::from_secs(3));
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].entry.mnt_id, 7);
    assert_eq!(c.running(), 5);
    c.abort(next[0].token, t0 + Duration::from_secs(3));
    assert_eq!(c.running(), 4);
}

/// Review M7: a thread stuck in `statfs` on a hung mount is never reclaimed. With the
/// stuck ones counted against `max_threads`, `max_threads` hung mounts stopped every
/// other probe for good: a mount that hung later was never reported, a slow or
/// recovered one never re-probed.
#[test]
fn hung_mounts_do_not_stop_the_probing_of_the_others() {
    let t0 = Instant::now();
    // As many hung mounts as the cap (2), then a healthy one.
    let mut c = core_with(
        vec![
            ent(2, "/h2", "nfs"),
            ent(3, "/h3", "nfs"),
            ent(4, "/ok", "nfs"),
        ],
        t0,
    );
    assert_eq!(c.due(t0).len(), 2);
    let ch = c.expire(t0 + Duration::from_secs(1));
    assert_eq!(ch.len(), 2, "both hung");
    let later = c.due(t0 + Duration::from_secs(1));
    assert_eq!(
        later.iter().map(|j| j.entry.mnt_id).collect::<Vec<_>>(),
        [4],
        "the third mount is still probed"
    );
    // It answers, and keeps being probed every interval.
    let now = t0 + Duration::from_secs(1) + MS;
    c.complete(later[0].token, Outcome::Answered, MS, now);
    assert!(c.next_wake().is_some_and(|w| w <= now + 200 * MS));
    let again = c.due(now + 200 * MS);
    assert_eq!(again.len(), 1);
    // Now it hangs too: reported, although two older probes are stuck for good.
    let ch = c.expire(now + 300 * MS);
    assert_eq!(ch.len(), 1);
    assert_eq!((ch[0].hint.mnt_id, ch[0].to), (4, Health::Hung));
}

#[test]
fn unmounts_and_reused_ids_are_reported_and_queries_by_id_say_gone() {
    let t0 = Instant::now();
    let mut c = core_with(vec![ent(1, "/", "ext4"), ent(2, "/n", "nfs")], t0);
    let j = c.due(t0).pop().expect("due");
    c.expire(t0 + Duration::from_secs(1));
    // umount -l of the hung mount.
    let ch = c.set_table(vec![ent(1, "/", "ext4")], t0 + Duration::from_secs(2));
    assert_eq!(ch.len(), 1);
    assert!(ch[0].removed && ch[0].from == Health::Hung);
    assert_eq!(c.by_id(2).map(|r| r.state), Some(Health::Gone));
    assert_eq!(c.lookup(b"/n/f").map(|r| r.hint.mnt_id), Some(1));
    // Its stuck thread returns later: nothing to update, the slot is released.
    assert!(
        c.complete(j.token, Outcome::Answered, MS, t0 + Duration::from_secs(3))
            .is_empty()
    );
    assert_eq!(c.running(), 0);
    // The same id for a different mount: old one removed, new one probed fresh.
    c.set_table(vec![ent(1, "/", "ext4"), ent(5, "/a", "nfs")], t0);
    let mut other = ent(5, "/b", "cifs");
    other.source = b"//x/y".to_vec();
    let ch = c.set_table(vec![ent(1, "/", "ext4"), other], t0);
    assert_eq!(ch.len(), 1);
    assert!(ch[0].removed);
    assert_eq!(c.lookup(b"/b").map(|r| r.hint.mnt_id), Some(5));
    // Unchanged entries keep their state across re-reads.
    let mut d = core_with(vec![ent(2, "/n", "nfs")], t0);
    d.due(t0);
    d.expire(t0 + Duration::from_secs(1));
    assert!(d.set_table(vec![ent(2, "/n", "nfs")], t0).is_empty());
    assert_eq!(d.by_id(2).map(|r| r.state), Some(Health::Hung));
}

#[test]
fn the_snapshot_lists_unhealthy_mounts_and_everything_at_or_below_them() {
    let t0 = Instant::now();
    let mut c = Core::new(
        HealthConfig {
            max_threads: 16,
            ..cfg()
        },
        Vec::new(),
    );
    c.set_table(fsid::parse_mountinfo(FIXTURE), t0);
    assert!(c.listed().is_empty(), "all healthy: nothing to send");
    let jobs = c.due(t0);
    // Everything but the NFS mount answers promptly.
    for j in &jobs {
        if j.entry.mnt_id != 40 {
            c.complete(j.token, Outcome::Answered, MS, t0 + MS);
        }
    }
    c.expire(t0 + Duration::from_secs(1));
    let ids: Vec<(u64, Health)> = c.listed().iter().map(|(i, h, _)| (*i, *h)).collect();
    // The hung NFS mount, the tmpfs inside it and the tmpfs on top of it, in table order.
    assert_eq!(
        ids,
        [
            (40, Health::Hung),
            (41, Health::Healthy),
            (46, Health::Healthy)
        ]
    );
}

#[test]
fn snapshots_encode_across_slots_and_flag_what_does_not_fit() {
    let (epoch, flags, entries) = decode_event(&encode_snapshot(7, &[])[0]).expect("valid");
    assert_eq!((epoch, flags, entries.len()), (7, EV_FIRST | EV_LAST, 0));
    let one = vec![(3, Health::Hung, b"/mnt/nfs".to_vec())];
    let s = encode_snapshot(8, &one);
    assert_eq!(s.len(), 1);
    assert_eq!(
        decode_event(&s[0]),
        Ok((8, EV_FIRST | EV_LAST, one.clone()))
    );
    // 40 entries of ~1 KiB: 4 per slot, the 4-slot cap cuts the rest.
    let big: Vec<Listed> = (0..40)
        .map(|i| {
            (
                i,
                Health::Healthy,
                format!("/{}", "x".repeat(1000 + usize::try_from(i).unwrap_or(0))).into_bytes(),
            )
        })
        .collect();
    let s = encode_snapshot(9, &big);
    assert_eq!(s.len(), MAX_EVENT_SLOTS);
    let mut got = Vec::new();
    for (i, slot) in s.iter().enumerate() {
        assert!(slot.len() <= PAYLOAD_MAX);
        let (e, f, mut v) = decode_event(slot).expect("valid");
        assert_eq!(e, 9);
        assert_eq!(f & EV_FIRST != 0, i == 0);
        assert_eq!(f & EV_LAST != 0, i == s.len() - 1);
        assert_eq!(f & EV_INCOMPLETE != 0, i == s.len() - 1);
        got.append(&mut v);
    }
    assert_eq!(got[..], big[..got.len()]);
    // A mount point that cannot fit any slot is skipped and flagged.
    let huge = vec![(1, Health::Hung, vec![b'/'; PAYLOAD_MAX])];
    let (_, f, v) = decode_event(&encode_snapshot(1, &huge)[0]).expect("valid");
    assert!(v.is_empty() && f & EV_INCOMPLETE != 0);
    // Malformed payloads are refused.
    assert!(decode_event(&[0; 10]).is_err());
    let mut bad = encode_snapshot(1, &one).remove(0);
    bad.push(0);
    assert!(decode_event(&bad).is_err());
}

// ---- the monitor, with a probe backend that blocks ------------------------------------

#[derive(Clone, Copy)]
enum Mode {
    Block,
    Answer(Duration),
    Dead,
}

#[derive(Default)]
struct Ctl {
    modes: Mutex<HashMap<Vec<u8>, Mode>>,
    calls: Mutex<HashMap<Vec<u8>, usize>>,
    cv: Condvar,
}

impl Ctl {
    fn set(&self, mp: &str, m: Mode) {
        lock(&self.modes).insert(mp.as_bytes().to_vec(), m);
        self.cv.notify_all();
    }
    fn calls(&self, mp: &str) -> usize {
        lock(&self.calls).get(mp.as_bytes()).copied().unwrap_or(0)
    }
}

struct TestProber(Arc<Ctl>);

impl Prober for TestProber {
    fn probe(&self, m: &MountEntry) -> Outcome {
        *lock(&self.0.calls)
            .entry(m.mount_point.clone())
            .or_default() += 1;
        let mut g = lock(&self.0.modes);
        loop {
            match g.get(&m.mount_point).copied() {
                Some(Mode::Block) => {
                    g = self.0.cv.wait(g).unwrap_or_else(PoisonError::into_inner);
                }
                Some(Mode::Answer(d)) => {
                    drop(g);
                    thread::sleep(d);
                    return Outcome::Answered;
                }
                Some(Mode::Dead) => return Outcome::Dead(libc::ENOTCONN),
                None => return Outcome::Answered,
            }
        }
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<(bool, u64)>>);

impl SuspectSink for Sink {
    fn mark(&self, h: MountHint) {
        lock(&self.0).push((true, h.mnt_id));
    }
    fn clear(&self, h: &MountHint) {
        lock(&self.0).push((false, h.mnt_id));
    }
}

fn wait_for(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < timeout, "timed out waiting for {what}");
        thread::sleep(2 * MS);
    }
}

fn state(m: &Monitor, p: &str) -> Option<Health> {
    m.lookup(p.as_bytes()).map(|r| r.state)
}

#[test]
fn monitor_detects_a_hang_marks_the_resolver_and_recovers() {
    let ctl = Arc::new(Ctl::default());
    ctl.set("/n", Mode::Block);
    let table = vec![ent(1, "/", "ext4"), ent(2, "/n", "nfs4")];
    let t0 = Instant::now();
    let m = Monitor::start(
        cfg(),
        Arc::new(TestProber(Arc::clone(&ctl))),
        Source::Fixed(table),
        Vec::new(),
    )
    .expect("monitor");
    let sink = Arc::new(Sink::default());
    let s: Arc<dyn SuspectSink> = sink.clone();
    m.set_sink(Arc::downgrade(&s));
    wait_for("hung", Duration::from_secs(2), || {
        state(&m, "/n/x") == Some(Health::Hung)
    });
    let took = t0.elapsed();
    assert!(took >= 90 * MS, "not before the deadline ({took:?})");
    assert_eq!(*lock(&sink.0), [(true, 2)]);
    assert_eq!(
        m.blocking_mount(Path::new("/n/x")).map(|h| h.mnt_id),
        Some(2)
    );
    assert_eq!(m.blocking_mount(Path::new("/etc")), None);
    // One in flight: however long it stays stuck, no second probe is started.
    thread::sleep(500 * MS);
    assert_eq!(ctl.calls("/n"), 1);
    assert_eq!(m.probe_threads(), 1);
    // The stuck probe returns (late: still a failure), then the backoff probe answers.
    ctl.set("/n", Mode::Answer(MS));
    wait_for("healthy", Duration::from_secs(3), || {
        state(&m, "/n/x") == Some(Health::Healthy)
    });
    assert!(ctl.calls("/n") >= 2);
    assert_eq!(*lock(&sink.0), [(true, 2), (false, 2)]);
    // Then it is probed every interval; a dead server makes it gone.
    ctl.set("/n", Mode::Dead);
    wait_for("gone", Duration::from_secs(2), || {
        state(&m, "/n/x") == Some(Health::Gone)
    });
    assert_eq!(lock(&sink.0).last(), Some(&(true, 2)));
    // An unmount clears it.
    m.set_table(vec![ent(1, "/", "ext4")]);
    assert_eq!(lock(&sink.0).last(), Some(&(false, 2)));
    assert_eq!(m.by_id(2).map(|r| r.state), Some(Health::Gone));
    m.stop();
}

/// A resolver that takes its time to note a mark (lock contention, a busy machine).
#[derive(Default)]
struct SlowSink(Mutex<Vec<(bool, u64)>>);

impl SuspectSink for SlowSink {
    fn mark(&self, h: MountHint) {
        thread::sleep(30 * MS);
        lock(&self.0).push((true, h.mnt_id));
    }
    fn clear(&self, h: &MountHint) {
        thread::sleep(30 * MS);
        lock(&self.0).push((false, h.mnt_id));
    }
}

/// Review M7 (the flake in `monitor_detects_a_hang_marks_the_resolver_and_recovers`,
/// 2 in 300 runs under load): the resolver was told after the new state was visible to
/// lookups, outside the core lock, so a reader could see a mount hung (or healthy again)
/// while the resolver still disagreed; marks and clears from two threads could also land
/// out of order, and a hang found while `set_sink` ran was never marked at all.
#[test]
fn the_resolver_agrees_with_every_state_a_lookup_sees() {
    let ctl = Arc::new(Ctl::default());
    ctl.set("/n", Mode::Block);
    let m = Monitor::start(
        cfg(),
        Arc::new(TestProber(Arc::clone(&ctl))),
        Source::Fixed(vec![ent(1, "/", "ext4"), ent(2, "/n", "nfs4")]),
        Vec::new(),
    )
    .expect("monitor");
    let sink = Arc::new(SlowSink::default());
    let s: Arc<dyn SuspectSink> = sink.clone();
    m.set_sink(Arc::downgrade(&s));
    wait_for("hung", Duration::from_secs(2), || {
        state(&m, "/n/x") == Some(Health::Hung)
    });
    assert_eq!(*lock(&sink.0), [(true, 2)], "marked before it is seen hung");
    ctl.set("/n", Mode::Answer(MS));
    wait_for("not hung", Duration::from_secs(3), || {
        !state(&m, "/n/x").is_some_and(Health::blocks)
    });
    assert_eq!(
        *lock(&sink.0),
        [(true, 2), (false, 2)],
        "cleared before it is seen"
    );
    m.stop();
}

#[test]
fn monitor_never_exceeds_its_thread_cap_and_reports_slow_mounts() {
    let ctl = Arc::new(Ctl::default());
    let mut table = vec![ent(1, "/", "ext4")];
    for i in 2..7 {
        let mp = format!("/h{i}");
        ctl.set(&mp, Mode::Block);
        table.push(ent(i, &mp, "fuse.sshfs"));
    }
    ctl.set("/slow", Mode::Answer(60 * MS));
    table.push(ent(9, "/slow", "cifs"));
    let m = Monitor::start(
        HealthConfig {
            max_threads: 3,
            max_stuck: 1,
            ..cfg()
        },
        Arc::new(TestProber(Arc::clone(&ctl))),
        Source::Fixed(table),
        Vec::new(),
    )
    .expect("monitor");
    // 3 within the deadline, then they are stuck: 1 more (3 + 1 threads in all).
    wait_for("four hung", Duration::from_secs(2), || {
        (2..7)
            .filter(|i| state(&m, &format!("/h{i}")) == Some(Health::Hung))
            .count()
            == 4
    });
    thread::sleep(300 * MS);
    assert_eq!(m.probe_threads(), 4, "max_threads + max_stuck");
    let started: usize = (2..7).map(|i| ctl.calls(&format!("/h{i}"))).sum();
    assert_eq!(started, 4);
    assert_eq!(ctl.calls("/slow"), 0, "no room left for it");
    // Free them all: every mount gets probed; the slow one is reported slow.
    for i in 2..7 {
        ctl.set(&format!("/h{i}"), Mode::Answer(MS));
    }
    wait_for("slow", Duration::from_secs(3), || {
        state(&m, "/slow") == Some(Health::Slow)
    });
    wait_for("all healthy", Duration::from_secs(3), || {
        (2..7).all(|i| state(&m, &format!("/h{i}")) == Some(Health::Healthy))
    });
    assert!(m.probe_threads() <= 4);
    m.stop();
}

// ---- over a real socket, through the resolver -------------------------------------------

fn health_query(
    c: &mut md::Client,
    by: u8,
    arg: &[u8],
) -> md::ClientResult<(u64, Health, Vec<u8>)> {
    let mut p = vec![by];
    p.extend_from_slice(arg);
    let b = c.raw_call(MSG_HEALTH_QUERY, &p)?;
    let mut r = md::Reader(&b);
    let id = r.u64()?;
    let st = Health::from_code(r.u8()?).ok_or(md::MdError::BadRequest)?;
    let _probed = r.u8()?;
    let _lat = r.u32()?;
    let mp = r.blob16()?.to_vec();
    r.end()?;
    Ok((id, st, mp))
}

/// The next health event within `timeout` (other messages are skipped).
fn next_event(c: &mut md::Client, timeout: Duration) -> (u64, u8, Vec<Listed>) {
    let t0 = Instant::now();
    loop {
        let left = timeout.saturating_sub(t0.elapsed());
        let m = c.recv(left).expect("an event in time");
        if m.kind == MSG_HEALTH_EVENT {
            assert_eq!(m.seq, 0);
            return decode_event(m.payload()).expect("well-formed event");
        }
    }
}

#[test]
fn over_a_socket_subscribers_get_events_and_hung_paths_fail_fast() -> crate::Result<()> {
    let dir = TestDir::new("health")?;
    let hung_dir = dir.join("hung");
    fs::create_dir(&hung_dir)?;
    fs::write(hung_dir.join("f"), b"x")?;
    fs::write(dir.join("ok"), b"x")?;
    let hung = hung_dir.as_os_str().as_bytes().to_vec();
    let hung_s = String::from_utf8_lossy(&hung).into_owned();

    let ctl = Arc::new(Ctl::default());
    ctl.set(&hung_s, Mode::Block);
    let mut table = fsid::parse_mountinfo(&fs::read("/proc/self/mountinfo")?);
    let mut fake = ent(u64::MAX - 1, &hung_s, "nfs4");
    fake.parent_id = 0;
    table.push(fake);
    let m = Monitor::start(
        HealthConfig {
            deadline: Duration::from_millis(150),
            ..cfg()
        },
        Arc::new(TestProber(Arc::clone(&ctl))),
        Source::Fixed(table),
        Vec::new(),
    )?;
    let resolver = Arc::new(Resolver::new(
        Gated::new(SysBackend::with_cache(MountCache::open()?), Arc::clone(&m)),
        ResolverConfig::default(),
    )?);
    let sink: Arc<dyn SuspectSink> = resolver.clone();
    m.set_sink(Arc::downgrade(&sink));
    let db = store::spawn(
        Store::open(&dir.join("db/metadata.db"), StoreConfig::default())?,
        DbConfig::default(),
    )?;
    let mdh: Arc<dyn Handler> = Arc::new(mdsvc::Service::new(Arc::clone(&resolver), db));
    let handler: Arc<dyn Handler> = Arc::new(HealthHandler::new(mdh, Arc::clone(&m)));
    let sock = dir.join("s.sock");
    let listener = ipc::bind(&sock)?;
    thread::spawn(move || {
        let _ = ipc::serve(&listener.socket, ipc::Config::default(), &handler);
    });

    let mut c = md::Client::connect(&sock, Duration::from_secs(2))?;
    // Subscribe: OK with the epoch, then the snapshot follows (healthy so far, or hung).
    let body = c.raw_call(MSG_HEALTH_SUBSCRIBE, &[]).expect("subscribe");
    assert_eq!(body.len(), 8);
    let mut ev = next_event(&mut c, Duration::from_secs(2));
    assert!(ev.1 & EV_FIRST != 0 && ev.1 & EV_LAST != 0);
    while ev.2.is_empty() {
        ev = next_event(&mut c, Duration::from_secs(3)); // the change to hung is pushed
    }
    assert_eq!(ev.2, [(u64::MAX - 1, Health::Hung, hung.clone())]);

    // Metadata requests for the hung mount fail fast; others work.
    let f = hung_dir.join("f");
    let t0 = Instant::now();
    match c.identify(&f) {
        Err(md::ClientError::Status(md::MdError::SuspectMount)) => {}
        other => panic!("expected SuspectMount, got {other:?}"),
    }
    assert!(t0.elapsed() < 100 * MS, "{:?}", t0.elapsed());
    assert!(c.identify(&dir.join("ok")).is_ok());
    // Queries by path and by id; errors.
    let (id, st, mp) = health_query(&mut c, QUERY_BY_PATH, f.as_os_str().as_bytes()).expect("q");
    assert_eq!((id, st, mp), (u64::MAX - 1, Health::Hung, hung.clone()));
    let (_, st, _) = health_query(&mut c, QUERY_BY_ID, &(u64::MAX - 1).to_le_bytes()).expect("q");
    assert_eq!(st, Health::Hung);
    let (_, st, _) = health_query(&mut c, QUERY_BY_PATH, b"/").expect("q");
    assert_eq!(st, Health::Healthy);
    for (by, arg, want) in [
        (
            QUERY_BY_ID,
            &7_777_777u64.to_le_bytes()[..],
            md::MdError::NotFound,
        ),
        (QUERY_BY_ID, &[1u8, 2][..], md::MdError::BadRequest),
        (QUERY_BY_PATH, &b"relative"[..], md::MdError::BadRequest),
        (9, &[][..], md::MdError::BadRequest),
    ] {
        match health_query(&mut c, by, arg) {
            Err(md::ClientError::Status(e)) => assert_eq!(e, want),
            other => panic!("expected {want:?}, got {other:?}"),
        }
    }
    match c.raw_call(MSG_HEALTH_SUBSCRIBE, &[1]) {
        Err(md::ClientError::Status(md::MdError::BadRequest)) => {}
        other => panic!("expected BadRequest, got {other:?}"),
    }

    // Recovery: an empty snapshot is pushed, and the path works again.
    ctl.set(&hung_s, Mode::Answer(MS));
    let mut ev = next_event(&mut c, Duration::from_secs(3));
    while !ev.2.is_empty() {
        ev = next_event(&mut c, Duration::from_secs(3));
    }
    assert!(c.identify(&f).is_ok());
    m.stop();
    Ok(())
}

#[test]
fn an_idle_subscriber_never_loses_its_connection_to_events() -> crate::Result<()> {
    let dir = TestDir::new("health-idle")?;
    let ctl = Arc::new(Ctl::default());
    ctl.set("/d", Mode::Dead);
    let m = Monitor::start(
        cfg(),
        Arc::new(TestProber(Arc::clone(&ctl))),
        Source::Fixed(vec![ent(1, "/", "ext4")]),
        Vec::new(),
    )?;
    let handler: Arc<dyn Handler> =
        Arc::new(HealthHandler::new(Arc::new(ipc::NoService), Arc::clone(&m)));
    let sock = dir.join("s.sock");
    let listener = ipc::bind(&sock)?;
    thread::spawn(move || {
        let _ = ipc::serve(&listener.socket, ipc::Config::default(), &handler);
    });
    let mut c = md::Client::connect(&sock, Duration::from_secs(2))?;
    c.raw_call(MSG_HEALTH_SUBSCRIBE, &[]).expect("subscribe");
    // 40 snapshots (a dead mount appears and goes away 20 times) while the client reads
    // nothing: events fill the ring up to the reserve, then wait; the connection lives.
    let (e0, _) = m.snapshot();
    for _ in 0..20 {
        m.set_table(vec![ent(1, "/", "ext4"), ent(2, "/d", "nfs")]);
        wait_for("gone", Duration::from_secs(2), || {
            state(&m, "/d") == Some(Health::Gone)
        });
        m.set_table(vec![ent(1, "/", "ext4")]);
    }
    let (e1, last) = m.snapshot();
    assert!(e1 >= e0 + 40 && last.is_empty());
    // Requests still get their replies; other kinds reach the inner handler.
    match c.raw_call(md::MSG_MD_IDENTIFY, b"/x") {
        Err(md::ClientError::Status(md::MdError::Unsupported)) => {}
        other => panic!("expected Unsupported, got {other:?}"),
    }
    // That call read (and, being a plain client, dropped) whatever events were queued.
    // Two more snapshots: both reach the client in order, nothing stale is replayed, and
    // the last one arrives even if the first left no room for it at once.
    m.set_table(vec![ent(1, "/", "ext4"), ent(2, "/d", "nfs")]);
    wait_for("gone", Duration::from_secs(2), || {
        state(&m, "/d") == Some(Health::Gone)
    });
    m.set_table(vec![ent(1, "/", "ext4")]);
    let (e2, _) = m.snapshot();
    assert!(e2 >= e1 + 2);
    let t0 = Instant::now();
    // e1 itself may still be on its way (if it had no room before that call).
    let mut prev = e1 - 1;
    loop {
        let (e, f, v) = next_event(&mut c, Duration::from_secs(2));
        assert!(e > prev, "stale or repeated snapshot {e} after {prev}");
        prev = e;
        if e == e2 {
            assert!(f & EV_LAST != 0 && v.is_empty());
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
    let (_, st, _) = health_query(&mut c, QUERY_BY_PATH, b"/x").expect("query");
    assert_eq!(st, Health::Healthy);
    m.stop();
    Ok(())
}

#[test]
fn fake_hung_mounts_need_the_feature() {
    let e = fake_entries(&[b"/x/y".to_vec()]);
    assert_eq!(e[0].mnt_id, u64::MAX - 1);
    assert!(is_probed(&e[0].fstype));
    // Not set in the test environment: nothing.
    if std::env::var_os(FAKE_HUNG_ENV).is_none() {
        assert!(fake_hung_from_env().is_empty());
    }
}
