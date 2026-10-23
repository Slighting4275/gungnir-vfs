//! Mount health monitor (milestone 7): finds hung or dead mounts before a request does.
//!
//! - One "gungnir-health" thread watches `/proc/self/mountinfo` (`POLLPRI`, procfs only,
//!   never a syscall on another filesystem) and schedules probes of network and FUSE
//!   mounts ([`is_probed`]); local filesystems are never probed and count as healthy.
//! - A probe is one `statfs` of the mount point ([`StatfsProber`]): a server round trip
//!   on NFS, CIFS and FUSE, which a cached `statx` (`AT_STATX_DONT_SYNC`) would skip and
//!   so never notice a dead server. It runs on a sacrificial "gungnir-probe" thread
//!   ([`PROBE_STACK`] stack): at most one probe in flight per mount, at most
//!   [`HealthConfig::max_threads`] probes within their deadline, plus at most
//!   [`HealthConfig::max_stuck`] stuck past it (a thread in `statfs` on a hung mount
//!   cannot be reclaimed; counting those against the same cap would let a few hung
//!   mounts stop the probing of every other mount for good), and nobody ever waits
//!   for one.
//! - States ([`Health`]): healthy; slow (answered, but in `slow_after` or more); hung
//!   (no answer within `deadline`, or `ETIMEDOUT`); gone (answered with a dead-mount
//!   errno: `ENOTCONN` from a FUSE server that died, `ESTALE`, `EIO`, `ENODEV`, ...).
//!   A mount that leaves the mount table is dropped (queries by its id say gone).
//!   Healthy and slow mounts are re-probed every `interval`; after a failure the next
//!   probe waits `backoff_base`, doubling per consecutive failure up to `backoff_max`; a
//!   stuck probe is never duplicated, its thread reports back whenever it returns.
//! - Hung and gone mounts are marked suspect in the M4 [`Resolver`] (and cleared again
//!   on recovery or unmount), and [`Gated`] refuses paths on them before a worker is
//!   used, so metadata requests for them fail fast with `SuspectMount`.
//!
//! Protocol (protocol v2 stays: new message kinds only, an M6 daemon answers them with
//! `ST_UNSUPPORTED`; mirrored in `src/client-zig/src/health.zig`). Every request gets one
//! `MSG_MD_REPLY` (`status u32 | body`):
//! - [`MSG_HEALTH_QUERY`] `by u8` then `0: path bytes` (absolute; longest mount-point
//!   prefix, lexical, the path is never touched) or `1: mnt_id u64`. Body:
//!   `mnt_id u64 | state u8 | probed u8 | latency_us u32 (u32::MAX: none yet) | path16`.
//!   An unknown mount id is `ST_NOT_FOUND`.
//! - [`MSG_HEALTH_SUBSCRIBE`], empty. Body `epoch u64`. Right after the reply, and after
//!   every change, the daemon pushes a snapshot as [`MSG_HEALTH_EVENT`] slots (`seq` 0):
//!   `epoch u64 | flags u8 | count u16 | count x (mnt_id u64 | state u8 | path16)`, flags
//!   [`EV_FIRST`], [`EV_LAST`], [`EV_INCOMPLETE`]; at most [`MAX_EVENT_SLOTS`] slots,
//!   pushed all or none and only with [`EVENT_RESERVE`] slots left for replies (else
//!   retried every 100 ms). A snapshot lists every mount that is not healthy plus every
//!   mount at or below one of those, in mount-table order, so a client's longest-prefix
//!   lookup on it gives the same answer as on the whole table. Each snapshot replaces
//!   the previous one; a lost or partial one is simply superseded by the next.

use std::{
    collections::{HashMap, VecDeque},
    ffi::CString,
    fs,
    io::{self, Read, Seek},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    fsid::{self, Backend, FileIdentity, FsidError, MountEntry, MountHint, Resolver, Target},
    ipc::{Handler, MAX_INFLIGHT, Msg, PAYLOAD_MAX, Port, Session},
    md::{MSG_MD_REPLY, ST_BAD_REQUEST, ST_IO_ERROR, ST_NOT_FOUND, ST_OK, reply_payload},
};

pub const MSG_HEALTH_QUERY: u32 = 23;
pub const MSG_HEALTH_SUBSCRIBE: u32 = 24;
/// Daemon -> client, unsolicited, `seq` 0.
pub const MSG_HEALTH_EVENT: u32 = 33;
pub const QUERY_BY_PATH: u8 = 0;
pub const QUERY_BY_ID: u8 = 1;
pub const EV_FIRST: u8 = 1;
pub const EV_LAST: u8 = 2;
/// Some entries did not fit: the client must not trust lookups on this snapshot.
pub const EV_INCOMPLETE: u8 = 4;
pub const MAX_EVENT_SLOTS: usize = 4;
/// Slots an event push leaves free for replies (every in-flight request, plus one).
pub const EVENT_RESERVE: usize = MAX_INFLIGHT + 1;
const EVENT_HEADER: usize = 8 + 1 + 2;
const ENTRY_FIXED: usize = 8 + 1 + 2;
/// How long the resolver keeps a mount suspect per mark; cleared earlier on recovery.
const MARK_SPAN: Duration = Duration::from_secs(3600);
/// Subscribers whose snapshot did not fit are retried this often.
const RETRY: Duration = Duration::from_millis(100);
/// Longest sleep of the monitor thread with nothing scheduled.
const IDLE_MAX: Duration = Duration::from_secs(30);
/// Removed mounts remembered for queries by id.
const GONE_MEMORY: usize = 64;
/// Configured spans are capped here, so `Instant` arithmetic cannot overflow.
const SPAN_CAP: Duration = Duration::from_secs(86_400);
/// Stack of a probe thread: it only calls `statfs`, and stuck ones live forever.
pub const PROBE_STACK: usize = 256 * 1024;

/// Test-only fake hung mount (`test-hooks` builds; ignored with a warning otherwise).
pub const FAKE_HUNG_ENV: &str = "GUNGNIR_TEST_FAKE_HUNG_MOUNT";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Slow,
    Hung,
    Gone,
}

impl Health {
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Health::Healthy => 0,
            Health::Slow => 1,
            Health::Hung => 2,
            Health::Gone => 3,
        }
    }

    #[must_use]
    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Health::Healthy,
            1 => Health::Slow,
            2 => Health::Hung,
            3 => Health::Gone,
            _ => return None,
        })
    }

    /// Requests for paths on this mount must fail fast.
    #[must_use]
    pub fn blocks(self) -> bool {
        matches!(self, Health::Hung | Health::Gone)
    }
}

/// Filesystems whose answers depend on a server or a userspace process: the only ones
/// probed. FUSE covers sshfs (`fuse.sshfs`), gvfsd-fuse, rclone, virtiofs-over-FUSE, ...
#[must_use]
pub fn is_probed(fstype: &[u8]) -> bool {
    fstype == b"fuse"
        || fstype == b"fuseblk"
        || fstype.starts_with(b"fuse.")
        || matches!(
            fstype,
            b"nfs"
                | b"nfs4"
                | b"cifs"
                | b"smb3"
                | b"smbfs"
                | b"9p"
                | b"ceph"
                | b"afs"
                | b"ncpfs"
                | b"lustre"
                | b"glusterfs"
                | b"davfs"
                | b"coda"
                | b"virtiofs"
        )
}

/// How one probe ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The filesystem answered (success, or an error that proves it is alive: EACCES...).
    Answered,
    /// An errno that means the mount is dead.
    Dead(i32),
    /// The filesystem itself gave up waiting for its server (`ETIMEDOUT`, soft mounts).
    TimedOut,
}

/// Map a probe's errno to an [`Outcome`].
#[must_use]
pub fn classify_error(e: &io::Error) -> Outcome {
    match e.raw_os_error() {
        Some(libc::ETIMEDOUT) => Outcome::TimedOut,
        Some(
            n @ (libc::ENOTCONN
            | libc::ESTALE
            | libc::EIO
            | libc::ENODEV
            | libc::ESHUTDOWN
            | libc::ECONNABORTED
            | libc::ECONNRESET
            | libc::ECONNREFUSED
            | libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::ENETUNREACH
            | libc::ENETDOWN),
        ) => Outcome::Dead(n),
        _ => Outcome::Answered,
    }
}

/// The blocking side of the monitor: one round trip to the mount's filesystem.
pub trait Prober: Send + Sync + 'static {
    /// May block for as long as the filesystem does; only ever called on a probe thread.
    fn probe(&self, mount: &MountEntry) -> Outcome;
}

/// `statfs(2)` on the mount point.
pub struct StatfsProber;

impl Prober for StatfsProber {
    fn probe(&self, mount: &MountEntry) -> Outcome {
        let Ok(p) = CString::new(mount.mount_point.clone()) else {
            return Outcome::Answered; // mountinfo never yields a NUL; nothing to probe
        };
        // SAFETY: statfs is plain old data; all-zero is a valid value.
        let mut st: libc::statfs = unsafe { mem::zeroed() };
        // SAFETY: NUL-terminated path, writable `st`.
        if unsafe { libc::statfs(p.as_ptr(), &raw mut st) } == 0 {
            Outcome::Answered
        } else {
            classify_error(&io::Error::last_os_error())
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HealthConfig {
    /// A probe without an answer by then makes the mount hung.
    pub deadline: Duration,
    /// Re-probe period of healthy and slow mounts.
    pub interval: Duration,
    /// An answer this slow (or slower, but within `deadline`) makes the mount slow.
    pub slow_after: Duration,
    /// Wait after the first failure; doubles per consecutive failure.
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    /// Probes within their deadline at once.
    pub max_threads: usize,
    /// Probe threads stuck past their deadline that may stay alive on top of
    /// `max_threads` (each hung mount holds at most one); when they are all used up,
    /// nothing new is probed until one returns.
    pub max_stuck: usize,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(1),
            interval: Duration::from_secs(5),
            slow_after: Duration::from_millis(250),
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            max_threads: 8,
            max_stuck: 56,
        }
    }
}

impl HealthConfig {
    fn capped(mut self) -> Self {
        for d in [
            &mut self.deadline,
            &mut self.interval,
            &mut self.slow_after,
            &mut self.backoff_base,
            &mut self.backoff_max,
        ] {
            *d = (*d).min(SPAN_CAP);
        }
        self.max_threads = self.max_threads.max(1);
        self
    }

    /// Wait before the next probe after `failures` consecutive failures (>= 1).
    #[must_use]
    pub fn backoff(&self, failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(30);
        self.backoff_base
            .saturating_mul(1u32 << shift)
            .min(self.backoff_max)
            .min(SPAN_CAP)
    }
}

// ---------------------------------------------------------------------------------------
// Paths (lexical only: the target is never touched)

fn lexical(path: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let mut out = Vec::with_capacity(path.len() + 1);
    for p in parts {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

fn under(path: &[u8], mount_point: &[u8]) -> bool {
    mount_point == b"/"
        || path == mount_point
        || (path.starts_with(mount_point) && path.get(mount_point.len()) == Some(&b'/'))
}

fn hint_of(e: &MountEntry) -> MountHint {
    MountHint {
        mnt_id: e.mnt_id,
        mount_point: e.mount_point_path(),
    }
}

// ---------------------------------------------------------------------------------------
// The state machine (no threads, no syscalls: driven with explicit instants)

#[derive(Debug, Clone)]
struct Mount {
    entry: MountEntry,
    probed: bool,
    state: Health,
    /// Token and start of the probe in flight.
    inflight: Option<(u64, Instant)>,
    failures: u32,
    next_probe: Instant,
    latency: Option<Duration>,
}

/// A probe to run on a probe thread; hand its result to [`Core::complete`].
#[derive(Debug, Clone)]
pub struct Job {
    pub token: u64,
    pub entry: MountEntry,
}

/// One mount's state change; `removed`: it left the mount table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub hint: MountHint,
    pub fstype: Vec<u8>,
    pub from: Health,
    pub to: Health,
    pub removed: bool,
}

/// What a query reports about one mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub hint: MountHint,
    pub state: Health,
    pub probed: bool,
    pub latency: Option<Duration>,
}

/// One snapshot entry: mount id, state, mount point.
pub type Listed = (u64, Health, Vec<u8>);

pub struct Core {
    cfg: HealthConfig,
    mounts: Vec<Mount>,
    /// Appended to every table (test-hook fake mounts).
    extra: Vec<MountEntry>,
    gone: VecDeque<MountHint>,
    /// Every probe thread alive, by token: its start and whether it is past its deadline
    /// (also those of mounts that left the table meanwhile).
    probes: HashMap<u64, (Instant, bool)>,
    next_token: u64,
}

impl Core {
    #[must_use]
    pub fn new(cfg: HealthConfig, extra: Vec<MountEntry>) -> Self {
        Self {
            cfg: cfg.capped(),
            mounts: Vec::new(),
            extra,
            gone: VecDeque::new(),
            probes: HashMap::new(),
            next_token: 1,
        }
    }

    /// Probe threads alive (in flight, stuck ones included).
    #[must_use]
    pub fn running(&self) -> usize {
        self.probes.len()
    }

    /// Probe threads alive past their deadline.
    #[must_use]
    pub fn stuck(&self) -> usize {
        self.probes.values().filter(|(_, stuck)| *stuck).count()
    }

    /// Room for another probe: fewer than `max_threads` within their deadline, and
    /// fewer than `max_threads + max_stuck` threads alive in all.
    fn room(&self) -> bool {
        let stuck = self.stuck();
        self.probes.len() - stuck < self.cfg.max_threads
            && self.probes.len() < self.cfg.max_threads.saturating_add(self.cfg.max_stuck)
    }

    /// Install a new mount table. Unchanged mounts keep their state; new ones that are
    /// probed get a probe at once; removed ones are reported.
    pub fn set_table(&mut self, table: Vec<MountEntry>, now: Instant) -> Vec<Change> {
        let mut old: HashMap<u64, Mount> = mem::take(&mut self.mounts)
            .into_iter()
            .map(|m| (m.entry.mnt_id, m))
            .collect();
        let mut replaced = Vec::new();
        for e in table.into_iter().chain(self.extra.iter().cloned()) {
            let m = match old.remove(&e.mnt_id) {
                Some(m) if m.entry == e => m,
                // A different mount reusing the id: the old one is reported removed.
                Some(m) => {
                    replaced.push(m);
                    Mount::new(e, now)
                }
                None => Mount::new(e, now),
            };
            self.mounts.push(m);
        }
        let mut changes = Vec::new();
        for m in replaced.into_iter().chain(old.into_values()) {
            let hint = hint_of(&m.entry);
            if self.gone.len() == GONE_MEMORY {
                self.gone.pop_front();
            }
            self.gone.push_back(hint.clone());
            changes.push(Change {
                hint,
                fstype: m.entry.fstype,
                from: m.state,
                to: Health::Gone,
                removed: true,
            });
        }
        changes
    }

    /// Probes to start now: due, none in flight for that mount, within the thread cap.
    pub fn due(&mut self, now: Instant) -> Vec<Job> {
        let mut jobs = Vec::new();
        for i in 0..self.mounts.len() {
            if !self.room() {
                break;
            }
            let m = &mut self.mounts[i];
            if m.probed && m.inflight.is_none() && m.next_probe <= now {
                let token = self.next_token;
                self.next_token += 1;
                m.inflight = Some((token, now));
                self.probes.insert(token, (now, false));
                jobs.push(Job {
                    token,
                    entry: m.entry.clone(),
                });
            }
        }
        jobs
    }

    /// Probes past their deadline make their mounts hung.
    pub fn expire(&mut self, now: Instant) -> Vec<Change> {
        let deadline = self.cfg.deadline;
        for (started, stuck) in self.probes.values_mut() {
            if now.saturating_duration_since(*started) >= deadline {
                *stuck = true;
            }
        }
        let mut changes = Vec::new();
        for m in &mut self.mounts {
            if let Some((_, started)) = m.inflight
                && now.saturating_duration_since(started) >= deadline
                && m.state != Health::Hung
            {
                changes.push(m.set(Health::Hung));
            }
        }
        changes
    }

    /// A probe returned (possibly long after its deadline).
    pub fn complete(
        &mut self,
        token: u64,
        outcome: Outcome,
        latency: Duration,
        now: Instant,
    ) -> Vec<Change> {
        self.probes.remove(&token);
        let cfg = self.cfg;
        let Some(m) = self
            .mounts
            .iter_mut()
            .find(|m| m.inflight.is_some_and(|(t, _)| t == token))
        else {
            return Vec::new(); // its mount was removed meanwhile
        };
        m.inflight = None;
        m.latency = Some(latency);
        let to = match outcome {
            Outcome::Answered if latency < cfg.deadline => {
                m.failures = 0;
                m.next_probe = now + cfg.interval;
                if latency >= cfg.slow_after {
                    Health::Slow
                } else {
                    Health::Healthy
                }
            }
            // Too late to count as an answer, or the filesystem's own timeout.
            Outcome::Answered | Outcome::TimedOut => {
                m.fail(&cfg, now);
                Health::Hung
            }
            Outcome::Dead(_) => {
                m.fail(&cfg, now);
                Health::Gone
            }
        };
        if m.state == to {
            Vec::new()
        } else {
            vec![m.set(to)]
        }
    }

    /// A probe thread could not be started: release its slot, retry after the base backoff.
    pub fn abort(&mut self, token: u64, now: Instant) {
        self.probes.remove(&token);
        if let Some(m) = self
            .mounts
            .iter_mut()
            .find(|m| m.inflight.is_some_and(|(t, _)| t == token))
        {
            m.inflight = None;
            m.next_probe = now + self.cfg.backoff_base;
        }
    }

    /// When the monitor must look again: the next probe deadline or due probe.
    #[must_use]
    pub fn next_wake(&self) -> Option<Instant> {
        let room = self.room();
        // A probe reaching its deadline frees a slot within the cap (and may make its
        // mount hung); stuck ones report when their thread returns.
        let deadlines = self
            .probes
            .values()
            .filter(|(_, stuck)| !stuck)
            .map(|(started, _)| *started + self.cfg.deadline);
        let due = self
            .mounts
            .iter()
            .filter(|m| room && m.probed && m.inflight.is_none())
            .map(|m| m.next_probe);
        deadlines.chain(due).min()
    }

    /// The mount a path is on (longest mount-point prefix, later entries win ties).
    #[must_use]
    pub fn lookup(&self, path: &[u8]) -> Option<Report> {
        let p = lexical(path);
        let mut best: Option<&Mount> = None;
        for m in self
            .mounts
            .iter()
            .filter(|m| under(&p, &m.entry.mount_point))
        {
            if best.is_none_or(|b| m.entry.mount_point.len() >= b.entry.mount_point.len()) {
                best = Some(m);
            }
        }
        best.map(Mount::report)
    }

    /// A mount by id; a recently removed one reports gone.
    #[must_use]
    pub fn by_id(&self, mnt_id: u64) -> Option<Report> {
        if let Some(m) = self.mounts.iter().rev().find(|m| m.entry.mnt_id == mnt_id) {
            return Some(m.report());
        }
        self.gone
            .iter()
            .rev()
            .find(|h| h.mnt_id == mnt_id)
            .map(|h| Report {
                hint: h.clone(),
                state: Health::Gone,
                probed: false,
                latency: None,
            })
    }

    /// Hung and gone mounts right now.
    #[must_use]
    pub fn blocked(&self) -> Vec<MountHint> {
        self.mounts
            .iter()
            .filter(|m| m.state.blocks())
            .map(|m| hint_of(&m.entry))
            .collect()
    }

    /// The snapshot clients get: every mount that is not healthy, plus every mount at
    /// or below one of them (so longest-prefix lookups on it match the whole table).
    #[must_use]
    pub fn listed(&self) -> Vec<Listed> {
        let unhealthy: Vec<(usize, &[u8])> = self
            .mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| m.state != Health::Healthy)
            .map(|(i, m)| (i, m.entry.mount_point.as_slice()))
            .collect();
        self.mounts
            .iter()
            .enumerate()
            .filter(|(i, m)| {
                m.state != Health::Healthy
                    || unhealthy
                        .iter()
                        .any(|(j, mp)| i != j && under(&m.entry.mount_point, mp))
            })
            .map(|(_, m)| (m.entry.mnt_id, m.state, m.entry.mount_point.clone()))
            .collect()
    }
}

impl Mount {
    fn new(entry: MountEntry, now: Instant) -> Self {
        Self {
            probed: is_probed(&entry.fstype),
            entry,
            state: Health::Healthy,
            inflight: None,
            failures: 0,
            next_probe: now,
            latency: None,
        }
    }

    fn fail(&mut self, cfg: &HealthConfig, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.next_probe = now + cfg.backoff(self.failures);
    }

    fn set(&mut self, to: Health) -> Change {
        let from = mem::replace(&mut self.state, to);
        Change {
            hint: hint_of(&self.entry),
            fstype: self.entry.fstype.clone(),
            from,
            to,
            removed: false,
        }
    }

    fn report(&self) -> Report {
        Report {
            hint: hint_of(&self.entry),
            state: self.state,
            probed: self.probed,
            latency: self.latency,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Snapshot encoding

/// Encode a snapshot into at most [`MAX_EVENT_SLOTS`] event payloads.
#[must_use]
pub fn encode_snapshot(epoch: u64, listed: &[Listed]) -> Vec<Vec<u8>> {
    fn start(epoch: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(PAYLOAD_MAX);
        v.extend_from_slice(&epoch.to_le_bytes());
        v.extend_from_slice(&[0, 0, 0]);
        v
    }
    fn finish(slot: &mut [u8], count: u16) {
        slot[9..11].copy_from_slice(&count.to_le_bytes());
    }
    let mut slots: Vec<Vec<u8>> = Vec::new();
    let mut cur = start(epoch);
    let mut count: u16 = 0;
    let mut incomplete = false;
    for (id, state, mp) in listed {
        let need = ENTRY_FIXED + mp.len();
        if EVENT_HEADER + need > PAYLOAD_MAX {
            incomplete = true; // a mount point this long cannot be sent: skip it
            continue;
        }
        if cur.len() + need > PAYLOAD_MAX {
            if slots.len() + 1 == MAX_EVENT_SLOTS {
                incomplete = true;
                break;
            }
            finish(&mut cur, count);
            slots.push(mem::replace(&mut cur, start(epoch)));
            count = 0;
        }
        cur.extend_from_slice(&id.to_le_bytes());
        cur.push(state.code());
        // Fits a slot, so it fits a u16.
        cur.extend_from_slice(&(mp.len() as u16).to_le_bytes());
        cur.extend_from_slice(mp);
        count += 1;
    }
    finish(&mut cur, count);
    slots.push(cur);
    let last = slots.len() - 1;
    slots[0][8] |= EV_FIRST;
    slots[last][8] |= EV_LAST;
    if incomplete {
        slots[last][8] |= EV_INCOMPLETE;
    }
    slots
}

/// Decode one event payload (tests and diagnostics): `(epoch, flags, entries)`.
///
/// # Errors
/// `Err(())` for a malformed payload.
#[allow(clippy::result_unit_err)]
pub fn decode_event(p: &[u8]) -> Result<(u64, u8, Vec<Listed>), ()> {
    fn take<'a>(p: &mut &'a [u8], n: usize) -> Result<&'a [u8], ()> {
        if p.len() < n {
            return Err(());
        }
        let (a, b) = p.split_at(n);
        *p = b;
        Ok(a)
    }
    let mut r = p;
    let epoch = u64::from_le_bytes(take(&mut r, 8)?.try_into().map_err(|_| ())?);
    let flags = take(&mut r, 1)?[0];
    let count = u16::from_le_bytes(take(&mut r, 2)?.try_into().map_err(|_| ())?);
    let mut out = Vec::new();
    for _ in 0..count {
        let id = u64::from_le_bytes(take(&mut r, 8)?.try_into().map_err(|_| ())?);
        let st = Health::from_code(take(&mut r, 1)?[0]).ok_or(())?;
        let len = u16::from_le_bytes(take(&mut r, 2)?.try_into().map_err(|_| ())?);
        out.push((id, st, take(&mut r, usize::from(len))?.to_vec()));
    }
    if !r.is_empty() {
        return Err(());
    }
    Ok((epoch, flags, out))
}

// ---------------------------------------------------------------------------------------
// The monitor (threads around the state machine)

/// Where hung mounts are reported: the M4 resolver.
pub trait SuspectSink: Send + Sync {
    fn mark(&self, hint: MountHint);
    fn clear(&self, hint: &MountHint);
}

impl<B: Backend> SuspectSink for Resolver<B> {
    fn mark(&self, hint: MountHint) {
        self.mark_suspect(hint, MARK_SPAN);
    }
    fn clear(&self, hint: &MountHint) {
        self.clear_suspect(hint);
    }
}

/// Where the mount table comes from.
pub enum Source {
    /// `/proc/self/mountinfo`, re-read on `POLLPRI`.
    Proc,
    /// A fixed table (tests); replace it with [`Monitor::set_table`].
    Fixed(Vec<MountEntry>),
}

struct Sub {
    port: Weak<Port>,
    sent: u64,
}

struct Subs {
    epoch: u64,
    listed: Vec<Listed>,
    snapshot: Vec<Vec<u8>>,
    subs: Vec<Sub>,
}

impl Subs {
    /// Push the current snapshot to everyone who lacks it; drop closed connections.
    /// Returns whether someone still lacks it (no room in their ring).
    fn deliver(&mut self) -> bool {
        let (epoch, snap) = (self.epoch, &self.snapshot);
        let mut pending = false;
        self.subs.retain_mut(|s| {
            let Some(port) = s.port.upgrade() else {
                return false;
            };
            if s.sent != epoch {
                if port.push_unsolicited(MSG_HEALTH_EVENT, snap, EVENT_RESERVE) {
                    s.sent = epoch;
                } else {
                    pending = true;
                }
            }
            true
        });
        pending
    }
}

/// The resolver and what it has been told: kept equal to the core's blocked mounts by
/// [`Monitor::commit`], which runs before the core lock is released, so whoever sees a
/// state through the core sees the resolver agree, and marks and clears from different
/// threads can never land out of order.
struct SinkState {
    sink: Option<Weak<dyn SuspectSink>>,
    marked: Vec<MountHint>,
}

pub struct Monitor {
    core: Mutex<Core>,
    prober: Arc<dyn Prober>,
    wake: OwnedFd,
    /// Lock order: `core`, then `sink`, then the sink's own (the resolver's suspects).
    sink: Mutex<SinkState>,
    subs: Mutex<Subs>,
    stop: AtomicBool,
}

fn read_mountinfo(f: &mut fs::File) -> io::Result<Vec<MountEntry>> {
    f.rewind()?;
    let mut text = Vec::new();
    f.read_to_end(&mut text)?;
    Ok(fsid::parse_mountinfo(&text))
}

impl Monitor {
    /// Read the mount table and start the monitor thread.
    ///
    /// # Errors
    /// I/O errors opening or reading `/proc/self/mountinfo`, creating the eventfd or
    /// starting the thread.
    pub fn start(
        cfg: HealthConfig,
        prober: Arc<dyn Prober>,
        source: Source,
        extra: Vec<MountEntry>,
    ) -> io::Result<Arc<Self>> {
        let (file, table) = match source {
            Source::Proc => {
                let mut f = fs::File::open("/proc/self/mountinfo")?;
                let t = read_mountinfo(&mut f)?;
                (Some(f), t)
            }
            Source::Fixed(t) => (None, t),
        };
        let mut core = Core::new(cfg, extra);
        core.set_table(table, Instant::now());
        // SAFETY: plain syscall, no pointers.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let listed = core.listed();
        let me = Arc::new(Self {
            core: Mutex::new(core),
            prober,
            // SAFETY: a fresh fd owned by nobody else.
            wake: unsafe { OwnedFd::from_raw_fd(fd) },
            sink: Mutex::new(SinkState {
                sink: None,
                marked: Vec::new(),
            }),
            subs: Mutex::new(Subs {
                epoch: 1,
                snapshot: encode_snapshot(1, &listed),
                listed,
                subs: Vec::new(),
            }),
            stop: AtomicBool::new(false),
        });
        let m = Arc::clone(&me);
        thread::Builder::new()
            .name("gungnir-health".into())
            .spawn(move || m.run(file))?;
        Ok(me)
    }

    /// Report hung mounts to `sink` (held weakly: the resolver owns the monitor's gate).
    pub fn set_sink(&self, sink: Weak<dyn SuspectSink>) {
        let core = lock(&self.core);
        *lock(&self.sink) = SinkState {
            sink: Some(sink),
            marked: Vec::new(),
        };
        self.commit(core);
    }

    /// Bring the sink in line with `core` (still locked), then unlock. The sink's `Arc`
    /// is dropped only after the core lock is released.
    fn commit(&self, core: MutexGuard<'_, Core>) {
        let held = {
            let mut st = lock(&self.sink);
            let sink = st.sink.as_ref().and_then(Weak::upgrade);
            if let Some(s) = &sink {
                let want = core.blocked();
                for h in st.marked.iter().filter(|h| !want.contains(h)) {
                    s.clear(h);
                }
                for h in want.iter().filter(|h| !st.marked.contains(h)) {
                    s.mark(h.clone());
                }
                st.marked = want;
            }
            sink
        };
        drop(core);
        drop(held);
    }

    /// Stop the monitor thread (tests). Stuck probe threads stay stuck.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.kick();
    }

    fn kick(&self) {
        let one = 1u64.to_ne_bytes();
        // SAFETY: writes 8 bytes from a live buffer to our eventfd.
        let _ = unsafe { libc::write(self.wake.as_raw_fd(), one.as_ptr().cast(), 8) };
    }

    /// Replace the mount table (a [`Source::Fixed`] monitor; tests).
    pub fn set_table(&self, table: Vec<MountEntry>) {
        let mut core = lock(&self.core);
        let ch = core.set_table(table, Instant::now());
        self.commit(core);
        self.apply(&ch);
        self.kick();
    }

    #[must_use]
    pub fn lookup(&self, path: &[u8]) -> Option<Report> {
        lock(&self.core).lookup(path)
    }

    #[must_use]
    pub fn by_id(&self, mnt_id: u64) -> Option<Report> {
        lock(&self.core).by_id(mnt_id)
    }

    /// Probe threads alive.
    #[must_use]
    pub fn probe_threads(&self) -> usize {
        lock(&self.core).running()
    }

    /// The mount `path` is on, if it is hung or gone.
    #[must_use]
    pub fn blocking_mount(&self, path: &Path) -> Option<MountHint> {
        self.lookup(path.as_os_str().as_bytes())
            .filter(|r| r.state.blocks())
            .map(|r| r.hint)
    }

    /// The current snapshot epoch and entries.
    #[must_use]
    pub fn snapshot(&self) -> (u64, Vec<Listed>) {
        let s = lock(&self.subs);
        (s.epoch, s.listed.clone())
    }

    /// Register a connection for events; it gets the current snapshot at once (or as
    /// soon as its ring has room). Returns the current epoch.
    pub fn subscribe(&self, port: &Arc<Port>) -> u64 {
        let (epoch, pending) = {
            let mut s = lock(&self.subs);
            let w = Arc::downgrade(port);
            s.subs.retain(|x| !x.port.ptr_eq(&w));
            s.subs.push(Sub { port: w, sent: 0 });
            (s.epoch, s.deliver())
        };
        if pending {
            self.kick(); // the monitor thread retries every RETRY while one is pending
        }
        epoch
    }

    /// Log `changes` and publish the new snapshot (the resolver was already told, in
    /// [`Monitor::commit`]).
    fn apply(&self, changes: &[Change]) {
        if changes.is_empty() {
            return;
        }
        for c in changes {
            eprintln!(
                "gungnird: mount {} ({}) {:?} -> {}",
                c.hint.mount_point.display(),
                String::from_utf8_lossy(&c.fstype),
                c.from,
                if c.removed {
                    "removed".to_owned()
                } else {
                    format!("{:?}", c.to)
                }
            );
        }
        self.publish();
    }

    /// Recompute the snapshot; a different one gets a new epoch and goes to everyone.
    fn publish(&self) -> bool {
        let listed = lock(&self.core).listed();
        let mut s = lock(&self.subs);
        if listed != s.listed {
            s.epoch += 1;
            s.snapshot = encode_snapshot(s.epoch, &listed);
            s.listed = listed;
        }
        s.deliver()
    }

    fn spawn_probe(self: &Arc<Self>, job: Job) {
        let me = Arc::clone(self);
        let token = job.token;
        let spawned = thread::Builder::new()
            .name("gungnir-probe".into())
            .stack_size(PROBE_STACK)
            .spawn(move || {
                let t0 = Instant::now();
                let out = me.prober.probe(&job.entry);
                let took = t0.elapsed();
                let mut core = lock(&me.core);
                let ch = core.complete(job.token, out, took, Instant::now());
                me.commit(core);
                me.apply(&ch);
                me.kick(); // schedule its next probe
            });
        if spawned.is_err() {
            lock(&self.core).abort(token, Instant::now());
        }
    }

    fn run(self: Arc<Self>, mut file: Option<fs::File>) {
        let mut reread = false;
        loop {
            if self.stop.load(Ordering::Acquire) {
                return;
            }
            let now = Instant::now();
            let (changes, jobs) = {
                let mut c = lock(&self.core);
                let r = (c.expire(now), c.due(now));
                self.commit(c);
                r
            };
            self.apply(&changes);
            for j in jobs {
                self.spawn_probe(j);
            }
            let pending = self.publish();
            let wake_at = lock(&self.core).next_wake();
            let mut timeout =
                wake_at.map_or(IDLE_MAX, |t| t.saturating_duration_since(Instant::now()));
            if pending || reread {
                timeout = timeout.min(RETRY);
            }
            let timeout = timeout.min(IDLE_MAX);
            let mut fds = [
                libc::pollfd {
                    fd: self.wake.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: file.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    events: libc::POLLPRI,
                    revents: 0,
                },
            ];
            // Round up, so a deadline is never polled for 0 ms in a loop.
            let ms = i32::try_from(timeout.as_micros().div_ceil(1000)).unwrap_or(i32::MAX);
            // SAFETY: two valid pollfds (a negative fd is ignored by poll).
            let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
            if r < 0 {
                continue; // EINTR
            }
            if fds[0].revents != 0 {
                let mut b = [0u8; 8];
                // SAFETY: reads at most 8 bytes into `b` (non-blocking eventfd).
                let _ = unsafe { libc::read(self.wake.as_raw_fd(), b.as_mut_ptr().cast(), 8) };
            }
            // poll itself consumes the change flag: remember it until a re-read works.
            if fds[1].revents & (libc::POLLPRI | libc::POLLERR) != 0 {
                reread = true;
            }
            if reread
                && let Some(f) = &mut file
                && let Ok(t) = read_mountinfo(f)
            {
                reread = false;
                let mut core = lock(&self.core);
                let ch = core.set_table(t, Instant::now());
                self.commit(core);
                self.apply(&ch);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// The resolver gate and the IPC requests

/// A [`Backend`] that refuses paths on hung or gone mounts without touching them, and
/// tells the resolver which mount they are on (so its suspect check fails them fast).
pub struct Gated<B> {
    inner: B,
    monitor: Arc<Monitor>,
}

impl<B> Gated<B> {
    pub fn new(inner: B, monitor: Arc<Monitor>) -> Self {
        Self { inner, monitor }
    }
}

impl<B: Backend> Backend for Gated<B> {
    fn identify(&self, target: &Target) -> fsid::Result<FileIdentity> {
        // Re-checked on the worker: covers a mount that turned hung after dispatch.
        if let Target::Path(p) = target
            && let Some(h) = self.monitor.blocking_mount(p)
        {
            return Err(FsidError::SuspectMount(h.mount_point));
        }
        self.inner.identify(target)
    }

    fn mount_hint(&self, target: &Target) -> Option<MountHint> {
        if let Target::Path(p) = target
            && let Some(h) = self.monitor.blocking_mount(p)
        {
            return Some(h);
        }
        self.inner.mount_hint(target)
    }
}

/// Serves the health requests and hands everything else to `inner`.
pub struct HealthHandler {
    inner: Arc<dyn Handler>,
    monitor: Arc<Monitor>,
}

impl HealthHandler {
    pub fn new(inner: Arc<dyn Handler>, monitor: Arc<Monitor>) -> Self {
        Self { inner, monitor }
    }
}

impl Handler for HealthHandler {
    fn session(&self) -> Box<dyn Session> {
        Box::new(HealthSession {
            inner: self.inner.session(),
            monitor: Arc::clone(&self.monitor),
        })
    }
}

struct HealthSession {
    inner: Box<dyn Session>,
    monitor: Arc<Monitor>,
}

/// Reply body of a query.
#[must_use]
pub fn report_body(r: &Report) -> Option<Vec<u8>> {
    let mp = r.hint.mount_point.as_os_str().as_bytes();
    if 4 + 8 + 1 + 1 + 4 + 2 + mp.len() > PAYLOAD_MAX {
        return None;
    }
    let mut b = Vec::with_capacity(16 + mp.len());
    b.extend_from_slice(&r.hint.mnt_id.to_le_bytes());
    b.push(r.state.code());
    b.push(u8::from(r.probed));
    let us = r.latency.map_or(u32::MAX, |d| {
        u32::try_from(d.as_micros()).unwrap_or(u32::MAX - 1)
    });
    b.extend_from_slice(&us.to_le_bytes());
    b.extend_from_slice(&(mp.len() as u16).to_le_bytes());
    b.extend_from_slice(mp);
    Some(b)
}

/// A query payload: `(by path, path)` or `(by id, id)`.
fn query(monitor: &Monitor, p: &[u8]) -> Result<Report, u32> {
    match p.split_first() {
        Some((&QUERY_BY_PATH, path)) => {
            if path.first() != Some(&b'/') || path.contains(&0) {
                return Err(ST_BAD_REQUEST);
            }
            monitor.lookup(path).ok_or(ST_NOT_FOUND)
        }
        Some((&QUERY_BY_ID, id)) => {
            let id: [u8; 8] = id.try_into().map_err(|_| ST_BAD_REQUEST)?;
            monitor.by_id(u64::from_le_bytes(id)).ok_or(ST_NOT_FOUND)
        }
        _ => Err(ST_BAD_REQUEST),
    }
}

impl Session for HealthSession {
    fn request(&mut self, port: &Arc<Port>, msg: &Msg) {
        match msg.kind {
            MSG_HEALTH_QUERY => {
                let p = match query(&self.monitor, msg.payload()) {
                    Ok(r) => match report_body(&r) {
                        Some(b) => reply_payload(ST_OK, &b),
                        None => reply_payload(ST_IO_ERROR, &[]),
                    },
                    Err(st) => reply_payload(st, &[]),
                };
                port.reply(MSG_MD_REPLY, msg.seq, &p);
            }
            MSG_HEALTH_SUBSCRIBE if msg.payload().is_empty() => {
                // The reply first: the snapshot follows it on the ring.
                let (epoch, _) = self.monitor.snapshot();
                port.reply(
                    MSG_MD_REPLY,
                    msg.seq,
                    &reply_payload(ST_OK, &epoch.to_le_bytes()),
                );
                self.monitor.subscribe(port);
            }
            MSG_HEALTH_SUBSCRIBE => {
                port.reply(MSG_MD_REPLY, msg.seq, &reply_payload(ST_BAD_REQUEST, &[]));
            }
            _ => self.inner.request(port, msg),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Test hook: a fake hung mount, for the integration tests of the GIO module

/// Mount points from [`FAKE_HUNG_ENV`] (one absolute path) in `test-hooks` builds;
/// otherwise empty, with a warning if the variable is set.
#[must_use]
pub fn fake_hung_from_env() -> Vec<Vec<u8>> {
    let Some(v) = std::env::var_os(FAKE_HUNG_ENV) else {
        return Vec::new();
    };
    // A compile-time gate (not `cfg!`): without the feature none of the hook's code or
    // strings are in the binary, whatever the environment says.
    #[cfg(not(feature = "test-hooks"))]
    {
        drop(v);
        eprintln!("gungnird: {FAKE_HUNG_ENV} ignored (built without the test-hooks feature)");
        Vec::new()
    }
    #[cfg(feature = "test-hooks")]
    fake_hung_path(v)
}

#[cfg(feature = "test-hooks")]
fn fake_hung_path(v: std::ffi::OsString) -> Vec<Vec<u8>> {
    let p = lexical(&std::os::unix::ffi::OsStringExt::into_vec(v));
    if p == b"/" {
        eprintln!("gungnird: {FAKE_HUNG_ENV} must name a directory below /");
        return Vec::new();
    }
    eprintln!(
        "gungnird: TEST HOOK: {} is a fake mount whose probes never return",
        Path::new(std::ffi::OsStr::from_bytes(&p)).display()
    );
    vec![p]
}

/// Mount entries for fake mounts (ids from `u64::MAX` down, never a kernel's).
#[must_use]
pub fn fake_entries(paths: &[Vec<u8>]) -> Vec<MountEntry> {
    paths
        .iter()
        .zip(0u64..)
        .map(|(p, i)| MountEntry {
            mnt_id: u64::MAX - 1 - i,
            parent_id: 0,
            major: 0,
            minor: 0,
            root: b"/".to_vec(),
            mount_point: p.clone(),
            fstype: b"fuse.gungnir-test-hung".to_vec(),
            source: b"gungnir-test".to_vec(),
        })
        .collect()
}

/// A prober whose probes of the fake mounts block forever (parked), others go to `inner`.
pub struct FakeHung<P> {
    inner: P,
    paths: Vec<Vec<u8>>,
}

impl<P> FakeHung<P> {
    pub fn new(inner: P, paths: Vec<Vec<u8>>) -> Self {
        Self { inner, paths }
    }
}

impl<P: Prober> Prober for FakeHung<P> {
    fn probe(&self, mount: &MountEntry) -> Outcome {
        if self.paths.contains(&mount.mount_point) {
            loop {
                thread::park(); // a sacrificial thread, as with a real hung mount
            }
        }
        self.inner.probe(mount)
    }
}

#[cfg(test)]
mod tests;
