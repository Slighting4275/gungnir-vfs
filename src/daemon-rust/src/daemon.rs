//! The daemon's start, after the control socket is bound, and its serving life: the
//! phases in their order, and the rollback a refused start owes (DIR-A2-F01, DIR-HC-O1:
//! no socket, and no store if this start created it).
//!
//! The order, each step needing the ones before it:
//! 1. (the caller) signals blocked, live-upgrade handoff read, socket bound or adopted;
//! 2. the store's lock (before anything reads or writes the store), then the store;
//! 3. the mount health monitor and the identity resolver gated by it;
//! 4. the file-op engine: restricted io_uring rings made before its workers exist, and
//!    a refusal if a worker under a uring engine has none;
//! 5. the services and their router;
//! 6. the sandbox ([`Sandbox`]), once every thread exists (TSYNC);
//! 7. only then, past the last refusal, the temp ledger is swept and opened (a refused
//!    start leaves the store as it found it, BC-CM-D01), and the daemon serves.
//!
//! Everything a test may want to replace is behind a parameter: the kernel-level steps
//! are [`Ports`] (the sandbox, and the live upgrade's exec), each with two adapters (the
//! real one in the daemon, a recording fake in tests), and the test hooks come in as
//! [`Hooks`].

use std::{
    ffi::OsString,
    io,
    os::fd::RawFd,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use crate::{
    Error, Result,
    fsid::{Resolver, ResolverConfig, SysBackend},
    health::{self, FakeHung, Gated, HealthConfig, HealthService, Monitor, StatfsProber},
    hooks::Hooks,
    ipc, mdsvc,
    ops::{self, Ops, OpsConfig},
    opsvc::{DbMeta, MonitorGate, OpsService},
    seccomp::{self, SeccompMode},
    store::{self, DbConfig, Store, StoreConfig},
    vfssvc,
};

/// Longest a live upgrade under seccomp waits for running file ops before it exits.
pub const UPGRADE_DRAIN_MAX: Duration = Duration::from_secs(30);
/// How long cancelled ops get to remove their temp files and report before the exit.
const CANCEL_WAIT: Duration = Duration::from_secs(2);

/// What a start is asked for, everything from the environment already read.
#[derive(Debug, Clone, Default)]
pub struct StartConfig {
    /// The metadata store.
    pub db_path: PathBuf,
    pub idle_timeout: Option<Duration>,
    pub seccomp: SeccompMode,
    /// `GUNGNIR_NO_URING`'s value ([`ops::choose_engine`]).
    pub no_uring: Option<OsString>,
    /// The store's lock a live upgrade carried ([`ipc::Handoff::store_lock`]).
    pub carried_store_lock: Option<RawFd>,
    pub hooks: Hooks,
}

/// Installs the sandbox on the whole process once every thread exists.
pub trait Sandbox {
    /// # Errors
    /// The sandbox could not go in; the start is refused.
    fn install(&self, mode: SeccompMode) -> io::Result<()>;
}

/// The daemon's sandbox: the seccomp filter on every thread (TSYNC).
pub struct SeccompSandbox {
    /// The TSYNC fault injection ([`Hooks::tsync_fail`]).
    pub fail_tsync: bool,
}

impl Sandbox for SeccompSandbox {
    fn install(&self, mode: SeccompMode) -> io::Result<()> {
        seccomp::apply_sandbox_with(mode, self.fail_tsync)
    }
}

/// The steps that act on the whole process at kernel level, for [`run`] to take.
#[derive(Clone, Copy)]
pub struct Ports<'a> {
    pub sandbox: &'a dyn Sandbox,
    /// The live upgrade's re-exec ([`ipc::Execve`] in the daemon).
    pub exec: &'a dyn ipc::Exec,
}

/// Start on the bound `listener` and serve until a shutdown. A start refused or failed
/// anywhere leaves no socket and, when it created the store, no store; both locks are
/// released only after that cleanup, so another daemon can never take a store this
/// start is still removing (DIR-C1-F02).
///
/// # Errors
/// Why the start was refused or the daemon stopped badly.
pub fn run(listener: &ipc::Listener, cfg: &StartConfig, ports: &Ports<'_>) -> Result<()> {
    let mut fresh = FreshStore::default();
    let mut store_lock = None;
    let r = serve(listener, cfg, ports, &mut fresh, &mut store_lock);
    if r.is_err() {
        listener.cleanup();
        fresh.remove();
    }
    // The store's lock here, the socket's when `listener` drops.
    drop(store_lock);
    r
}

/// Steps 2 to 7 of the module's order.
fn serve(
    listener: &ipc::Listener,
    cfg: &StartConfig,
    ports: &Ports<'_>,
    fresh: &mut FreshStore,
    store_lock: &mut Option<store::StoreLock>,
) -> Result<()> {
    let hooks = &cfg.hooks;
    // 2. The store, as the only daemon on it (DIR-C1-F02): its lock comes before anything
    // reads or writes it, its temp ledger included, and before what this start would
    // create is noted (a refused start must never take another daemon's new store for its
    // own).
    let db_path = &cfg.db_path;
    let new_dirs = FreshStore::missing_dirs(db_path);
    // A lock refused for an insecure directory leaves no empty directory of ours behind.
    fresh.dirs.clone_from(&new_dirs);
    *store_lock = store::lock_store(db_path, cfg.carried_store_lock)?;
    let new_lock = store_lock
        .as_ref()
        .filter(|l| l.created())
        .map(|l| l.path().to_path_buf());
    *fresh = FreshStore::note(db_path, new_dirs, new_lock);
    let db = store::spawn(
        Store::open(db_path, StoreConfig::default())?,
        DbConfig::default(),
    )?;
    eprintln!("gungnird: metadata db ready at {}", db_path.display());

    // 3. Mount health (milestone 7)
    let fake = hooks.fake_hung.clone();
    let monitor = Monitor::start(
        HealthConfig::default(),
        Arc::new(FakeHung::new(StatfsProber, fake.clone())),
        health::Source::Proc,
        health::fake_entries(&fake),
    )?;
    let resolver = Arc::new(Resolver::new(
        Gated::new(SysBackend::new()?, Arc::clone(&monitor)),
        ResolverConfig::default(),
    )?);
    let sink: Arc<dyn health::SuspectSink> = resolver.clone();
    monitor.set_sink(Arc::downgrade(&sink));

    // 4. File operations (milestone 8)
    let seccomp_mode = cfg.seccomp;
    let (mut engine, why) = ops::choose_engine(cfg.no_uring.as_deref());
    let ops_cfg = OpsConfig::default().with_hooks(hooks);
    let workers = ops_cfg.workers.max(1);
    // The filter refuses io_uring_setup. Every worker ring, the first workers' included,
    // is created and restricted here, before Ops::start spawns them: a worker creating
    // its own ring raced the filter install and fell back to syscalls (BC-A2-F01). How
    // many is the engine's own knowledge (OpsConfig::sandbox_rings). If the rings cannot
    // be made, every worker uses the thread engine, said once here (D-044 item 1), never
    // a per-worker mix.
    if seccomp_mode != SeccompMode::Disabled
        && engine == ops::io::EngineKind::Uring
        && let Err(e) = ops::io::prepare_sandbox_rings(ops_cfg.sandbox_rings())
    {
        eprintln!(
            "gungnird: restricted io_uring rings for the sandbox failed ({e}): \
             thread engine for every worker"
        );
        engine = ops::io::EngineKind::Threads;
    }
    eprintln!("gungnird: file ops engine: {engine:?} ({why})");
    let ops = Arc::new(Ops::start(
        ops_cfg,
        engine,
        Arc::new(MonitorGate::new(Arc::clone(&monitor))),
        Arc::new(DbMeta::new(Arc::clone(&resolver), db.clone())),
    )?);
    if seccomp_mode != SeccompMode::Disabled && engine == ops::io::EngineKind::Uring {
        // Every first worker has its ring before the filter goes in; a worker on plain
        // syscalls under a uring engine would be a silent fallback: refuse to start.
        let (made, uring) = ops.wait_workers_ready(workers, Duration::from_secs(5));
        // Fault injection for the mixed-engine refusal (DIR-A2-F01).
        let uring = if hooks.mixed_rings {
            uring.saturating_sub(1)
        } else {
            uring
        };
        if made < workers || uring < workers {
            let msg = format!(
                "only {uring} of {workers} file op workers on restricted io_uring rings \
                 ({made} started); refusing to start sandboxed"
            );
            eprintln!("gungnird: error: {msg}");
            return Err(Error::Io(io::Error::other(msg)));
        }
        eprintln!("gungnird: {uring} of {workers} file op workers on restricted io_uring rings");
    }

    // 5. The services and their router.
    let vfs = vfssvc::Svc::new(Arc::clone(&ops), vfssvc::SvcConfig::daemon(hooks));
    let ops_for_ledger = Arc::clone(&ops);
    let services: Vec<Arc<dyn ipc::Service>> = vec![
        Arc::new(vfssvc::VfsService::new(vfs)),
        Arc::new(OpsService::new(ops)),
        Arc::new(HealthService::new(monitor)),
        Arc::new(mdsvc::MdService::new(resolver, db.clone())),
    ];
    let handler: Arc<dyn ipc::Handler> = Arc::new(ipc::Router::new(services)?);

    // 6. The sandbox (milestone 12), every thread existing by now.
    if seccomp_mode != SeccompMode::Disabled {
        eprintln!("gungnird: applying seccomp BPF sandbox ({seccomp_mode})");
        ports.sandbox.install(seccomp_mode)?;
    }
    // From here the store is in use: an error no longer removes it.
    *fresh = FreshStore::default();

    // 7. Temp files of copies and moves a previous run left unfinished (killed, or a
    // stuck op abandoned at a drain): removed in the background, since they may sit on a
    // mount that is still hung (BC-A2-F03b, BC-HC-F06). Only now, past the last refusal
    // (the ring check, the sandbox): a refused start must leave the store as it found
    // it, its ledger included (BC-CM-D01). No op can start before serving does.
    let ledger_path = db_path.with_file_name("ops-pending");
    if let Err(e) = ops::detach_temp_sweep(&ledger_path) {
        eprintln!("gungnird: temp ledger {}: {e}", ledger_path.display());
    }
    match ops::open_ledger(&ledger_path, true) {
        Ok(f) => ops_for_ledger.set_temp_ledger(f),
        Err(e) => eprintln!("gungnird: temp ledger {}: {e}", ledger_path.display()),
    }
    let kept_path = ledger_path.with_extension("kept");
    match ops::open_ledger(&kept_path, true) {
        Ok(f) => ops_for_ledger.set_kept_ledger(f),
        Err(e) => eprintln!("gungnird: temp ledger {}: {e}", kept_path.display()),
    }

    // Serve with signal handling and idle shutdown multiplexing (milestone 11).
    let ipc_cfg = ipc::Config {
        handshake_timeout: Duration::from_secs(2),
        idle_poll: Duration::from_millis(200),
        idle_timeout: cfg.idle_timeout,
        handle_signals: true,
    };

    // Lifecycle shutdown or live in-place upgrade. A failed upgrade exec leaves
    // everything as it was: log it and keep serving (BC-HC-F02).
    // Every way out persists the store first; `when` names the moment in the log.
    let persist = |when: &str| {
        if let Err(e) = db.flush_and_checkpoint() {
            eprintln!("gungnird: database checkpoint {when} failed: {e}");
        }
    };
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        match ipc::serve_counting(&listener.socket, ipc_cfg, &handler, &active)? {
            ipc::ShutdownReason::Signal(sig) => {
                eprintln!("gungnird: signal {sig} received; persisting state and shutting down");
                persist("on shutdown");
                listener.cleanup();
                break;
            }
            ipc::ShutdownReason::IdleTimeout => {
                eprintln!("gungnird: idle timeout elapsed; persisting state and shutting down");
                persist("on idle shutdown");
                listener.cleanup();
                break;
            }
            ipc::ShutdownReason::LiveUpgrade(sig) if seccomp_mode != SeccompMode::Disabled => {
                // The filter denies execve (D-044 item 2): no re-exec in place. Let running
                // file ops finish, persist state and exit cleanly; the service manager
                // starts the new binary (on the next connection, with socket activation).
                eprintln!(
                    "gungnird: signal {sig} received; live upgrade under seccomp: \
                     draining, then exiting for the service manager to start the new binary"
                );
                let cut = drain(handler.as_ref(), hooks.drain.unwrap_or(UPGRADE_DRAIN_MAX));
                persist("before upgrade exit");
                listener.cleanup();
                if let Some(why) = cut {
                    // Not a clean upgrade exit: some ops were cancelled (BC-A2-F03b/c).
                    return Err(Error::Io(io::Error::other(why)));
                }
                break;
            }
            ipc::ShutdownReason::LiveUpgrade(sig) => {
                eprintln!(
                    "gungnird: signal {sig} received; persisting state and performing live upgrade"
                );
                persist("before upgrade");
                let store_fd = store_lock.as_ref().map(store::StoreLock::fd);
                if let Err(e) = ipc::perform_live_upgrade(
                    listener,
                    store_fd,
                    hooks.upgrade_exe.as_deref(),
                    ports.exec,
                ) {
                    eprintln!("gungnird: live upgrade failed, still serving: {e}");
                }
            }
        }
    }

    Ok(())
}

/// The store files a start created, removed if that start fails (DIR-A2-F01).
#[derive(Default)]
struct FreshStore {
    files: Vec<PathBuf>,
    /// The store lock file, if this start created it with the store; removed last of the
    /// files, while the lock is still held (DIR-C1-F02).
    lock: Option<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl FreshStore {
    /// The directories above `db` that do not exist yet, innermost first.
    fn missing_dirs(db: &Path) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        let mut d = db.parent();
        while let Some(p) = d {
            if p.as_os_str().is_empty() || std::fs::symlink_metadata(p).is_ok() {
                break;
            }
            dirs.push(p.to_path_buf());
            d = p.parent();
        }
        dirs
    }

    /// What a start with the store at `db` would create: nothing if it exists. `dirs`
    /// were missing and `lock` was created before the store lock was taken.
    fn note(db: &Path, dirs: Vec<PathBuf>, lock: Option<PathBuf>) -> Self {
        // The temp ledger next to the store (BC-A2-F03) and its kept file are created by
        // every start.
        let ledger = db.with_file_name("ops-pending");
        let kept = ledger.with_extension("kept");
        if std::fs::symlink_metadata(db).is_ok() {
            let files = [ledger, kept]
                .into_iter()
                .filter(|p| std::fs::symlink_metadata(p).is_err())
                .collect();
            return Self {
                files,
                lock: None,
                dirs: Vec::new(),
            };
        }
        let mut files = vec![db.to_path_buf()];
        // Only if new: left by an earlier run, they are records, not this start's litter.
        files.extend(
            [ledger, kept]
                .into_iter()
                .filter(|p| std::fs::symlink_metadata(p).is_err()),
        );
        for sfx in ["-wal", "-shm", "-journal"] {
            let mut p = db.as_os_str().to_os_string();
            p.push(sfx);
            files.push(PathBuf::from(p));
        }
        Self { files, lock, dirs }
    }

    /// Remove the new store, and the directories created for it if they are empty.
    fn remove(&self) {
        let mut n = 0;
        for f in &self.files {
            if std::fs::remove_file(f).is_ok()
                && !f.ends_with("ops-pending")
                && !f.ends_with("ops-pending.kept")
            {
                n += 1;
            }
        }
        if let Some(l) = &self.lock {
            let _ = std::fs::remove_file(l);
        }
        for d in &self.dirs {
            let _ = std::fs::remove_dir(d);
        }
        if n > 0 {
            eprintln!("gungnird: removed the store this failed start created");
        }
    }
}

/// Drain before an upgrade exit (D-044 item 2, BC-A2-F03): new ops are refused at once
/// (a); running ones get until `max` to finish (b, [`UPGRADE_DRAIN_MAX`] unless the
/// drain hook says otherwise), and a SIGTERM or SIGINT ends the wait early (c). Whatever
/// still runs then is cancelled: each op removes its temp file and sends its Cancelled
/// done event, within [`CANCEL_WAIT`]. Returns why the exit is not clean (ops
/// cancelled, or still stuck after the cancel), or None.
fn drain(handler: &dyn ipc::Handler, max: Duration) -> Option<String> {
    handler.begin_drain();
    let stop = ipc::stop_signal_fd()
        .map_err(|e| eprintln!("gungnird: no stop signal during the drain: {e}"))
        .ok();
    let t0 = std::time::Instant::now();
    let mut stopped = None;
    while handler.is_busy() && t0.elapsed() < max && stopped.is_none() {
        match &stop {
            Some(fd) => stopped = ipc::wait_stop_signal(fd, 20),
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    if !handler.is_busy() {
        if stopped.is_some() {
            eprintln!("gungnird: stop signal during the drain; nothing left running");
        }
        return None;
    }
    let why = match stopped {
        Some(sig) => format!("signal {sig} during the drain"),
        None => format!("file ops still running after {max:?}"),
    };
    let n = handler.cancel_all();
    eprintln!("gungnird: {why}: cancelling {n} file op(s)");
    let t1 = std::time::Instant::now();
    while handler.is_busy() && t1.elapsed() < CANCEL_WAIT {
        std::thread::sleep(Duration::from_millis(10));
    }
    if handler.is_busy() {
        eprintln!(
            "gungnird: file ops still stuck {CANCEL_WAIT:?} after the cancel; \
             their temp files go at the next start"
        );
        Some(format!("{why}: {n} file op(s) cancelled, some still stuck"))
    } else {
        Some(format!("{why}: {n} file op(s) cancelled"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use std::sync::Mutex;

    /// An exec that never replaces the test process.
    struct NoExec;

    impl ipc::Exec for NoExec {
        fn exec(
            &self,
            _: &std::ffi::CStr,
            _: &[std::ffi::CString],
            _: &[std::ffi::CString],
        ) -> io::Error {
            io::Error::from_raw_os_error(libc::ENOEXEC)
        }
    }

    fn ports(sandbox: &dyn Sandbox) -> Ports<'_> {
        Ports {
            sandbox,
            exec: &NoExec,
        }
    }

    /// What the sandbox saw when it was asked in, and whether it refused.
    #[derive(Default)]
    struct Recording {
        seen: Mutex<Vec<String>>,
        refuse: bool,
        db: PathBuf,
    }

    impl Sandbox for Recording {
        fn install(&self, mode: SeccompMode) -> io::Result<()> {
            let exists = |p: &Path| std::fs::symlink_metadata(p).is_ok();
            let mut seen = self.seen.lock().unwrap();
            seen.push(format!("mode {mode}"));
            seen.push(format!("store {}", exists(&self.db)));
            seen.push(format!(
                "ledger {}",
                exists(&self.db.with_file_name("ops-pending"))
            ));
            if self.refuse {
                Err(io::Error::other("no sandbox here"))
            } else {
                Ok(())
            }
        }
    }

    /// A start refused at the sandbox: the store existed by then and the ledger did not
    /// (the order), and the refusal leaves no socket, no store, no directories of its own
    /// and no lock behind (the rollback). In process: no daemon binary, no environment.
    #[test]
    fn a_refused_sandbox_leaves_nothing_behind() -> Result<()> {
        let dir = TestDir::new("daemon-refused")?;
        let sock = dir.join("gungnird.sock");
        let listener = ipc::bind(&sock)?;
        let db = dir.join("new/data/metadata.db");
        let sandbox = Recording {
            refuse: true,
            db: db.clone(),
            ..Recording::default()
        };
        let cfg = StartConfig {
            db_path: db.clone(),
            seccomp: SeccompMode::Filter,
            // The thread engine: a uring engine would make restricted rings, which are
            // process-wide, for a sandbox this test never installs.
            no_uring: Some("1".into()),
            ..StartConfig::default()
        };
        let r = run(&listener, &cfg, &ports(&sandbox));
        assert!(r.is_err(), "the start was refused");
        assert_eq!(
            *sandbox.seen.lock().unwrap(),
            ["mode filter", "store true", "ledger false"]
        );
        assert!(!sock.exists(), "no socket left");
        assert!(!db.exists(), "no store left");
        assert!(!dir.join("new").exists(), "no directory of this start left");
        drop(listener);
        // The store's lock went with the start: another can take the place at once.
        std::fs::create_dir_all(db.parent().unwrap_or(&db))?;
        assert!(store::lock_store(&db, None)?.is_some());
        Ok(())
    }

    /// A disabled sandbox is never asked in.
    #[test]
    fn a_disabled_sandbox_is_never_installed() -> Result<()> {
        let dir = TestDir::new("daemon-nosandbox")?;
        let listener = ipc::bind(&dir.join("gungnird.sock"))?;
        let db = dir.join("metadata.db");
        // Refuse anyway: reaching it would fail the start. Then stop the serving loop
        // from the outside the only way it allows, an idle timeout with no client.
        let sandbox = Recording {
            refuse: true,
            db: db.clone(),
            ..Recording::default()
        };
        let cfg = StartConfig {
            db_path: db,
            seccomp: SeccompMode::Disabled,
            no_uring: Some("1".into()),
            idle_timeout: Some(Duration::from_millis(300)),
            ..StartConfig::default()
        };
        run(&listener, &cfg, &ports(&sandbox))?;
        assert!(sandbox.seen.lock().unwrap().is_empty());
        Ok(())
    }
}
