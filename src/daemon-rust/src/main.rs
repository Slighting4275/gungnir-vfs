use std::{
    env, ffi::OsString, os::unix::fs::OpenOptionsExt, path::PathBuf, process::ExitCode, sync::Arc,
    time::Duration,
};

use gungnird::{
    Error, Result,
    fsid::{Resolver, ResolverConfig, SysBackend},
    health::{self, FakeHung, Gated, HealthConfig, HealthHandler, Monitor, StatfsProber},
    ipc, mdsvc,
    ops::{self, Ops, OpsConfig},
    opsvc::{DbMeta, MonitorGate, OpsHandler},
    seccomp::{self, SeccompMode},
    store::{self, DbConfig, Store, StoreConfig},
    vfssvc,
};

const HELP_TEXT: &str = "\
gungnird - Gungnir virtual filesystem background daemon

Usage: gungnird [OPTIONS] [DB_PATH]

Arguments:
  [DB_PATH]                  Path to metadata database

Options:
  -s, --socket <PATH>        Path to UNIX control socket (overrides env and default)
  -d, --db <PATH>            Path to metadata database (overrides env and default)
  -i, --idle-timeout <SECS>  Idle shutdown timeout in seconds (0 = disabled)
  -S, --seccomp[=MODE]       Enable Linux seccomp BPF sandbox (filter, strict, disabled)
      --no-seccomp           Disable seccomp sandbox
  -V, --version              Print version information and exit
  -h, --help                 Print this help information and exit
";

#[derive(Default, Debug, PartialEq, Eq)]
pub struct CliOptions {
    pub db_path: Option<PathBuf>,
    pub socket_path: Option<PathBuf>,
    pub idle_timeout: Option<Duration>,
    pub seccomp: Option<SeccompMode>,
    pub help: bool,
    pub version: bool,
}

pub fn parse_cli_args<I, T>(args: I) -> std::result::Result<CliOptions, String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut opts = CliOptions::default();
    let mut iter = args.into_iter().map(Into::into).skip(1);

    while let Some(arg) = iter.next() {
        let s = arg.to_string_lossy();
        if s == "-h" || s == "--help" {
            opts.help = true;
            return Ok(opts);
        } else if s == "-V" || s == "--version" {
            opts.version = true;
            return Ok(opts);
        } else if s == "-s" || s == "--socket" {
            let val = iter
                .next()
                .ok_or_else(|| format!("option '{s}' requires an argument"))?;
            opts.socket_path = Some(PathBuf::from(val));
        } else if let Some(rest) = s.strip_prefix("--socket=") {
            opts.socket_path = Some(PathBuf::from(rest));
        } else if s == "-d" || s == "--db" {
            let val = iter
                .next()
                .ok_or_else(|| format!("option '{s}' requires an argument"))?;
            opts.db_path = Some(PathBuf::from(val));
        } else if let Some(rest) = s.strip_prefix("--db=") {
            opts.db_path = Some(PathBuf::from(rest));
        } else if s == "-i" || s == "--idle-timeout" {
            let val = iter
                .next()
                .ok_or_else(|| format!("option '{s}' requires an argument"))?;
            let val_str = val.to_string_lossy();
            let secs: u64 = val_str
                .parse()
                .map_err(|_| format!("invalid integer value for '{s}': '{val_str}'"))?;
            opts.idle_timeout = if secs > 0 {
                Some(Duration::from_secs(secs))
            } else {
                None
            };
        } else if let Some(rest) = s.strip_prefix("--idle-timeout=") {
            let secs: u64 = rest
                .parse()
                .map_err(|_| format!("invalid integer value for '--idle-timeout': '{rest}'"))?;
            opts.idle_timeout = if secs > 0 {
                Some(Duration::from_secs(secs))
            } else {
                None
            };
        } else if s == "-S" || s == "--seccomp" {
            opts.seccomp = Some(SeccompMode::Filter);
        } else if let Some(rest) = s.strip_prefix("--seccomp=") {
            let mode = SeccompMode::parse(rest).ok_or_else(|| {
                format!(
                    "invalid value for '--seccomp': '{rest}' (expected filter, strict, or disabled)"
                )
            })?;
            opts.seccomp = Some(mode);
        } else if s == "--no-seccomp" {
            opts.seccomp = Some(SeccompMode::Disabled);
        } else if s.starts_with('-') {
            return Err(format!("unrecognized option '{s}'"));
        } else {
            // Positional argument: DB path
            if opts.db_path.is_none() {
                opts.db_path = Some(PathBuf::from(arg));
            } else {
                return Err(format!("unexpected positional argument '{s}'"));
            }
        }
    }

    Ok(opts)
}

fn idle_timeout_from_env() -> Option<Duration> {
    for var in ["GUNGNIR_IDLE_TIMEOUT_SEC", "GUNGNIR_IDLE_TIMEOUT"] {
        if let Ok(v) = env::var(var)
            && let Ok(secs) = v.trim().parse::<u64>()
            && secs > 0
        {
            return Some(Duration::from_secs(secs));
        }
    }
    None
}

fn seccomp_from_env() -> Option<SeccompMode> {
    if let Ok(v) = env::var("GUNGNIR_SECCOMP") {
        SeccompMode::parse(v.trim())
    } else {
        None
    }
}

fn resolve_db_path(cli_db: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = cli_db {
        return Ok(path);
    }
    store::default_db_path(
        env::var_os("XDG_DATA_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
    )
}

fn run() -> Result<()> {
    ipc::block_lifecycle_signals()?;
    // Before anything can replace the binary (BC-HC-F05).
    ipc::remember_startup_exe();

    let opts = parse_cli_args(env::args_os()).map_err(|msg| {
        eprintln!("gungnird: error: {msg}");
        Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
    })?;

    if opts.help {
        print!("{HELP_TEXT}");
        return Ok(());
    }
    if opts.version {
        println!("gungnird {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let idle_timeout = opts.idle_timeout.or_else(idle_timeout_from_env);

    // 1. Establish listening control socket: adopt systemd activation or bind
    let listener = match ipc::systemd_listener()? {
        Some(l) => {
            eprintln!("gungnird: adopting systemd socket activation on fd 3");
            l
        }
        None => {
            let sock = match opts.socket_path {
                Some(p) => p,
                None => ipc::socket_path_from_env()?,
            };
            let l = ipc::bind(&sock)?;
            eprintln!("gungnird: listening on {}", sock.display());
            l
        }
    };

    // Every refusal or error from here on leaves no socket and, when this start created
    // the store, no store either (DIR-A2-F01, DIR-HC-O1): the sandbox can only go in
    // after the threads exist, so it cannot be checked before the bind.
    let mut fresh = FreshStore::default();
    let r = serve_daemon(
        &listener,
        opts.db_path,
        idle_timeout,
        opts.seccomp,
        &mut fresh,
    );
    if r.is_err() {
        listener.cleanup();
        fresh.remove();
    }
    // The lock is released when `listener` drops, after the cleanup.
    r
}

/// Steps 2 to 7 of [`run`], after the bind.
fn serve_daemon(
    listener: &ipc::Listener,
    db_path: Option<PathBuf>,
    idle_timeout: Option<Duration>,
    seccomp: Option<SeccompMode>,
    fresh: &mut FreshStore,
) -> Result<()> {
    // 2. Open metadata database in WAL mode
    let db_path = resolve_db_path(db_path)?;
    *fresh = FreshStore::note(&db_path);
    let db = store::spawn(
        Store::open(&db_path, StoreConfig::default())?,
        DbConfig::default(),
    )?;
    eprintln!("gungnird: metadata db ready at {}", db_path.display());

    // 3. Mount health (milestone 7)
    let fake = health::fake_hung_from_env();
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
    let seccomp_mode = seccomp
        .or_else(seccomp_from_env)
        .unwrap_or(SeccompMode::Disabled);
    let (mut engine, why) = ops::choose_engine(env::var_os(ops::NO_URING_ENV).as_deref());
    let ops_cfg = OpsConfig::from_env();
    let workers = ops_cfg.workers.max(1);
    // The filter refuses io_uring_setup. Every worker ring, the first workers' included,
    // is created and restricted here, before Ops::start spawns them: a worker creating
    // its own ring raced the filter install and fell back to syscalls (BC-A2-F01).
    // Twice the workers covers replacements of stuck ones; GRAVEYARD_MAX more cover the
    // rings still waiting for the kernel. If the rings cannot be made, every worker uses
    // the thread engine, said once here (D-044 item 1), never a per-worker mix.
    if seccomp_mode != SeccompMode::Disabled && engine == ops::io::EngineKind::Uring {
        let n = workers * 2 + ops::io::GRAVEYARD_MAX;
        // An exhausted pool on demand, for the refusal path (A2-MGR-03).
        #[cfg(feature = "test-hooks")]
        let n = if env::var_os(ops::RING_LOSS_ENV).is_some() {
            workers
        } else {
            n
        };
        if let Err(e) = ops::io::prepare_sandbox_rings(n) {
            eprintln!(
                "gungnird: restricted io_uring rings for the sandbox failed ({e}): \
                 thread engine for every worker"
            );
            engine = ops::io::EngineKind::Threads;
        }
    }
    eprintln!("gungnird: file ops engine: {engine:?} ({why})");
    // Temp files of copies and moves a previous run left unfinished (killed, or a stuck
    // op abandoned at a drain): removed before any new op (BC-A2-F03b, BC-HC-F06).
    let ledger_path = db_path.with_file_name("ops-pending");
    match ops::sweep_temp_ledger(&ledger_path) {
        Ok(0) => {}
        Ok(n) => eprintln!("gungnird: removed {n} temp file(s) left by unfinished file ops"),
        Err(e) => eprintln!("gungnird: temp ledger {}: {e}", ledger_path.display()),
    }
    let ops = Arc::new(Ops::start(
        ops_cfg,
        engine,
        Arc::new(MonitorGate::new(Arc::clone(&monitor))),
        Arc::new(DbMeta::new(Arc::clone(&resolver), db.clone())),
    )?);
    match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&ledger_path)
    {
        Ok(f) => ops.set_temp_ledger(f),
        Err(e) => eprintln!("gungnird: temp ledger {}: {e}", ledger_path.display()),
    }
    if seccomp_mode != SeccompMode::Disabled && engine == ops::io::EngineKind::Uring {
        // Every first worker has its ring before the filter goes in; a worker on plain
        // syscalls under a uring engine would be a silent fallback: refuse to start.
        let (made, uring) = ops.wait_workers_ready(workers, Duration::from_secs(5));
        #[cfg(feature = "test-hooks")]
        let uring = if env::var_os("GUNGNIR_TEST_MIXED_RINGS").is_some() {
            // Fault injection for the mixed-engine refusal (DIR-A2-F01).
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
            return Err(Error::Io(std::io::Error::other(msg)));
        }
        eprintln!("gungnird: {uring} of {workers} file op workers on restricted io_uring rings");
    }

    // 5. Wire handlers
    let md: Arc<dyn ipc::Handler> = Arc::new(mdsvc::Service::new(resolver, db.clone()));
    let health: Arc<dyn ipc::Handler> = Arc::new(HealthHandler::new(md, monitor));
    let vfs = vfssvc::Svc::new(
        Arc::clone(&ops),
        env::var_os("XDG_DATA_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
    );
    let handler: Arc<dyn ipc::Handler> = Arc::new(OpsHandler::new(health, ops));
    let handler: Arc<dyn ipc::Handler> = Arc::new(vfssvc::VfsHandler::new(handler, vfs));

    // Milestone 12: Apply Seccomp BPF Sandbox
    if seccomp_mode != SeccompMode::Disabled {
        eprintln!("gungnird: applying seccomp BPF sandbox ({seccomp_mode})");
        seccomp::apply_sandbox(seccomp_mode)?;
    }
    // From here the store is in use: an error no longer removes it.
    *fresh = FreshStore::default();

    // 6. Serve with signal handling and idle shutdown multiplexing (milestone 11)
    let cfg = ipc::Config {
        handshake_timeout: Duration::from_secs(2),
        idle_poll: Duration::from_millis(200),
        idle_timeout,
        handle_signals: true,
    };

    // 7. Handle lifecycle shutdown or live in-place upgrade. A failed upgrade exec
    // leaves everything as it was: log it and keep serving (BC-HC-F02).
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        match ipc::serve_counting(&listener.socket, cfg, &handler, &active)? {
            ipc::ShutdownReason::Signal(sig) => {
                eprintln!("gungnird: signal {sig} received; persisting state and shutting down");
                if let Err(e) = db.flush_and_checkpoint() {
                    eprintln!("gungnird: database checkpoint on shutdown failed: {e}");
                }
                listener.cleanup();
                break;
            }
            ipc::ShutdownReason::IdleTimeout => {
                eprintln!("gungnird: idle timeout elapsed; persisting state and shutting down");
                if let Err(e) = db.flush_and_checkpoint() {
                    eprintln!("gungnird: database checkpoint on idle shutdown failed: {e}");
                }
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
                let cut = drain(handler.as_ref());
                if let Err(e) = db.flush_and_checkpoint() {
                    eprintln!("gungnird: database checkpoint before upgrade exit failed: {e}");
                }
                listener.cleanup();
                if let Some(why) = cut {
                    // Not a clean upgrade exit: some ops were cancelled (BC-A2-F03b/c).
                    return Err(Error::Io(std::io::Error::other(why)));
                }
                break;
            }
            ipc::ShutdownReason::LiveUpgrade(sig) => {
                eprintln!(
                    "gungnird: signal {sig} received; persisting state and performing live upgrade"
                );
                if let Err(e) = db.flush_and_checkpoint() {
                    eprintln!("gungnird: database checkpoint before upgrade failed: {e}");
                }
                if let Err(e) = ipc::perform_live_upgrade(listener) {
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
    dirs: Vec<PathBuf>,
}

impl FreshStore {
    /// What a start with the store at `db` would create: nothing if it exists.
    fn note(db: &std::path::Path) -> Self {
        // The temp ledger next to the store (BC-A2-F03) is created by every start.
        let ledger = db.with_file_name("ops-pending");
        let new_ledger = std::fs::symlink_metadata(&ledger).is_err();
        if std::fs::symlink_metadata(db).is_ok() {
            return Self {
                files: if new_ledger { vec![ledger] } else { Vec::new() },
                dirs: Vec::new(),
            };
        }
        let mut files = vec![db.to_path_buf(), ledger];
        for sfx in ["-wal", "-shm", "-journal"] {
            let mut p = db.as_os_str().to_os_string();
            p.push(sfx);
            files.push(PathBuf::from(p));
        }
        let mut dirs = Vec::new();
        let mut d = db.parent();
        while let Some(p) = d {
            if p.as_os_str().is_empty() || std::fs::symlink_metadata(p).is_ok() {
                break;
            }
            dirs.push(p.to_path_buf());
            d = p.parent();
        }
        Self { files, dirs }
    }

    /// Remove the new store, and the directories created for it if they are empty.
    fn remove(&self) {
        let mut n = 0;
        for f in &self.files {
            if std::fs::remove_file(f).is_ok() && !f.ends_with("ops-pending") {
                n += 1;
            }
        }
        for d in &self.dirs {
            let _ = std::fs::remove_dir(d);
        }
        if n > 0 {
            eprintln!("gungnird: removed the store this failed start created");
        }
    }
}

/// Longest a live upgrade under seccomp waits for running file ops before it exits.
const UPGRADE_DRAIN_MAX: Duration = Duration::from_secs(30);
/// How long cancelled ops get to remove their temp files and report before the exit.
const CANCEL_WAIT: Duration = Duration::from_secs(2);

/// The drain bound: [`UPGRADE_DRAIN_MAX`], or `GUNGNIR_TEST_DRAIN_MS` in a test-hooks
/// build.
fn drain_max() -> Duration {
    #[cfg(feature = "test-hooks")]
    if let Some(ms) = env::var("GUNGNIR_TEST_DRAIN_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        eprintln!("gungnird: TEST HOOK: drain bound {ms} ms");
        return Duration::from_millis(ms);
    }
    UPGRADE_DRAIN_MAX
}

/// Drain before an upgrade exit (D-044 item 2, BC-A2-F03): new ops are refused at once
/// (a); running ones get until the bound to finish (b), and a SIGTERM or SIGINT ends
/// the wait early (c). Whatever still runs then is cancelled: each op removes its temp
/// file and sends its Cancelled done event, within [`CANCEL_WAIT`]. Returns why the
/// exit is not clean (ops cancelled, or still stuck after the cancel), or None.
fn drain(handler: &dyn ipc::Handler) -> Option<String> {
    handler.begin_drain();
    let stop = ipc::stop_signal_fd()
        .map_err(|e| eprintln!("gungnird: no stop signal during the drain: {e}"))
        .ok();
    let max = drain_max();
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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gungnird: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing_options() {
        // Defaults
        let opts = parse_cli_args(["gungnird"]).expect("default args");
        assert_eq!(opts, CliOptions::default());

        // Help
        let opts = parse_cli_args(["gungnird", "-h"]).expect("help short");
        assert!(opts.help);
        let opts = parse_cli_args(["gungnird", "--help"]).expect("help long");
        assert!(opts.help);

        // Version
        let opts = parse_cli_args(["gungnird", "-V"]).expect("version short");
        assert!(opts.version);
        let opts = parse_cli_args(["gungnird", "--version"]).expect("version long");
        assert!(opts.version);

        // Positional db
        let opts = parse_cli_args(["gungnird", "/var/data/meta.db"]).expect("positional db");
        assert_eq!(opts.db_path, Some(PathBuf::from("/var/data/meta.db")));

        // Flags
        let opts = parse_cli_args([
            "gungnird",
            "-d",
            "/tmp/db.sqlite",
            "-s",
            "/tmp/test.sock",
            "-i",
            "30",
        ])
        .expect("all flags short");
        assert_eq!(opts.db_path, Some(PathBuf::from("/tmp/db.sqlite")));
        assert_eq!(opts.socket_path, Some(PathBuf::from("/tmp/test.sock")));
        assert_eq!(opts.idle_timeout, Some(Duration::from_secs(30)));

        // Long flags with equals
        let opts = parse_cli_args([
            "gungnird",
            "--db=/tmp/db.sqlite",
            "--socket=/tmp/test.sock",
            "--idle-timeout=120",
        ])
        .expect("long flags with equals");
        assert_eq!(opts.db_path, Some(PathBuf::from("/tmp/db.sqlite")));
        assert_eq!(opts.socket_path, Some(PathBuf::from("/tmp/test.sock")));
        assert_eq!(opts.idle_timeout, Some(Duration::from_secs(120)));

        // Disable idle timeout with 0
        let opts = parse_cli_args(["gungnird", "-i", "0"]).expect("idle timeout 0");
        assert_eq!(opts.idle_timeout, None);

        // Seccomp flags
        let opts = parse_cli_args(["gungnird", "-S"]).expect("seccomp short");
        assert_eq!(opts.seccomp, Some(SeccompMode::Filter));
        let opts = parse_cli_args(["gungnird", "--seccomp"]).expect("seccomp long");
        assert_eq!(opts.seccomp, Some(SeccompMode::Filter));
        let opts = parse_cli_args(["gungnird", "--seccomp=strict"]).expect("seccomp strict");
        assert_eq!(opts.seccomp, Some(SeccompMode::Strict));
        let opts = parse_cli_args(["gungnird", "--no-seccomp"]).expect("no-seccomp");
        assert_eq!(opts.seccomp, Some(SeccompMode::Disabled));

        // Errors
        assert!(parse_cli_args(["gungnird", "--unknown-opt"]).is_err());
        assert!(parse_cli_args(["gungnird", "-i", "not-a-number"]).is_err());
        assert!(parse_cli_args(["gungnird", "-s"]).is_err());
        assert!(parse_cli_args(["gungnird", "pos1", "pos2"]).is_err());
    }
}
