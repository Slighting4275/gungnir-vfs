use std::{env, ffi::OsString, path::PathBuf, process::ExitCode, time::Duration};

use gungnird::{
    Error, Result, daemon, hooks::Hooks, ipc, ops, seccomp::SeccompMode, store, vfssvc,
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
    // What a live upgrade's old image left (its locks, BC-CM-D02, and whether it bound
    // the socket, F08); read while the process is still single-threaded.
    let handoff = ipc::Handoff::take();

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
    let listener = match ipc::systemd_listener(&handoff)? {
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

    let seccomp = opts
        .seccomp
        .or_else(seccomp_from_env)
        .unwrap_or(SeccompMode::Disabled);
    let hooks = Hooks::from_env();
    let sandbox = daemon::SeccompSandbox {
        fail_tsync: hooks.tsync_fail,
    };
    // A start refused here leaves no socket either.
    let db_path = resolve_db_path(opts.db_path).inspect_err(|_| listener.cleanup())?;
    let cfg = daemon::StartConfig {
        db_path,
        idle_timeout,
        seccomp,
        no_uring: env::var_os(ops::NO_URING_ENV),
        carried_store_lock: handoff.store_lock,
        dirs: vfssvc::HomeDirs {
            xdg_data: env::var_os("XDG_DATA_HOME"),
            home: env::var_os("HOME"),
        },
        hooks,
    };
    // Every refusal or error from here on leaves no socket and, when this start created
    // the store, no store either (DIR-A2-F01, DIR-HC-O1): the sandbox can only go in
    // after the threads exist, so it cannot be checked before the bind.
    let ports = daemon::Ports {
        sandbox: &sandbox,
        exec: &ipc::Execve,
    };
    daemon::run(&listener, &cfg, &ports)
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
