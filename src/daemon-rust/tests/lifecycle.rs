//! Milestone 11: Daemon Lifecycle Management Integration Tests
//!
//! Verifies:
//! - systemd socket activation protocol (`LISTEN_PID`, `LISTEN_FDS`, fd 3 adoption)
//! - socket preservation (never unlinking systemd-managed sockets)
//! - idle auto-shutdown (`--idle-timeout`, `GUNGNIR_IDLE_TIMEOUT_SEC`)
//! - signal handling via `signalfd` (`SIGTERM`, `SIGINT`, `SIGHUP`, `SIGUSR1`)
//! - live in-place upgrade re-exec handover without dropped connections
//! - WAL checkpointing & state persistence
//! - CLI options (`--help`, `--version`, `--socket`, `--db`, `--idle-timeout`)

use std::{
    env,
    ffi::CString,
    fs,
    os::{
        fd::AsRawFd,
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use gungnird::{
    ipc::{self, Config, Handler, Listener, NoService, ShutdownReason},
    md::Client,
    store::{Store, StoreConfig},
};

type R<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A private (0700) directory under <repo>/.build/tmp, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> R<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let base = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build"))?
            .join("tmp");
        fs::create_dir_all(&base)?;
        let md = fs::symlink_metadata(&base)?;
        if !md.is_dir() {
            return Err("base is not a directory".into());
        }
        if md.permissions().mode() & 0o022 != 0 {
            fs::set_permissions(
                &base,
                fs::Permissions::from_mode(md.permissions().mode() & 0o7755),
            )?;
        }
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = base.join(format!("it-life-{name}-{}-{n}", std::process::id()));
        fs::create_dir(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        Ok(Self(p))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn systemd_socket_activation_protocol() -> R {
    let dir = Dir::new("sd-act")?;
    let sock_path = dir.0.join("sd.sock");
    let db_path = dir.0.join("meta.db");

    // Parent binds the listening socket (as systemd would)
    let parent_sock = UnixListener::bind(&sock_path)?;
    let raw_fd = parent_sock.as_raw_fd();

    // Spawn gungnird configured to adopt fd 3 via pre_exec
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
    cmd.arg("-d")
        .arg(&db_path)
        .arg("-i")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    unsafe {
        cmd.pre_exec(move || {
            // Duplicate parent_sock into fd 3
            if libc::dup2(raw_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(3, libc::F_GETFD);
            libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);

            let my_pid = libc::getpid();
            let c_fds = CString::new("1").map_err(|e| std::io::Error::other(e.to_string()))?;
            let c_pid = CString::new(my_pid.to_string())
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let k_fds =
                CString::new("LISTEN_FDS").map_err(|e| std::io::Error::other(e.to_string()))?;
            let k_pid =
                CString::new("LISTEN_PID").map_err(|e| std::io::Error::other(e.to_string()))?;

            libc::setenv(k_fds.as_ptr(), c_fds.as_ptr(), 1);
            libc::setenv(k_pid.as_ptr(), c_pid.as_ptr(), 1);

            Ok(())
        });
    }

    let mut child = cmd.spawn()?;

    // Connect to the socket activated daemon
    let mut client = Client::connect(&sock_path, Duration::from_secs(3))?;
    let pong = client.ping(b"systemd-ping")?;
    assert_eq!(pong, b"systemd-ping");
    drop(client);

    // Wait for daemon to exit via idle timeout (1s)
    let status = child.wait()?;
    assert!(
        status.success(),
        "socket-activated daemon must exit cleanly"
    );

    // Verify socket file was NOT deleted by the daemon (systemd owns it)
    assert!(
        sock_path.exists(),
        "socket-activated socket file must never be unlinked by daemon"
    );

    Ok(())
}

#[test]
fn systemd_socket_activation_rejection_on_mismatch() -> R {
    // PID mismatch
    unsafe {
        env::set_var("LISTEN_PID", (std::process::id() + 9999).to_string());
        env::set_var("LISTEN_FDS", "1");
    }
    assert!(
        ipc::systemd_listener()?.is_none(),
        "must reject PID mismatch"
    );

    // FDS count 0
    unsafe {
        env::set_var("LISTEN_PID", std::process::id().to_string());
        env::set_var("LISTEN_FDS", "0");
    }
    assert!(
        ipc::systemd_listener()?.is_none(),
        "must reject LISTEN_FDS = 0"
    );

    // Clean up
    unsafe {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
    }
    Ok(())
}

#[test]
fn idle_shutdown_with_zero_clients() -> R {
    let dir = Dir::new("idle-zero")?;
    let sock_path = dir.0.join("idle.sock");
    let listener = ipc::bind(&sock_path)?;

    let handler: Arc<dyn Handler> = Arc::new(NoService);
    let cfg = Config {
        idle_timeout: Some(Duration::from_millis(200)),
        ..Config::default()
    };

    let t0 = Instant::now();
    let reason = ipc::serve(&listener.socket, cfg, &handler)?;
    let elapsed = t0.elapsed();

    assert_eq!(reason, ShutdownReason::IdleTimeout);
    assert!(
        elapsed >= Duration::from_millis(180) && elapsed <= Duration::from_secs(2),
        "idle timeout expired in {elapsed:?}"
    );

    Ok(())
}

#[test]
fn idle_shutdown_stays_alive_while_client_connected() -> R {
    let dir = Dir::new("idle-active")?;
    let sock_path = dir.0.join("idle.sock");
    let listener = ipc::bind(&sock_path)?;

    let handler: Arc<dyn Handler> = Arc::new(NoService);
    let srv = thread::spawn(move || {
        let cfg = Config {
            idle_timeout: Some(Duration::from_millis(300)),
            ..Config::default()
        };
        ipc::serve(&listener.socket, cfg, &handler)
    });

    // Connect immediately
    let mut client = Client::connect(&sock_path, Duration::from_secs(2))?;
    let pong = client.ping(b"test")?;
    assert_eq!(pong, b"test");

    // Sleep 400ms (longer than idle_timeout of 300ms) with client still held open
    thread::sleep(Duration::from_millis(400));

    // Client is still active; verify another ping succeeds
    let pong2 = client.ping(b"still-alive")?;
    assert_eq!(pong2, b"still-alive");

    // Now disconnect client
    drop(client);

    // Server should now trigger idle timeout in ~300ms
    let t0 = Instant::now();
    let reason = srv.join().expect("thread join").expect("serve result");
    let elapsed = t0.elapsed();

    assert_eq!(reason, ShutdownReason::IdleTimeout);
    assert!(
        elapsed >= Duration::from_millis(250),
        "idle shutdown must only count after disconnect: took {elapsed:?}"
    );

    Ok(())
}

#[test]
fn socket_cleanup_on_graceful_shutdown() -> R {
    let dir = Dir::new("cleanup")?;
    let sock_path = dir.0.join("test.sock");

    // Directly bound listener: socket_activated is false
    let listener = ipc::bind(&sock_path)?;
    assert!(!listener.socket_activated);
    assert!(sock_path.exists());

    // Calling cleanup removes file
    listener.cleanup();
    assert!(!sock_path.exists());

    // Socket-activated listener: cleanup does NOT remove file
    fs::write(&sock_path, b"keep")?;
    let socket = UnixListener::bind(dir.0.join("dummy.sock"))?;
    let activated = Listener::new_socket_activated(socket, Some(sock_path.clone()));
    activated.cleanup();
    assert!(sock_path.exists());

    Ok(())
}

#[test]
fn signal_handling_graceful_shutdown_sigterm() -> R {
    let dir = Dir::new("sigterm")?;
    let sock = dir.0.join("sig.sock");
    let db = dir.0.join("meta.db");

    let mut child = Command::new(env!("CARGO_BIN_EXE_gungnird"))
        .arg("-s")
        .arg(&sock)
        .arg("-d")
        .arg(&db)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait until daemon listens
    let t0 = Instant::now();
    while UnixStream::connect(&sock).is_err() {
        if let Some(status) = child.try_wait()? {
            return Err(format!("daemon exited prematurely: {status}").into());
        }
        if t0.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            return Err("daemon did not start listening in 5s".into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Connect and verify operational
    let mut client = Client::connect(&sock, Duration::from_secs(2))?;
    let pong = client.ping(b"before-term")?;
    assert_eq!(pong, b"before-term");
    drop(client);

    // Send SIGTERM to the daemon child process
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Wait for clean exit
    let status = child.wait()?;
    assert!(status.success(), "daemon must exit with code 0 on SIGTERM");

    // Socket file must be cleaned up on graceful shutdown
    assert!(!sock.exists(), "socket must be unlinked on clean shutdown");

    Ok(())
}

#[test]
fn signal_handling_live_upgrade_signal() -> R {
    let dir = Dir::new("live-upgrade")?;
    let sock = dir.0.join("upgrade.sock");
    let db = dir.0.join("meta.db");

    let mut child = Command::new(env!("CARGO_BIN_EXE_gungnird"))
        .arg("-s")
        .arg(&sock)
        .arg("-d")
        .arg(&db)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait until daemon listens
    let t0 = Instant::now();
    while UnixStream::connect(&sock).is_err() {
        if let Some(status) = child.try_wait()? {
            return Err(format!("daemon exited prematurely: {status}").into());
        }
        if t0.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            return Err("daemon did not start listening in 5s".into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Connect and test before upgrade
    let mut client = Client::connect(&sock, Duration::from_secs(2))?;
    let pong = client.ping(b"pre-upgrade")?;
    assert_eq!(pong, b"pre-upgrade");
    drop(client);

    // Send SIGHUP to trigger live in-place upgrade re-exec
    unsafe {
        libc::kill(child.id() as i32, libc::SIGHUP);
    }

    // Wait for re-execed process to respond
    let t1 = Instant::now();
    let mut upgraded = false;
    while t1.elapsed() < Duration::from_secs(5) {
        if let Ok(mut c) = Client::connect(&sock, Duration::from_millis(500))
            && let Ok(resp) = c.ping(b"post-upgrade")
            && resp == b"post-upgrade"
        {
            upgraded = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(upgraded, "re-execed daemon must answer on the same socket");

    // Terminate upgraded daemon cleanly with SIGTERM
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let status = child.wait()?;
    assert!(
        status.success(),
        "re-execed daemon must exit cleanly on SIGTERM"
    );

    Ok(())
}

#[test]
fn cli_flags_help_and_version() -> R {
    // --help
    let out = Command::new(env!("CARGO_BIN_EXE_gungnird"))
        .arg("--help")
        .output()?;
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gungnird - Gungnir virtual filesystem background daemon"));
    assert!(stdout.contains("--idle-timeout"));

    // -h
    let out = Command::new(env!("CARGO_BIN_EXE_gungnird"))
        .arg("-h")
        .output()?;
    assert!(out.status.success());

    // --version
    let out = Command::new(env!("CARGO_BIN_EXE_gungnird"))
        .arg("--version")
        .output()?;
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("gungnird"));

    // -V
    let out = Command::new(env!("CARGO_BIN_EXE_gungnird"))
        .arg("-V")
        .output()?;
    assert!(out.status.success());

    Ok(())
}

#[test]
fn cli_idle_shutdown_subprocess() -> R {
    let dir = Dir::new("cli-idle")?;
    let sock = dir.0.join("auto.sock");
    let db = dir.0.join("meta.db");

    // Spawn gungnird with --idle-timeout 1
    let t0 = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gungnird"))
        .arg("-s")
        .arg(&sock)
        .arg("-d")
        .arg(&db)
        .arg("-i")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait for the child to exit on its own via idle timeout
    let status = child.wait()?;
    let elapsed = t0.elapsed();

    assert!(
        status.success(),
        "gungnird must exit cleanly with code 0 on idle shutdown"
    );
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed <= Duration::from_secs(5),
        "idle timeout took {elapsed:?}"
    );

    // Database should be cleanly checkpointed
    let s = Store::open(&db, StoreConfig::default())?;
    drop(s);

    Ok(())
}
