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
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use gungnird::{
    ipc::{self, Config, Handler, Listener, NoService, ShutdownReason},
    md::Client,
    store::{Store, StoreConfig},
};

mod common;
use common::{Dir, R, Reaped as Reap};

#[test]
fn systemd_socket_activation_protocol() -> R {
    let dir = Dir::new("sd-act")?;
    let sock_path = dir.0.join("sd.sock");
    let db_path = dir.0.join("meta.db");

    // Parent binds the listening socket (as systemd would)
    let parent_sock = UnixListener::bind(&sock_path)?;
    let raw_fd = parent_sock.as_raw_fd();

    // Spawn gungnird configured to adopt fd 3 via pre_exec
    // As the shipped unit runs it (ExecStart has --seccomp; BC-HC-F02).
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
    cmd.arg("--seccomp")
        .arg("-d")
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
        ipc::systemd_listener(&ipc::Handoff::default())?.is_none(),
        "must reject PID mismatch"
    );

    // FDS count 0
    unsafe {
        env::set_var("LISTEN_PID", std::process::id().to_string());
        env::set_var("LISTEN_FDS", "0");
    }
    assert!(
        ipc::systemd_listener(&ipc::Handoff::default())?.is_none(),
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
        .arg("--seccomp") // as the shipped unit (BC-HC-F02)
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

/// Start gungnird (with `--seccomp` if `seccomp`) and wait until it listens; its stderr
/// goes to `log`.
fn spawn_listening(
    sock: &Path,
    db: &Path,
    log: &Path,
    seccomp: bool,
    env: &[(&str, &str)],
) -> R<Reap> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
    if seccomp {
        cmd.arg("--seccomp");
    }
    cmd.arg("-s")
        .arg(sock)
        .arg("-d")
        .arg(db)
        // A sandbox the caller did not ask for (CI, a shell) must not change the test.
        .env_remove("GUNGNIR_SECCOMP")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(log)?);
    let mut child = Reap(cmd.spawn()?);
    let t0 = Instant::now();
    while UnixStream::connect(sock).is_err() {
        if let Some(status) = child.try_wait()? {
            return Err(format!("daemon exited prematurely: {status}").into());
        }
        if t0.elapsed() > Duration::from_secs(5) {
            return Err("daemon did not start listening in 5s".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(child)
}

/// Ping `sock` until it answers `msg` or 5 s pass.
fn answers(sock: &Path, msg: &[u8]) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        if let Ok(mut c) = Client::connect(sock, Duration::from_millis(500))
            && let Ok(resp) = c.ping(msg)
            && resp == msg
        {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

/// SIGHUP re-execs the daemon in place; the new image answers on the same socket with
/// the same pid, and exits cleanly on SIGTERM.
#[test]
fn signal_handling_live_upgrade_signal() -> R {
    {
        let seccomp = false;
        let dir = Dir::new("upgrade")?;
        let sock = dir.0.join("upgrade.sock");
        let db = dir.0.join("meta.db");
        let log = dir.0.join("gungnird.log");
        let mut child = spawn_listening(&sock, &db, &log, seccomp, &[])?;

        let mut client = Client::connect(&sock, Duration::from_secs(2))?;
        assert_eq!(client.ping(b"pre-upgrade")?, b"pre-upgrade");
        drop(client);

        // SAFETY: a signal to our own child.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGHUP);
        }
        let upgraded = answers(&sock, b"post-upgrade");
        let alive = child.try_wait()?.is_none();
        let text = fs::read_to_string(&log)?;
        assert!(
            upgraded && alive,
            "seccomp {seccomp}: the re-execed daemon must answer on the same socket\n{text}"
        );
        assert!(text.contains("live upgrade: re-execing"), "{text}");

        // SAFETY: as above.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let status = child.wait()?;
        assert!(
            status.success(),
            "seccomp {seccomp}: the re-execed daemon must exit cleanly on SIGTERM"
        );
    }
    Ok(())
}

/// D-044 item 2: the filter denies execve, so under `--seccomp` (as the shipped unit
/// runs it) SIGHUP and SIGUSR1 do not re-exec: the daemon persists its state, removes
/// its socket and exits 0, for the service manager to start the new binary.
#[test]
fn live_upgrade_under_seccomp_drains_and_exits() -> R {
    for sig in [libc::SIGHUP, libc::SIGUSR1] {
        let dir = Dir::new("upgrade-seccomp")?;
        let sock = dir.0.join("upgrade.sock");
        let db = dir.0.join("meta.db");
        let log = dir.0.join("gungnird.log");
        let mut child = spawn_listening(&sock, &db, &log, true, &[])?;
        let mut client = Client::connect(&sock, Duration::from_secs(2))?;
        assert_eq!(client.ping(b"pre-upgrade")?, b"pre-upgrade");
        drop(client);
        // SAFETY: a signal to our own child.
        unsafe {
            libc::kill(child.id() as i32, sig);
        }
        let t0 = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "signal {sig}: still running\n{}",
                fs::read_to_string(&log)?
            );
            thread::sleep(Duration::from_millis(10));
        };
        let text = fs::read_to_string(&log)?;
        assert!(status.success(), "signal {sig}: {status}\n{text}");
        assert!(
            text.contains("live upgrade under seccomp: draining"),
            "{text}"
        );
        assert!(!text.contains("re-execing"), "{text}");
        assert!(!sock.exists(), "socket left behind\n{text}");
    }
    Ok(())
}

/// BC-HC-F05: a package upgrade replaces the binary by rename, so `/proc/self/exe` of the
/// running daemon reads "<path> (deleted)". SIGHUP must then exec the new binary at the
/// path the daemon was started from, and the daemon keeps answering on its socket.
#[test]
fn live_upgrade_after_the_binary_is_replaced() -> R {
    let dir = Dir::new("upgrade-replaced")?;
    let bin = dir.0.join("bin");
    fs::create_dir(&bin)?;
    let exe = bin.join("gungnird");
    fs::copy(env!("CARGO_BIN_EXE_gungnird"), &exe)?;
    let sock = dir.0.join("upgrade.sock");
    let db = dir.0.join("meta.db");
    let log = dir.0.join("gungnird.log");
    // A sibling test that forks while our copy is open for writing holds that fd until
    // it execs, and exec of the copy then fails with ETXTBSY: retry, briefly.
    let t0 = Instant::now();
    let mut child = loop {
        match Command::new(&exe)
            .env_remove("GUNGNIR_SECCOMP") // this test needs the re-exec
            .arg("-s")
            .arg(&sock)
            .arg("-d")
            .arg(&db)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log)?)
            .spawn()
        {
            Ok(c) => break Reap(c),
            Err(e)
                if e.raw_os_error() == Some(libc::ETXTBSY)
                    && t0.elapsed() < Duration::from_secs(5) =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e.into()),
        }
    };
    let up = answers(&sock, b"old");
    let pid = child.id();
    let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
    let old_ino = fs::metadata(&proc_exe).map(|m| std::os::unix::fs::MetadataExt::ino(&m));

    // What pacman/dpkg do: write the new file beside it, rename it over the old one.
    let tmp = bin.join(".gungnird.new");
    fs::copy(&exe, &tmp)?;
    fs::rename(&tmp, &exe)?;
    let replaced = fs::read_link(&proc_exe)?;

    // SAFETY: a signal to our own child.
    unsafe {
        libc::kill(pid as i32, libc::SIGHUP);
    }
    let t0 = Instant::now();
    let mut busy_retries = 0;
    let mut now = fs::read_link(&proc_exe).ok();
    while now.as_deref() != Some(exe.as_path()) && t0.elapsed() < Duration::from_secs(5) {
        if child.try_wait()?.is_some() {
            break;
        }
        // The same ETXTBSY race for the new copy (see above): the daemon logs the failed
        // exec and keeps serving (BC-HC-F02); signal it again.
        let busy = fs::read_to_string(&log)?
            .matches("live upgrade failed, still serving")
            .count();
        if busy > busy_retries && fs::read_to_string(&log)?.contains("os error 26") {
            busy_retries = busy;
            // SAFETY: as above.
            unsafe {
                libc::kill(pid as i32, libc::SIGHUP);
            }
        }
        thread::sleep(Duration::from_millis(10));
        now = fs::read_link(&proc_exe).ok();
    }
    let alive = child.try_wait()?.is_none();
    let serving = alive && answers(&sock, b"new");
    let new_ino = fs::metadata(&proc_exe).map(|m| std::os::unix::fs::MetadataExt::ino(&m));
    let text = fs::read_to_string(&log)?;
    if alive {
        // SAFETY: as above.
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    let status = child.wait()?;
    assert!(up, "the daemon did not start\n{text}");
    assert!(
        replaced.to_string_lossy().ends_with(" (deleted)"),
        "the test did not replace the binary: {replaced:?}"
    );
    assert!(
        alive && serving,
        "the daemon must survive a live upgrade after its binary is replaced\n{text}"
    );
    assert_eq!(
        now.as_deref(),
        Some(exe.as_path()),
        "it runs the new binary\n{text}"
    );
    assert_ne!(
        old_ino.ok(),
        new_ino.ok(),
        "it runs the new file, not the old one"
    );
    assert!(status.success(), "{status}\n{text}");
    Ok(())
}

/// BC-HC-F02: if the live upgrade's exec fails, the daemon logs it and keeps serving
/// on the same socket, with the same process and its database, and a later SIGTERM still
/// shuts it down cleanly. The exec is made to fail with a test hook.
///
/// Without seccomp only: under `--seccomp` an upgrade never execs (see
/// `live_upgrade_under_seccomp_drains_and_exits`).
#[cfg(feature = "test-hooks")]
#[test]
fn a_failed_live_upgrade_keeps_serving() -> R {
    use gungnird::md::{Ident, Value};
    {
        let seccomp = false;
        let dir = Dir::new("upgrade-fail")?;
        let sock = dir.0.join("upgrade.sock");
        let db = dir.0.join("meta.db");
        let log = dir.0.join("gungnird.log");
        let missing = dir.0.join("no-such-gungnird");
        let missing = missing.to_str().ok_or("path")?;
        let mut child = spawn_listening(
            &sock,
            &db,
            &log,
            seccomp,
            &[(ipc::UPGRADE_EXE_ENV, missing)],
        )?;
        let id = Ident {
            fs_uuid: "00000000-0000-0000-0000-0000000000f2".into(),
            subvol_id: 0,
            inode_num: 42,
            generation: 1,
            btime_sec: 0,
            btime_nsec: 0,
        };
        let mut c = Client::connect(&sock, Duration::from_secs(2))?;
        let mut want = Value::String("before".into());
        c.set(&id, "k", &want)?;
        drop(c);
        for (n, sig) in [libc::SIGHUP, libc::SIGUSR1].into_iter().enumerate() {
            // SAFETY: a signal to our own child.
            unsafe {
                libc::kill(child.id() as i32, sig);
            }
            let t0 = Instant::now();
            while fs::read_to_string(&log)?
                .matches("live upgrade failed, still serving")
                .count()
                <= n
            {
                assert!(
                    child.try_wait()?.is_none(),
                    "seccomp {seccomp}: the daemon died after a failed exec\n{}",
                    fs::read_to_string(&log)?
                );
                assert!(
                    t0.elapsed() < Duration::from_secs(5),
                    "no failure logged\n{}",
                    fs::read_to_string(&log)?
                );
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                answers(&sock, b"still-here"),
                "seccomp {seccomp}, signal {sig}"
            );
            let mut c = Client::connect(&sock, Duration::from_secs(2))?;
            assert_eq!(
                c.get(&id, "k")?,
                Some(want.clone()),
                "the database still serves"
            );
            want = Value::String(format!("after {sig}"));
            c.set(&id, "k", &want)?;
            drop(c);
        }
        assert!(child.try_wait()?.is_none());
        // SAFETY: as above.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let status = child.wait()?;
        assert!(status.success(), "seccomp {seccomp}: {status}");
        assert!(!sock.exists(), "socket left behind after a clean shutdown");
    }
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
        .arg("--seccomp") // as the shipped unit (BC-HC-F02)
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

/// BC-HC-F09: the idle timeout must count from the moment the last client left, not from
/// the serve loop's last 500 ms sample. A raw connection (no handshake) ends its client
/// thread at once on close, which makes the early shutdown deterministic: the client stays
/// longer than the timeout, so the old code's last sample is already past the timeout
/// when it leaves, and it shut down at once.
#[test]
fn idle_timeout_counts_from_last_disconnect() -> R {
    let dir = Dir::new("idle-last-left")?;
    let sock_path = dir.0.join("idle2.sock");
    let listener = ipc::bind(&sock_path)?;
    let handler: Arc<dyn Handler> = Arc::new(NoService);
    let srv = thread::spawn(move || {
        let cfg = Config {
            idle_timeout: Some(Duration::from_millis(300)),
            ..Config::default()
        };
        ipc::serve(&listener.socket, cfg, &handler)
    });
    let raw = UnixStream::connect(&sock_path)?;
    thread::sleep(Duration::from_millis(400));
    drop(raw);
    let t0 = Instant::now();
    let reason = srv.join().expect("thread join").expect("serve result");
    let elapsed = t0.elapsed();
    assert_eq!(reason, ShutdownReason::IdleTimeout);
    assert!(
        elapsed >= Duration::from_millis(280),
        "idle shutdown {elapsed:?} after the last client left (timeout 300 ms)"
    );
    Ok(())
}

/// F08 (BC-HC001-F02): a daemon that bound its own socket still owns it after a live
/// upgrade. The re-execed image adopts the listener through the socket-activation
/// protocol, and took it for systemd's, so it left the socket file behind on exit.
#[test]
fn an_upgraded_daemon_removes_the_socket_it_bound() -> R {
    let dir = Dir::new("upgrade-cleanup")?;
    let sock = dir.0.join("u.sock");
    let db = dir.0.join("meta.db");
    let log = dir.0.join("gungnird.log");
    let mut child = spawn_listening(&sock, &db, &log, false, &[])?;
    for round in 1..=2 {
        // SAFETY: a signal to our own child.
        unsafe { libc::kill(child.id() as i32, libc::SIGHUP) };
        let t0 = Instant::now();
        while fs::read_to_string(&log)?
            .matches("live upgrade: re-execing")
            .count()
            < round
        {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "re-exec {round} not logged"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            answers(&sock, b"after-upgrade"),
            "round {round}: not serving"
        );
    }
    // SAFETY: as above.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let status = child.wait()?;
    let text = fs::read_to_string(&log)?;
    assert!(status.success(), "{status}\n{text}");
    assert!(
        !sock.exists(),
        "the upgraded daemon left its socket behind\n{text}"
    );
    Ok(())
}

/// SIGTERM `child` and expect a clean exit within 5 s.
fn terminates(child: &mut Reap) -> R<bool> {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(false)
}

/// A FIFO under a temp ledger's name blocked the start in `open(2)` before serving and
/// before signals were handled: the daemon never answered and only SIGKILL ended it.
#[test]
fn a_fifo_in_place_of_a_temp_ledger_never_blocks_the_start() -> R {
    for name in ["ops-pending", "ops-pending.kept"] {
        let dir = Dir::new("ledger-fifo")?;
        let (sock, db, log) = (
            dir.0.join("s.sock"),
            dir.0.join("meta.db"),
            dir.0.join("log"),
        );
        let fifo = CString::new(dir.0.join(name).into_os_string().into_encoded_bytes())?;
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let mut child = spawn_listening(&sock, &db, &log, true, &[])?;
        assert!(answers(&sock, b"ledger"), "{name}: never answered");
        assert!(terminates(&mut child)?, "{name}: no clean exit on SIGTERM");
        let text = fs::read_to_string(&log)?;
        assert!(
            text.contains("temp ledger"),
            "{name}: the refusal is logged: {text}"
        );
    }
    Ok(())
}

/// A damaged database failed every start ("file is not a database"); it is now kept
/// aside and the daemon serves on an empty store.
#[test]
fn a_damaged_database_does_not_stop_the_daemon() -> R {
    let dir = Dir::new("damaged-db")?;
    let (sock, db, log) = (
        dir.0.join("s.sock"),
        dir.0.join("meta.db"),
        dir.0.join("log"),
    );
    let junk: Vec<u8> = (0..8192u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    fs::write(&db, &junk)?;
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600))?;
    let mut child = spawn_listening(&sock, &db, &log, true, &[])?;
    assert!(answers(&sock, b"damaged"), "{}", fs::read_to_string(&log)?);
    assert!(terminates(&mut child)?);
    let kept: Vec<_> = fs::read_dir(&dir.0)?
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("meta.db.corrupt-")
        })
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(fs::read(kept[0].path())?, junk);
    Ok(())
}

/// PEN-1: the daemon's own peer check (`SO_PEERCRED`) refuses another user, even where
/// the socket's mode would let them in (a socket unit with a loose `SocketMode`, adopted
/// through socket activation as systemd would hand it over). A second user is a real
/// other uid (a subordinate uid in a user namespace); the probe is a test-only binary.
#[cfg(feature = "test-hooks")]
#[test]
fn another_user_is_refused_even_through_an_open_socket() -> R {
    const TEST: &str = "another_user_is_refused_even_through_an_open_socket";
    let dir = Dir::new("peer")?;
    let shared = dir.0.join("shared");
    fs::create_dir(&shared)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777))?;
    let sock_path = shared.join("s.sock");
    let listener = UnixListener::bind(&sock_path)?;
    fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o777))?;
    let probe = shared.join("probe");
    fs::copy(env!("CARGO_BIN_EXE_gungnir-peer-probe"), &probe)?;
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o755))?;
    let raw_fd = listener.as_raw_fd();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
    cmd.arg("--seccomp")
        .arg("-d")
        .arg(dir.0.join("meta.db"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(dir.0.join("log"))?);
    // SAFETY: async-signal-safe calls only, between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(3, libc::F_GETFD);
            libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            let pid = libc::getpid().to_string();
            let c_pid = CString::new(pid).map_err(|e| std::io::Error::other(e.to_string()))?;
            libc::setenv(c"LISTEN_FDS".as_ptr(), c"1".as_ptr(), 1);
            libc::setenv(c"LISTEN_PID".as_ptr(), c_pid.as_ptr(), 1);
            Ok(())
        });
    }
    let _daemon = Reap(cmd.spawn()?);
    let log = || fs::read_to_string(dir.0.join("log")).unwrap_or_default();
    // Control: our own user gets the hello reply through the same socket.
    assert!(answers(&sock_path, b"own"), "{}", log());
    let own = Command::new(&probe).arg(&sock_path).output()?;
    assert_eq!(
        String::from_utf8_lossy(&own.stdout).trim(),
        "REPLY",
        "{}",
        log()
    );
    // Another user connects (the socket lets them) and is hung up on, no reply.
    let Some(out) = gungnird::testenv::as_other_user(
        TEST,
        &shared,
        &[
            std::ffi::OsStr::new("./probe"),
            std::ffi::OsStr::new("s.sock"),
        ],
    )?
    else {
        return Ok(());
    };
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        said.starts_with("CLOSED"),
        "another user got: {said} {}\n{}",
        String::from_utf8_lossy(&out.stderr),
        log()
    );
    // ... and the daemon goes on serving its own user.
    assert!(answers(&sock_path, b"still"), "{}", log());
    Ok(())
}
