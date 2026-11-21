//! What the integration tests share: their scratch directory, the daemon as a child that
//! never outlives a failed assertion, and the one way to know a started daemon serves.
//! Each test file uses what it needs (`mod common;`), so not every item is used by each.
#![allow(dead_code)]

use std::{
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};

use gungnird::md::Client;

pub type R<T = ()> = Result<T, Box<dyn Error>>;

/// A private (0700) directory under `<repo>/.build/tmp` (never /tmp, AGENTS.md §3),
/// canonical, removed on drop.
pub struct Dir(pub PathBuf);

impl Dir {
    /// A fresh directory named after `tag`, this process and a counter.
    ///
    /// # Errors
    /// The directory could not be made.
    pub fn new(tag: &str) -> R<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let base = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?
            .join(".build/tmp");
        fs::create_dir_all(&base)?;
        // The socket directory check refuses a group/world-writable parent chain.
        let mode = fs::symlink_metadata(&base)?.permissions().mode();
        if mode & 0o022 != 0 {
            fs::set_permissions(&base, fs::Permissions::from_mode(mode & 0o7755))?;
        }
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = base.join(format!("it-{tag}-{}-{n}", std::process::id()));
        fs::create_dir(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        Ok(Self(p))
    }

    #[must_use]
    pub fn join(&self, p: impl AsRef<Path>) -> PathBuf {
        self.0.join(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A child process killed and reaped on drop, so a failed assertion never leaves a daemon
/// running.
pub struct Reaped(pub Child);

impl std::ops::Deref for Reaped {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for Reaped {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// gungnird with its home, data directory and store inside `d`, the host's btrfs
/// subvolumes out of its trash, no inherited sandbox choice, stdin and stdout closed and
/// stderr to `<d>/log`. Callers add the socket,
/// options and environment of their test.
///
/// # Errors
/// The log file could not be created.
pub fn gungnird(d: &Dir) -> R<Command> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
    cmd.env("HOME", &d.0)
        .env("XDG_DATA_HOME", d.join("data"))
        // The trash service keeps to the test's own volumes (test-hooks builds; a
        // release build only notes the variable and ignores it).
        .env(gungnird::hooks::NO_HOST_SUBVOLS_ENV, "1")
        .env_remove("GUNGNIR_SECCOMP")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(d.join("log"))?);
    Ok(cmd)
}

/// Wait until the daemon `child` serves at `sock`: a connection that completes the whole
/// handshake (hello, rings), not merely a socket file, which exists from the bind, before
/// the store, the engine and the sandbox. Gives up if the child exits or `limit` passes;
/// the error then carries `log`, the child's stderr.
///
/// # Errors
/// The daemon exited, or did not serve within `limit`.
pub fn ready(child: &mut Child, sock: &Path, log: &Path, limit: Duration) -> R<Client> {
    let t0 = Instant::now();
    loop {
        if let Some(st) = child.try_wait()? {
            let log = fs::read_to_string(log).unwrap_or_default();
            return Err(format!("gungnird exited ({st}) before serving:\n{log}").into());
        }
        if sock.exists()
            && let Ok(c) = Client::connect(sock, Duration::from_secs(2))
        {
            return Ok(c);
        }
        if t0.elapsed() > limit {
            let log = fs::read_to_string(log).unwrap_or_default();
            return Err(format!("gungnird did not serve within {limit:?}:\n{log}").into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}
