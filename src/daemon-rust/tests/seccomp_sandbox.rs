use std::{
    io,
    process::{Command, Stdio},
};

use gungnird::seccomp::{SeccompMode, apply_sandbox, build_filter};

#[test]
fn seccomp_filter_instruction_generation() {
    let filter = build_filter(SeccompMode::Filter).expect("build filter");
    assert!(!filter.is_empty());
    // Filter must have valid length and BPF instructions
    assert!(filter.len() >= 50);
}

#[test]
fn seccomp_sandbox_child_enforces_eperm_on_disallowed_syscall() {
    // Run an isolated child process to verify seccomp enforcement
    let status = Command::new(env!("CARGO_BIN_EXE_gungnird"))
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
        .expect("execute gungnird --help");
    assert!(status.success());
}

#[test]
fn in_process_filter_verification() {
    // Verify seccomp filter directly in an isolated fork child
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: apply seccomp filter
            if let Err(e) = apply_sandbox(SeccompMode::Filter) {
                eprintln!("apply_sandbox error: {e}");
                libc::_exit(2);
            }

            // Allowed syscall: getpid
            let my_pid = libc::getpid();
            if my_pid <= 0 {
                libc::_exit(3);
            }

            // Disallowed syscall: ptrace must return -1 with EPERM
            let res = libc::syscall(libc::SYS_ptrace, 0, 0, 0, 0);
            let err = io::Error::last_os_error();
            if res != -1 || err.raw_os_error() != Some(libc::EPERM) {
                eprintln!("ptrace result: {res}, errno: {:?}", err.raw_os_error());
                libc::_exit(4);
            }

            // Clean exit from child
            libc::_exit(0);
        } else {
            // Parent: wait for child
            let mut status = 0;
            let wait_res = libc::waitpid(pid, &mut status, 0);
            assert_eq!(wait_res, pid);
            assert!(libc::WIFEXITED(status), "child did not exit cleanly");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "child exited with error status"
            );
        }
    }
}

/// Run `body` in a forked child under the filter of `mode`; the child's exit status
/// (0 = all checks held, other = which check failed; killed = a signal).
fn in_sandboxed_child(mode: SeccompMode, body: fn() -> i32) -> i32 {
    // SAFETY: the child only applies the filter, makes raw syscalls and exits.
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            if apply_sandbox(mode).is_err() {
                libc::_exit(100);
            }
            libc::_exit(body());
        }
        let mut status = 0;
        assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -libc::WTERMSIG(status)
        }
    }
}

fn errno_of(res: libc::c_long) -> Option<i32> {
    (res == -1).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// Once sandboxed, no new ring and no ring registration, in both modes (EPERM, not a
/// kill: the engine falls back to plain syscalls). D-044 item 1.
#[test]
fn sandboxed_io_uring_setup_and_register_get_eperm() {
    fn body() -> i32 {
        let mut params = [0u8; 120];
        // SAFETY: io_uring_params is 120 bytes; refused before the kernel reads it.
        let r = unsafe { libc::syscall(libc::SYS_io_uring_setup, 8, params.as_mut_ptr()) };
        if errno_of(r) != Some(libc::EPERM) {
            return 1;
        }
        // SAFETY: refused before the kernel looks at fd or arguments.
        let r = unsafe { libc::syscall(libc::SYS_io_uring_register, -1, 0, 0, 0) };
        if errno_of(r) != Some(libc::EPERM) {
            return 2;
        }
        0
    }
    for mode in [SeccompMode::Filter, SeccompMode::Strict] {
        assert_eq!(in_sandboxed_child(mode, body), 0, "{mode}");
    }
}

/// Once sandboxed, no exec, in both modes (EPERM). D-044 item 2.
#[test]
fn sandboxed_execve_and_execveat_get_eperm() {
    fn body() -> i32 {
        let path = c"/bin/true".as_ptr();
        let argv = [path, std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        // SAFETY: valid NUL-terminated path, argv and envp; on success the child would
        // become /bin/true and exit 0, which the caller would see as a pass, so check
        // the errno here and return 1 instead of falling through.
        let r = unsafe { libc::syscall(libc::SYS_execve, path, argv.as_ptr(), envp.as_ptr()) };
        if errno_of(r) != Some(libc::EPERM) {
            return 1;
        }
        // SAFETY: as above, relative to the working directory.
        let r = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                libc::AT_FDCWD,
                path,
                argv.as_ptr(),
                envp.as_ptr(),
                0,
            )
        };
        if errno_of(r) != Some(libc::EPERM) {
            return 2;
        }
        7
    }
    for mode in [SeccompMode::Filter, SeccompMode::Strict] {
        // 7, not 0: an exec that went through would exit 0 from /bin/true.
        assert_eq!(in_sandboxed_child(mode, body), 7, "{mode}");
    }
}

/// Once sandboxed, sockets are AF_UNIX only, in both modes: other families get
/// EAFNOSUPPORT, AF_UNIX still works. D-044 item 3.
#[test]
fn sandboxed_sockets_are_af_unix_only() {
    fn body() -> i32 {
        let mut sv = [0i32; 2];
        for (i, af) in [
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
            libc::AF_PACKET,
        ]
        .into_iter()
        .enumerate()
        {
            // SAFETY: plain socket creation; nothing is dereferenced.
            let r = unsafe { libc::syscall(libc::SYS_socket, af, libc::SOCK_STREAM, 0) };
            if errno_of(r) != Some(libc::EAFNOSUPPORT) {
                return 10 + i as i32;
            }
            // SAFETY: sv has room for two fds.
            let r = unsafe {
                libc::syscall(
                    libc::SYS_socketpair,
                    af,
                    libc::SOCK_STREAM,
                    0,
                    sv.as_mut_ptr(),
                )
            };
            if errno_of(r) != Some(libc::EAFNOSUPPORT) {
                return 20 + i as i32;
            }
        }
        // SAFETY: as above.
        let r = unsafe { libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if r < 0 {
            return 1;
        }
        // SAFETY: as above.
        let r = unsafe {
            libc::syscall(
                libc::SYS_socketpair,
                libc::AF_UNIX,
                libc::SOCK_STREAM,
                0,
                sv.as_mut_ptr(),
            )
        };
        if r != 0 {
            return 2;
        }
        0
    }
    for mode in [SeccompMode::Filter, SeccompMode::Strict] {
        assert_eq!(in_sandboxed_child(mode, body), 0, "{mode}");
    }
}

/// Once sandboxed, in both modes: clone with a namespace flag gets EPERM, clone3 gets
/// ENOSYS, and threads still start (glibc falls back from clone3 to clone). D-044 item 4.
#[test]
fn sandboxed_clone_refuses_namespaces_and_clone3_is_enosys() {
    fn body() -> i32 {
        for (i, f) in [
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWNS,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWCGROUP,
        ]
        .into_iter()
        .enumerate()
        {
            // SAFETY: refused before the kernel creates anything; were it allowed it
            // would fork (no CLONE_VM), and the child exits at once below.
            let r = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    (f | libc::SIGCHLD) as libc::c_ulong,
                    0,
                    0,
                    0,
                    0,
                )
            };
            if r == 0 {
                // SAFETY: the unexpected child leaves at once.
                unsafe { libc::_exit(99) };
            }
            if errno_of(r) != Some(libc::EPERM) {
                return 10 + i as i32;
            }
        }
        let mut args = [0u64; 11]; // struct clone_args, flags 0
        args[4] = libc::SIGCHLD as u64; // exit_signal
        // SAFETY: refused before the kernel reads the struct.
        let r = unsafe { libc::syscall(libc::SYS_clone3, args.as_mut_ptr(), 88) };
        if r == 0 {
            // SAFETY: as above.
            unsafe { libc::_exit(99) };
        }
        if errno_of(r) != Some(libc::ENOSYS) {
            return 2;
        }
        // A thread still starts and joins.
        if std::thread::spawn(|| 5).join().ok() != Some(5) {
            return 3;
        }
        0
    }
    for mode in [SeccompMode::Filter, SeccompMode::Strict] {
        assert_eq!(in_sandboxed_child(mode, body), 0, "{mode}");
    }
}

/// Once sandboxed, in both modes: no PROT_EXEC mapping or protection change and no
/// MFD_EXEC memfd (EPERM); plain read/write mappings and sealable memfds still work.
/// D-044 item 5.
#[test]
fn sandboxed_executable_memory_is_refused() {
    fn body() -> i32 {
        let anon = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        // SAFETY: anonymous mappings at a kernel-chosen address.
        let p = unsafe { libc::syscall(libc::SYS_mmap, 0, 4096, rw, anon, -1, 0) };
        if p == -1 {
            return 1;
        }
        for (i, prot) in [
            libc::PROT_EXEC,
            libc::PROT_READ | libc::PROT_EXEC,
            rw | libc::PROT_EXEC,
        ]
        .into_iter()
        .enumerate()
        {
            // SAFETY: as above.
            let r = unsafe { libc::syscall(libc::SYS_mmap, 0, 4096, prot, anon, -1, 0) };
            if errno_of(r) != Some(libc::EPERM) {
                return 10 + i as i32;
            }
            // SAFETY: p is our own mapping of 4096 bytes.
            let r = unsafe { libc::syscall(libc::SYS_mprotect, p, 4096, prot) };
            if errno_of(r) != Some(libc::EPERM) {
                return 20 + i as i32;
            }
        }
        // SAFETY: as above.
        if unsafe { libc::syscall(libc::SYS_mprotect, p, 4096, libc::PROT_READ) } != 0 {
            return 2;
        }
        // SAFETY: a NUL-terminated name; flags only.
        let r = unsafe { libc::syscall(libc::SYS_memfd_create, c"x".as_ptr(), 0x0010) };
        if errno_of(r) != Some(libc::EPERM) {
            return 3;
        }
        // SAFETY: as above.
        let r = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"x".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if r < 0 {
            return 4;
        }
        0
    }
    for mode in [SeccompMode::Filter, SeccompMode::Strict] {
        assert_eq!(in_sandboxed_child(mode, body), 0, "{mode}");
    }
}

/// Once sandboxed, in both modes: ioctls outside the allowlist get ENOTTY (FIOCLEX,
/// TCGETS, TIOCSTI), allowed ones still reach the kernel (FIONBIO). D-044 item 6.
#[test]
fn sandboxed_ioctls_outside_the_allowlist_get_enotty() {
    fn body() -> i32 {
        let mut sv = [0i32; 2];
        // SAFETY: sv has room for two fds.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
            return 1;
        }
        let mut on: libc::c_int = 1;
        // SAFETY: FIONBIO reads one int.
        if unsafe { libc::syscall(libc::SYS_ioctl, sv[0], libc::FIONBIO, &raw mut on) } != 0 {
            return 2;
        }
        let mut buf = [0u8; 64];
        for (i, req) in [0x5451, libc::TCGETS, libc::TIOCSTI]
            .into_iter()
            .enumerate()
        {
            // SAFETY: on our own socket, never a terminal; FIOCLEX would succeed on it
            // unsandboxed, the terminal requests fail on a socket anyway.
            let r = unsafe { libc::syscall(libc::SYS_ioctl, sv[0], req, buf.as_mut_ptr()) };
            if errno_of(r) != Some(libc::ENOTTY) {
                return 10 + i as i32;
            }
        }
        0
    }
    for mode in [SeccompMode::Filter, SeccompMode::Strict] {
        assert_eq!(in_sandboxed_child(mode, body), 0, "{mode}");
    }
}

/// Once sandboxed (filter mode): kill and tgkill only to this process, setuid and
/// setgid refused. D-044 item 7.
#[test]
fn sandboxed_signals_only_to_self_and_no_set_id() {
    fn body() -> i32 {
        // SAFETY: getpid/getppid have no preconditions.
        let (me, parent) = unsafe { (libc::getpid(), libc::getppid()) };
        // Signal 0: permission and existence check only, nothing is delivered.
        // SAFETY: as above.
        if unsafe { libc::syscall(libc::SYS_kill, me, 0) } != 0 {
            return 1;
        }
        // SAFETY: as above; this thread is the main thread, tid == pid.
        if unsafe { libc::syscall(libc::SYS_tgkill, me, me, 0) } != 0 {
            return 2;
        }
        for (i, pid) in [parent, 0, -1, -me].into_iter().enumerate() {
            // SAFETY: signal 0, and refused by the filter anyway.
            let r = unsafe { libc::syscall(libc::SYS_kill, pid, 0) };
            if errno_of(r) != Some(libc::EPERM) {
                return 10 + i as i32;
            }
        }
        // SAFETY: as above.
        let r = unsafe { libc::syscall(libc::SYS_tgkill, parent, parent, 0) };
        if errno_of(r) != Some(libc::EPERM) {
            return 3;
        }
        // SAFETY: refused before anything changes (and a no-op to our own ids anyway).
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        if errno_of(unsafe { libc::syscall(libc::SYS_setuid, uid) }) != Some(libc::EPERM) {
            return 4;
        }
        // SAFETY: as above.
        if errno_of(unsafe { libc::syscall(libc::SYS_setgid, gid) }) != Some(libc::EPERM) {
            return 5;
        }
        0
    }
    assert_eq!(in_sandboxed_child(SeccompMode::Filter, body), 0);
}

/// SEC-R-011: the filter covers every thread that exists when it is installed, not only
/// the caller: a thread started before apply_sandbox gets EPERM for ptrace afterwards.
#[test]
fn the_filter_covers_threads_started_before_it() {
    fn body() -> i32 {
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            if go_rx.recv().is_err() {
                return 1;
            }
            // SAFETY: an invalid request (-1): refused by the filter, else EIO.
            let r = unsafe { libc::syscall(libc::SYS_ptrace, -1, 0, 0, 0) };
            if errno_of(r) == Some(libc::EPERM) {
                0
            } else {
                2
            }
        });
        if apply_sandbox(SeccompMode::Filter).is_err() {
            return 3;
        }
        if go_tx.send(()).is_err() {
            return 4;
        }
        worker.join().unwrap_or(5)
    }
    // No filter before the body: it installs one after its worker thread exists.
    assert_eq!(in_unsandboxed_child(body), 0);
}

/// SEC-R-011: if a thread cannot be synchronized, apply_sandbox fails (fail closed)
/// instead of filtering only the calling thread. A thread with a filter of its own,
/// not an ancestor of the caller's, makes TSYNC fail.
#[test]
fn apply_sandbox_fails_closed_when_a_thread_cannot_be_synchronized() {
    fn body() -> i32 {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let allow = [libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            }];
            let prog = libc::sock_fprog {
                len: 1,
                filter: allow.as_ptr().cast_mut(),
            };
            // SAFETY: a valid one-instruction allow-all program, on this thread only.
            let ok = unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                    && libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_SET_MODE_FILTER,
                        0,
                        &raw const prog,
                    ) == 0
            };
            let _ = ready_tx.send(ok);
            let _ = done_rx.recv();
        });
        if ready_rx.recv() != Ok(true) {
            return 1;
        }
        let r = apply_sandbox(SeccompMode::Filter);
        let _ = done_tx.send(());
        match r {
            Err(e) if e.to_string().contains("could not be synchronized") => 0,
            Err(_) => 2,
            Ok(()) => 3,
        }
    }
    assert_eq!(in_unsandboxed_child(body), 0);
}

/// Run `body` in a forked child without applying any filter first.
fn in_unsandboxed_child(body: fn() -> i32) -> i32 {
    // SAFETY: the child runs `body` and exits.
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            libc::_exit(body());
        }
        let mut status = 0;
        assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -libc::WTERMSIG(status)
        }
    }
}

// ---- The daemon itself under the filter (BC-HC-F02) -------------------------

mod daemon {
    use std::{
        fs,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt, net::UnixStream},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use gungnird::{
        md::{Client, MSG_MD_REPLY, ST_OK, Value},
        ops::{
            self, Done, FLAG_ALL_METADATA, FLAG_NOFOLLOW_SYMLINKS, FLAG_OVERWRITE, MSG_OP_DONE,
            MSG_OP_PROGRESS, MSG_OP_START, OpKind, OpRequest,
        },
    };

    pub type R<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    /// A private (0700) directory under <repo>/.build/tmp, removed on drop.
    pub struct Dir(pub PathBuf);

    impl Dir {
        pub fn new(name: &str) -> R<Self> {
            let base =
                fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build"))?
                    .join("tmp");
            fs::create_dir_all(&base)?;
            let mode = fs::symlink_metadata(&base)?.permissions().mode();
            if mode & 0o022 != 0 {
                fs::set_permissions(&base, fs::Permissions::from_mode(mode & 0o7755))?;
            }
            let p = base.join(format!("sc-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir(&p)?;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
            Ok(Self(p))
        }

        pub fn join(&self, f: &str) -> PathBuf {
            self.0.join(f)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// gungnird with `--seccomp=<mode>`, everything inside `dir`.
    pub struct Daemon {
        pub child: Child,
        pub sock: PathBuf,
        pub log: PathBuf,
    }

    impl Daemon {
        pub fn start(dir: &Dir, mode: &str, no_uring: bool) -> R<Self> {
            let sock = dir.join("gungnird.sock");
            let log = dir.join(&format!("gungnird-{mode}-{no_uring}.log"));
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
            cmd.arg(format!("--seccomp={mode}"))
                .arg("-s")
                .arg(&sock)
                .arg("-d")
                .arg(dir.join("data/metadata.db"))
                .env("HOME", &dir.0)
                .env("XDG_DATA_HOME", dir.join("data"))
                .env("XDG_RUNTIME_DIR", &dir.0)
                .env_remove(ops::NO_URING_ENV)
                .env_remove("GUNGNIR_SECCOMP")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(fs::File::create(&log)?);
            if no_uring {
                cmd.env(ops::NO_URING_ENV, "1");
            }
            let child = cmd.spawn()?;
            let mut d = Self { child, sock, log };
            let t0 = Instant::now();
            while UnixStream::connect(&d.sock).is_err() {
                if let Some(st) = d.child.try_wait()? {
                    return Err(format!("gungnird exited early: {st}\n{}", d.log_text()).into());
                }
                if t0.elapsed() > Duration::from_secs(10) {
                    return Err("gungnird did not start listening".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Ok(d)
        }

        pub fn client(&self) -> R<Client> {
            Ok(Client::connect(&self.sock, Duration::from_secs(5))?)
        }

        pub fn log_text(&self) -> String {
            fs::read_to_string(&self.log).unwrap_or_default()
        }

        /// Still running (a denied syscall in strict mode kills the whole process).
        pub fn alive(&mut self) -> R<bool> {
            Ok(self.child.try_wait()?.is_none())
        }
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn b(p: &Path) -> Vec<u8> {
        p.as_os_str().as_bytes().to_vec()
    }

    /// Run one op to its done event.
    pub fn run(
        c: &mut Client,
        kind: OpKind,
        flags: u32,
        src: &Path,
        dest: Option<&Path>,
    ) -> R<Done> {
        let r = OpRequest {
            kind,
            flags,
            timeout_ms: 0,
            src: b(src),
            dest: dest.map(b).unwrap_or_default(),
        };
        let seq = c.send(MSG_OP_START, &r.encode())?;
        let t0 = Instant::now();
        let mut id = None;
        loop {
            let left = Duration::from_secs(30)
                .checked_sub(t0.elapsed())
                .ok_or("no done event in time")?;
            let m = c.recv(left)?;
            match m.kind {
                MSG_MD_REPLY if m.seq == seq => {
                    let p = m.payload();
                    let st = u32::from_le_bytes(p[..4].try_into()?);
                    if st != ST_OK {
                        return Err(format!("{kind:?} refused with status {st}").into());
                    }
                    id = Some(u64::from_le_bytes(p[4..12].try_into()?));
                }
                MSG_OP_PROGRESS => {}
                MSG_OP_DONE => {
                    let d = ops::parse_done(m.payload()).ok_or("bad done")?;
                    if Some(d.id) == id {
                        return Ok(d);
                    }
                }
                k => return Err(format!("unexpected message kind {k}").into()),
            }
        }
    }

    /// Metadata and every M8 op kind through a sandboxed daemon, on real files.
    pub fn file_ops(dir: &Dir, mode: &str, no_uring: bool) -> R {
        let mut d = Daemon::start(dir, mode, no_uring)?;
        let mut c = d.client()?;
        let what = format!("--seccomp={mode}, no_uring={no_uring}");
        let tag = Value::String(what.clone());

        let src = dir.join("src");
        let data: Vec<u8> = (0..(3usize << 20)).map(|i| (i * 31 % 251) as u8).collect();
        fs::write(&src, &data)?;
        let sid = c.identify(&src)?;
        c.set(&sid, "tag", &tag)?;
        assert_eq!(c.get(&sid, "tag")?, Some(tag.clone()), "{what}");

        let copy = dir.join("copy");
        let done = run(&mut c, OpKind::Copy, FLAG_ALL_METADATA, &src, Some(&copy))?;
        assert_eq!(done.result, Ok(()), "copy, {what}\n{}", d.log_text());
        assert_eq!(fs::read(&copy)?, data, "{what}");
        let id = c.identify(&copy)?;
        assert_eq!(c.get(&id, "tag")?, Some(tag.clone()), "{what}");

        fs::create_dir(dir.join("sub"))?;
        let moved = dir.join("sub/moved");
        let done = run(&mut c, OpKind::Move, 0, &copy, Some(&moved))?;
        assert_eq!(done.result, Ok(()), "move, {what}\n{}", d.log_text());
        assert!(!copy.exists() && moved.exists(), "{what}");
        let id = c.identify(&moved)?;
        assert_eq!(c.get(&id, "tag")?, Some(tag.clone()), "{what}");

        let done = run(&mut c, OpKind::Fsync, 0, &moved, None)?;
        assert_eq!(done.result, Ok(()), "fsync, {what}\n{}", d.log_text());
        let done = run(&mut c, OpKind::Delete, 0, &moved, None)?;
        assert_eq!(done.result, Ok(()), "delete, {what}\n{}", d.log_text());
        assert!(!moved.exists(), "{what}");

        for i in 0..12 {
            fs::create_dir_all(dir.join(&format!("tree/d{}", i % 3)))?;
            fs::write(dir.join(&format!("tree/d{}/f{i}", i % 3)), b"x")?;
        }
        let done = run(&mut c, OpKind::DeleteTree, 0, &dir.join("tree"), None)?;
        assert_eq!(done.result, Ok(()), "delete-tree, {what}\n{}", d.log_text());
        assert!(!dir.join("tree").exists(), "{what}");

        // Symlinks (AUD-02): copying one recreates it with symlinkat, also over an
        // existing file; then move and delete one.
        let link = dir.join("link");
        std::os::unix::fs::symlink("src", &link)?;
        let lcopy = dir.join("link-copy");
        let done = run(
            &mut c,
            OpKind::Copy,
            FLAG_NOFOLLOW_SYMLINKS | FLAG_ALL_METADATA,
            &link,
            Some(&lcopy),
        )?;
        assert_eq!(
            done.result,
            Ok(()),
            "symlink copy, {what}\n{}",
            d.log_text()
        );
        assert_eq!(fs::read_link(&lcopy)?, Path::new("src"), "{what}");
        let over = dir.join("over");
        fs::write(&over, b"old")?;
        let done = run(
            &mut c,
            OpKind::Copy,
            FLAG_NOFOLLOW_SYMLINKS | FLAG_OVERWRITE,
            &link,
            Some(&over),
        )?;
        assert_eq!(
            done.result,
            Ok(()),
            "symlink copy over a file, {what}\n{}",
            d.log_text()
        );
        assert_eq!(fs::read_link(&over)?, Path::new("src"), "{what}");
        let lmoved = dir.join("sub/link-moved");
        let done = run(
            &mut c,
            OpKind::Move,
            FLAG_NOFOLLOW_SYMLINKS,
            &lcopy,
            Some(&lmoved),
        )?;
        assert_eq!(
            done.result,
            Ok(()),
            "symlink move, {what}\n{}",
            d.log_text()
        );
        assert_eq!(fs::read_link(&lmoved)?, Path::new("src"), "{what}");
        let done = run(&mut c, OpKind::Delete, 0, &lmoved, None)?;
        assert_eq!(
            done.result,
            Ok(()),
            "symlink delete, {what}\n{}",
            d.log_text()
        );
        assert!(
            fs::symlink_metadata(&lmoved).is_err() && src.exists(),
            "{what}"
        );

        // With io_uring usable here, the sandboxed daemon really ran its ops on
        // restricted rings, and pre-created the rings for later workers (D-044 item 1).
        if !no_uring && ops::io::uring_for_tests_env("sandboxed uring engine check") {
            let log = d.log_text();
            assert!(log.contains("file ops engine: Uring"), "{what}\n{log}");
            assert!(!log.contains("failed ("), "{what}\n{log}");
            // Every first worker took a restricted ring before the filter went in, none
            // fell back to syscalls (BC-A2-F01).
            let counted = log
                .lines()
                .find_map(|l| {
                    let l = l.strip_suffix(" file op workers on restricted io_uring rings")?;
                    let (on, of) = l.strip_prefix("gungnird: ")?.split_once(" of ")?;
                    Some((on.parse::<usize>().ok()?, of.parse::<usize>().ok()?))
                })
                .ok_or_else(|| format!("{what}: no worker count in the log\n{log}"))?;
            assert!(
                counted.0 == counted.1 && counted.0 >= 1,
                "{what}: workers on restricted rings {counted:?}\n{log}"
            );
        }
        drop(c);
        assert!(d.alive()?, "{what}: the daemon died\n{}", d.log_text());
        Ok(())
    }
}

/// BC-HC-F02, AUD-02: the daemon as the shipped unit runs it (`--seccomp`, filter mode) and in
/// strict mode (any denied syscall kills it) serves metadata and every M8 op kind on
/// real files, symlinks included, on both engines.
#[test]
fn the_sandboxed_daemon_serves_metadata_and_file_ops() -> daemon::R {
    for mode in ["filter", "strict"] {
        for no_uring in [false, true] {
            let dir = daemon::Dir::new(&format!("ops-{mode}-{no_uring}"))?;
            daemon::file_ops(&dir, mode, no_uring)?;
        }
    }
    Ok(())
}
