//! MGR-GAP-F3: the shipped unit's syscall filter, applied as systemd applies it, lets the
//! daemon's no-replace move fallback (`linkat`, then `unlink`) do its work.
//!
//! No systemd here: the test reads `SystemCallFilter=`, `SystemCallArchitectures=` and
//! `RestrictAddressFamilies=` from `init/systemd/gungnird.service`, compiles them into a
//! seccomp filter the way systemd does (allow list plus the implicit `@default` set, a
//! denied call kills the process unless `SystemCallErrorNumber=` says otherwise), and
//! starts gungnird under it with the unit's `--seccomp`, `NoNewPrivileges=`, `UMask=` and
//! `LimitCORE=`. A second test-only filter stands in for a filesystem without
//! `RENAME_NOREPLACE`: `renameat2` with that flag gets `EINVAL`, which is what sends a
//! move to the fallback. The thread engine runs the ops, so that rename is a syscall
//! the filter sees (an io_uring rename would not be).
//! Not modelled: the unit's filesystem directives (f04-unit-hardening.sh covers those),
//! RestrictNamespaces=, LockPersonality=, RestrictRealtime=.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use gungnird::{
    md::{Client, MSG_MD_REPLY, ST_OK, Value},
    ops::{self, Done, MSG_OP_DONE, MSG_OP_PROGRESS, MSG_OP_START, OpKind, OpRequest},
};

type R<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// ---- The unit ----------------------------------------------------------------

fn unit_text() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../init/systemd/gungnird.service");
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Every value of `key=` in the [Service] section, in order.
fn values(unit: &str, key: &str) -> Vec<String> {
    let mut service = false;
    let mut out = Vec::new();
    for l in unit.lines().map(str::trim) {
        if l.starts_with('[') {
            service = l == "[Service]";
        } else if service && let Some(v) = l.strip_prefix(key).and_then(|v| v.strip_prefix('=')) {
            out.push(v.trim().to_owned());
        }
    }
    out
}

/// The unit's allow list by name (an empty assignment resets it, as in systemd).
fn unit_allow_list(unit: &str) -> Vec<String> {
    let mut names = Vec::new();
    for v in values(unit, "SystemCallFilter") {
        assert!(
            !v.starts_with('~'),
            "deny-list SystemCallFilter= is not modelled: {v}"
        );
        if v.is_empty() {
            names.clear();
        }
        for n in v.split_whitespace() {
            let n = n.split(':').next().unwrap_or(n);
            assert!(!n.starts_with('@'), "syscall groups are not modelled: {n}");
            names.push(n.to_owned());
        }
    }
    names
}

/// systemd adds `@default` (which includes `@sandbox`) to every allow list; its x86-64
/// members, as `systemd-analyze syscall-filter @default` lists them.
const SYSTEMD_DEFAULT: &[&str] = &[
    "arch_prctl",
    "brk",
    "clock_getres",
    "clock_gettime",
    "clock_nanosleep",
    "execve",
    "exit",
    "exit_group",
    "futex",
    "futex_waitv",
    "get_robust_list",
    "get_thread_area",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getrandom",
    "getresgid",
    "getresuid",
    "getrlimit",
    "getsid",
    "gettid",
    "gettimeofday",
    "getuid",
    "membarrier",
    "mmap",
    "mprotect",
    "mseal",
    "munmap",
    "nanosleep",
    "pause",
    "prlimit64",
    "restart_syscall",
    "rseq",
    "rt_sigreturn",
    "sched_getaffinity",
    "sched_yield",
    "set_robust_list",
    "set_thread_area",
    "set_tid_address",
    "time",
    "landlock_add_rule",
    "landlock_create_ruleset",
    "landlock_restrict_self",
    "seccomp",
];

/// x86-64 syscall numbers by name (`SYS_<name>`); a name the unit gains must be added here.
macro_rules! syscalls {
    ($($s:ident),* $(,)?) => {
        &[$((stringify!($s), libc::$s)),*]
    };
}
const SYSCALLS: &[(&str, libc::c_long)] = syscalls![
    SYS_accept,
    SYS_accept4,
    SYS_access,
    SYS_arch_prctl,
    SYS_bind,
    SYS_brk,
    SYS_chmod,
    SYS_chown,
    SYS_clock_getres,
    SYS_clock_gettime,
    SYS_clock_nanosleep,
    SYS_clone,
    SYS_clone3,
    SYS_close,
    SYS_close_range,
    SYS_connect,
    SYS_copy_file_range,
    SYS_dup,
    SYS_dup2,
    SYS_dup3,
    SYS_epoll_create,
    SYS_epoll_create1,
    SYS_epoll_ctl,
    SYS_epoll_pwait,
    SYS_epoll_wait,
    SYS_eventfd,
    SYS_eventfd2,
    SYS_execve,
    SYS_execveat,
    SYS_exit,
    SYS_exit_group,
    SYS_faccessat,
    SYS_faccessat2,
    SYS_fadvise64,
    SYS_fallocate,
    SYS_fchmod,
    SYS_fchmodat,
    SYS_fchown,
    SYS_fchownat,
    SYS_fcntl,
    SYS_fdatasync,
    SYS_fgetxattr,
    SYS_flistxattr,
    SYS_flock,
    SYS_fork,
    SYS_fremovexattr,
    SYS_fsetxattr,
    SYS_fstat,
    SYS_fstatfs,
    SYS_fsync,
    SYS_ftruncate,
    SYS_futex,
    SYS_futex_waitv,
    SYS_get_robust_list,
    SYS_get_thread_area,
    SYS_getcwd,
    SYS_getdents,
    SYS_getdents64,
    SYS_getegid,
    SYS_geteuid,
    SYS_getgid,
    SYS_getgroups,
    SYS_getitimer,
    SYS_getpeername,
    SYS_getpgid,
    SYS_getpgrp,
    SYS_getpid,
    SYS_getppid,
    SYS_getrandom,
    SYS_getresgid,
    SYS_getresuid,
    SYS_getrlimit,
    SYS_getrusage,
    SYS_getsid,
    SYS_getsockname,
    SYS_getsockopt,
    SYS_gettid,
    SYS_gettimeofday,
    SYS_getuid,
    SYS_getxattr,
    SYS_io_uring_enter,
    SYS_io_uring_register,
    SYS_io_uring_setup,
    SYS_ioctl,
    SYS_kill,
    SYS_landlock_add_rule,
    SYS_landlock_create_ruleset,
    SYS_landlock_restrict_self,
    SYS_lgetxattr,
    SYS_linkat,
    SYS_listen,
    SYS_listxattr,
    SYS_llistxattr,
    SYS_lremovexattr,
    SYS_lseek,
    SYS_lsetxattr,
    SYS_lstat,
    SYS_madvise,
    SYS_membarrier,
    SYS_memfd_create,
    SYS_mincore,
    SYS_mkdir,
    SYS_mkdirat,
    SYS_mmap,
    SYS_mprotect,
    SYS_mremap,
    SYS_mseal,
    SYS_msync,
    SYS_munmap,
    SYS_nanosleep,
    SYS_newfstatat,
    SYS_open,
    SYS_openat,
    SYS_openat2,
    SYS_pause,
    SYS_pipe,
    SYS_pipe2,
    SYS_poll,
    SYS_ppoll,
    SYS_prctl,
    SYS_pread64,
    SYS_preadv,
    SYS_preadv2,
    SYS_prlimit64,
    SYS_pselect6,
    SYS_pwrite64,
    SYS_pwritev,
    SYS_pwritev2,
    SYS_read,
    SYS_readlink,
    SYS_readlinkat,
    SYS_readv,
    SYS_recvfrom,
    SYS_recvmmsg,
    SYS_recvmsg,
    SYS_removexattr,
    SYS_rename,
    SYS_renameat,
    SYS_renameat2,
    SYS_restart_syscall,
    SYS_rmdir,
    SYS_rseq,
    SYS_rt_sigaction,
    SYS_rt_sigprocmask,
    SYS_rt_sigreturn,
    SYS_sched_getaffinity,
    SYS_sched_setaffinity,
    SYS_sched_yield,
    SYS_seccomp,
    SYS_select,
    SYS_sendmmsg,
    SYS_sendmsg,
    SYS_sendto,
    SYS_set_robust_list,
    SYS_set_thread_area,
    SYS_set_tid_address,
    SYS_setitimer,
    SYS_setrlimit,
    SYS_setsockopt,
    SYS_setxattr,
    SYS_shutdown,
    SYS_sigaltstack,
    SYS_signalfd,
    SYS_signalfd4,
    SYS_socket,
    SYS_socketpair,
    SYS_splice,
    SYS_stat,
    SYS_statfs,
    SYS_statx,
    SYS_symlinkat,
    SYS_sync_file_range,
    SYS_syncfs,
    SYS_sysinfo,
    SYS_tee,
    SYS_tgkill,
    SYS_time,
    SYS_times,
    SYS_umask,
    SYS_unlink,
    SYS_unlinkat,
    SYS_utimensat,
    SYS_utimes,
    SYS_vfork,
    SYS_wait4,
    SYS_write,
    SYS_writev,
];

fn nr(name: &str) -> u32 {
    let n = SYSCALLS
        .iter()
        .find(|(s, _)| s.strip_prefix("SYS_") == Some(name))
        .unwrap_or_else(|| panic!("syscall {name:?} is not in this test's table"));
    u32::try_from(n.1).expect("syscall number")
}

// ---- The filters ---------------------------------------------------------------

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;
const NR: u32 = 0;
const ARCH: u32 = 4;
const fn arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn errno(e: i32) -> u32 {
    libc::SECCOMP_RET_ERRNO | u32::try_from(e).expect("errno")
}

/// What a call the unit does not allow gets: a kill, unless `SystemCallErrorNumber=`.
fn unit_denied_action(unit: &str) -> u32 {
    match values(unit, "SystemCallErrorNumber")
        .last()
        .map(String::as_str)
    {
        None | Some("" | "kill") => libc::SECCOMP_RET_KILL_PROCESS,
        Some("EPERM") => errno(libc::EPERM),
        Some("EACCES") => errno(libc::EACCES),
        Some("ENOSYS") => errno(libc::ENOSYS),
        Some(v) => panic!("SystemCallErrorNumber={v} is not modelled"),
    }
}

/// The unit's filter as systemd builds it, less `drop` (a previous allow list).
fn unit_filter(unit: &str, drop: &[&str]) -> Vec<libc::sock_filter> {
    assert_eq!(
        values(unit, "SystemCallArchitectures")
            .last()
            .map(String::as_str),
        Some("native")
    );
    assert_eq!(
        values(unit, "RestrictAddressFamilies")
            .last()
            .map(String::as_str),
        Some("AF_UNIX")
    );
    let mut allow: Vec<String> = unit_allow_list(unit);
    allow.extend(SYSTEMD_DEFAULT.iter().map(|s| (*s).to_owned()));
    allow.retain(|n| !drop.contains(&n.as_str()));
    let mut nrs: Vec<u32> = allow.iter().map(|n| nr(n)).collect();
    nrs.sort_unstable();
    nrs.dedup();
    let socket = nr("socket");
    assert!(nrs.contains(&socket), "the unit allows socket()");
    let kill = libc::SECCOMP_RET_KILL_PROCESS;
    let mut f = vec![
        // SystemCallArchitectures=native: other ABIs, x32 included, are not let through.
        stmt(BPF_LD_W_ABS, ARCH),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET_K, kill),
        stmt(BPF_LD_W_ABS, NR),
        jump(BPF_JGE_K, X32_SYSCALL_BIT, 0, 1),
        stmt(BPF_RET_K, kill),
        // RestrictAddressFamilies=AF_UNIX
        jump(BPF_JEQ_K, socket, 0, 4),
        stmt(BPF_LD_W_ABS, arg_lo(0)),
        jump(BPF_JEQ_K, libc::AF_UNIX as u32, 0, 1),
        stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW),
        stmt(BPF_RET_K, errno(libc::EAFNOSUPPORT)),
    ];
    for n in nrs {
        f.push(jump(BPF_JEQ_K, n, 0, 1));
        f.push(stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
    }
    f.push(stmt(BPF_RET_K, unit_denied_action(unit)));
    f
}

/// Test only: a filesystem without `RENAME_NOREPLACE` answers `renameat2` with that
/// flag `EINVAL`; everything else is left to the other filters.
fn no_noreplace_filesystem() -> Vec<libc::sock_filter> {
    vec![
        stmt(BPF_LD_W_ABS, NR),
        jump(BPF_JEQ_K, nr("renameat2"), 0, 3),
        stmt(BPF_LD_W_ABS, arg_lo(4)),
        jump(BPF_JSET_K, libc::RENAME_NOREPLACE, 0, 1),
        stmt(BPF_RET_K, errno(libc::EINVAL)),
        stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW),
    ]
}

// ---- The daemon as the unit starts it ------------------------------------------

/// A private (0700) directory under <repo>/.build/tmp, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> R<Self> {
        let base = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build"))?
            .join("tmp");
        fs::create_dir_all(&base)?;
        let p = base.join(format!("unit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(p.join("files"))?;
        Ok(Self(p))
    }

    fn join(&self, f: &str) -> PathBuf {
        self.0.join(f)
    }

    fn file(&self, f: &str) -> PathBuf {
        self.0.join("files").join(f)
    }

    /// No temporary file of an op was left behind.
    fn no_temp_files(&self) -> R<bool> {
        for e in fs::read_dir(self.join("files"))? {
            let n = e?.file_name();
            let n = n.to_string_lossy();
            if n.starts_with(".gungnir-") && n.ends_with(".tmp") {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Daemon {
    child: Child,
    sock: PathBuf,
    log: PathBuf,
}

impl Daemon {
    /// gungnird with the unit's ExecStart arguments, under `filters` (the first one is
    /// the unit's), on the thread engine.
    fn start(dir: &Dir, unit: &str, tag: &str, filters: Vec<Vec<libc::sock_filter>>) -> R<Self> {
        let exec = values(unit, "ExecStart").pop().ok_or("no ExecStart=")?;
        let mut words = exec.split_whitespace();
        assert_eq!(words.next(), Some("/usr/bin/gungnird"));
        assert_eq!(
            values(unit, "NoNewPrivileges").last().map(String::as_str),
            Some("yes")
        );
        let umask = values(unit, "UMask").pop().ok_or("no UMask=")?;
        let umask = libc::mode_t::from_str_radix(&umask, 8)?;
        assert_eq!(
            values(unit, "LimitCORE").last().map(String::as_str),
            Some("0")
        );

        let sock = dir.join("gungnird.sock");
        let _ = fs::remove_file(&sock);
        let log = dir.join(&format!("gungnird-{tag}.log"));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_gungnird"));
        cmd.args(words)
            .arg("-s")
            .arg(&sock)
            .arg("-d")
            .arg(dir.join("data/metadata.db"))
            .env("HOME", &dir.0)
            .env("XDG_DATA_HOME", dir.join("data"))
            .env("XDG_RUNTIME_DIR", &dir.0)
            .env(ops::NO_URING_ENV, "1")
            .env_remove("GUNGNIR_SECCOMP")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log)?);
        // SAFETY: between fork and exec the child only makes raw syscalls on memory that
        // was set up before the fork (the filters live in `cmd`'s closure).
        unsafe {
            cmd.pre_exec(move || {
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::umask(umask);
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                for f in &filters {
                    let prog = libc::sock_fprog {
                        len: u16::try_from(f.len()).unwrap_or(u16::MAX),
                        filter: f.as_ptr().cast_mut(),
                    };
                    let r = libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_SET_MODE_FILTER,
                        0,
                        &prog as *const libc::sock_fprog,
                    );
                    if r != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
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

    fn client(&self) -> R<Client> {
        Ok(Client::connect(&self.sock, Duration::from_secs(5))?)
    }

    fn log_text(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The signal that ended the daemon, waiting up to 10 s for it to end.
    fn killed_by(&mut self) -> R<Option<i32>> {
        let t0 = Instant::now();
        loop {
            if let Some(st) = self.child.try_wait()? {
                return Ok(st.signal());
            }
            if t0.elapsed() > Duration::from_secs(10) {
                return Err("the daemon is still running".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn alive(&mut self) -> R<bool> {
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
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}

/// One move (no flags: no-replace, fallback allowed) to its done event.
fn move_op(c: &mut Client, src: &Path, dest: &Path) -> R<Done> {
    let r = OpRequest {
        kind: OpKind::Move,
        flags: 0,
        timeout_ms: 0,
        src: b(src),
        dest: b(dest),
        src_at: None,
        dest_at: None,
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
                    return Err(format!("move refused with status {st}").into());
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

fn os_error(d: &Done) -> Option<i32> {
    match d.result {
        Err(ops::OpError::Os(e)) => Some(e),
        _ => None,
    }
}

// ---- The tests -----------------------------------------------------------------

/// The fallback calls `linkat` and the unit has to allow it (EPERM otherwise).
#[test]
fn the_unit_allows_every_call_of_the_no_replace_fallback() {
    let unit = unit_text();
    let allow = unit_allow_list(&unit);
    for call in ["renameat2", "statx", "linkat", "unlinkat"] {
        assert!(
            allow.iter().any(|n| n == call),
            "SystemCallFilter= lacks {call}"
        );
    }
    assert!(
        !SYSTEMD_DEFAULT.contains(&"linkat"),
        "linkat comes only from the unit's list"
    );
}

/// RC-HC4-F01 / C-21.13 (D-043, D-073): the kernel and namespace protections are all set,
/// and the rest of the static C-21 policy is as ruled. Static only: whether systemd
/// enforces them is the live C-21.17/C-21.18 check.
#[test]
fn the_unit_keeps_the_c21_static_policy() {
    let unit = unit_text();
    let last = |k: &str| values(&unit, k).pop();
    let is = |k: &str, v: &str| assert_eq!(last(k).as_deref(), Some(v), "{k}=");
    let absent_or = |k: &str, v: &str| {
        let got = last(k);
        assert!(got.is_none() || got.as_deref() == Some(v), "{k}={got:?}");
    };
    // C-21.13
    for k in [
        "RestrictNamespaces",
        "RestrictRealtime",
        "RestrictSUIDSGID",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectControlGroups",
        "ProtectClock",
        "ProtectHostname",
    ] {
        is(k, "yes");
    }
    // C-21.3 to C-21.12, C-21.14 to C-21.16: the file manager keeps its reach (D-043).
    is("RestrictAddressFamilies", "AF_UNIX");
    absent_or("ProtectHome", "no");
    absent_or("PrivateTmp", "no");
    is("ProtectSystem", "full");
    for k in [
        "ReadWritePaths",
        "ReadOnlyPaths",
        "InaccessiblePaths",
        "TemporaryFileSystem",
        "BindPaths",
        "IPAddressDeny",
    ] {
        assert!(values(&unit, k).is_empty(), "{k}= is set");
    }
    is("NoNewPrivileges", "yes");
    is("UMask", "0077");
    absent_or("PrivateDevices", "no");
    absent_or("MemoryDenyWriteExecute", "no");
    is("SystemCallArchitectures", "native");
    is("LockPersonality", "yes");
    is("SystemCallErrorNumber", "EPERM");
    is("LimitCORE", "0");
    is("Type", "exec");
    is(
        "ExecStart",
        "/usr/bin/gungnird --idle-timeout 300 --seccomp",
    );
    is("Restart", "on-failure");
    // C-21.1/C-21.2: by name, no groups, and the D-073 names (plus linkat, MGR-GAP-F3).
    let allow = unit_allow_list(&unit);
    for call in [
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "clone3",
        "symlinkat",
        "newfstatat",
        "memfd_create",
        "prctl",
        "seccomp",
        "bind",
        "listen",
        "connect",
        "rseq",
        "statfs",
        "flock",
        "eventfd2",
        "signalfd4",
        "accept4",
        "getsockopt",
        "setsockopt",
        "linkat",
    ] {
        assert!(
            allow.iter().any(|n| n == call),
            "SystemCallFilter= lacks {call}"
        );
    }
}

/// MGR-GAP-F3: under the unit's filter, a no-replace move on a filesystem without
/// `RENAME_NOREPLACE` goes through `linkat` and works: same file at the destination, the
/// source name gone, metadata moved, no temporary file; an existing destination is still
/// never replaced. With the allow list as it was before linkat was added (the only
/// difference), the same move fails with the unit's EPERM and the file stays where it was.
#[test]
fn the_unit_filter_lets_the_no_replace_fallback_link_and_unlink() -> R {
    let unit = unit_text();
    let dir = Dir::new("noreplace")?;
    let (src, dest) = (dir.file("src"), dir.file("dest"));
    let data: Vec<u8> = (0..(1usize << 16)).map(|i| (i * 31 % 251) as u8).collect();
    fs::write(&src, &data)?;
    let ino = fs::symlink_metadata(&src)?.ino();
    let tag = Value::String("MGR-GAP-F3".into());

    // 1. The previous allow list, without the injected EINVAL: renameat2 with
    // RENAME_NOREPLACE works on this filesystem and the move never reaches linkat.
    {
        let mut d = Daemon::start(
            &dir,
            &unit,
            "old-native",
            vec![unit_filter(&unit, &["linkat"])],
        )?;
        let mut c = d.client()?;
        let sid = c.identify(&src)?;
        c.set(&sid, "tag", &tag)?;
        let (a, b2) = (dir.file("native-a"), dir.file("native-b"));
        fs::write(&a, b"native")?;
        let done = move_op(&mut c, &a, &b2)?;
        assert_eq!(
            done.result,
            Ok(()),
            "native no-replace rename\n{}",
            d.log_text()
        );
        assert!(!a.exists() && fs::read(&b2)? == b"native");
        drop(c);
        assert!(d.alive()?, "{}", d.log_text());
    }

    // 2. The previous allow list on a filesystem without RENAME_NOREPLACE: the fallback's
    // linkat is refused (SystemCallErrorNumber=EPERM, which the move reports as
    // EOPNOTSUPP; a kill without it) and nothing moves.
    {
        let filters = vec![unit_filter(&unit, &["linkat"]), no_noreplace_filesystem()];
        let mut d = Daemon::start(&dir, &unit, "old-fallback", filters)?;
        let mut c = d.client()?;
        let r = move_op(&mut c, &src, &dest);
        if unit_denied_action(&unit) == libc::SECCOMP_RET_KILL_PROCESS {
            assert!(r.is_err(), "the move finished: {r:?}\n{}", d.log_text());
            assert_eq!(d.killed_by()?, Some(libc::SIGSYS), "{}", d.log_text());
        } else {
            let done = r?;
            assert_eq!(os_error(&done), Some(libc::EOPNOTSUPP), "{:?}", done.result);
            drop(c);
            assert!(d.alive()?, "{}", d.log_text());
        }
        assert_eq!(fs::read(&src)?, data);
        assert!(fs::symlink_metadata(&dest).is_err());
        assert!(dir.no_temp_files()?);
    }

    // 3. The unit as shipped, same filesystem: the fallback links and unlinks.
    {
        let filters = vec![unit_filter(&unit, &[]), no_noreplace_filesystem()];
        let mut d = Daemon::start(&dir, &unit, "fallback", filters)?;
        let mut c = d.client()?;
        // The refused move left the store as it was: the tag is still on the source.
        let sid = c.identify(&src)?;
        assert_eq!(c.get(&sid, "tag")?, Some(tag.clone()), "{}", d.log_text());
        let done = move_op(&mut c, &src, &dest)?;
        assert_eq!(done.result, Ok(()), "fallback move\n{}", d.log_text());
        assert!(
            fs::symlink_metadata(&src).is_err(),
            "the source name is gone"
        );
        assert_eq!(fs::read(&dest)?, data);
        assert_eq!(
            fs::symlink_metadata(&dest)?.ino(),
            ino,
            "the same file, not a copy"
        );
        assert_eq!(fs::symlink_metadata(&dest)?.nlink(), 1, "one name left");
        let did = c.identify(&dest)?;
        assert_eq!(
            c.get(&did, "tag")?,
            Some(tag.clone()),
            "metadata moved with the file"
        );
        assert!(dir.no_temp_files()?);

        // No-replace still holds through linkat's EEXIST.
        let (x, y) = (dir.file("x"), dir.file("y"));
        fs::write(&x, b"new")?;
        fs::write(&y, b"precious")?;
        let done = move_op(&mut c, &x, &y)?;
        assert_eq!(os_error(&done), Some(libc::EEXIST), "{:?}", done.result);
        assert_eq!(fs::read(&y)?, b"precious");
        assert_eq!(fs::read(&x)?, b"new");
        assert!(dir.no_temp_files()?);
        drop(c);
        assert!(d.alive()?, "{}", d.log_text());
    }

    Ok(())
}
