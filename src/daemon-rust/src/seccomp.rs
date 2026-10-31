//! Linux Seccomp BPF sandbox and system call hardening for `gungnird`.
//!
//! Milestone 12: System Hardening & Sandboxing.
//!
//! This module provides a zero-dependency Linux BPF filter that restricts the
//! daemon's attack surface to strictly the system calls needed for its IPC,
//! SQLite storage, thread workers, io_uring, and non-blocking filesystem operations.
//!
//! Disallowed operations (such as `ptrace`, `bpf`, `mount`, `chroot`, `kexec_load`,
//! raw sockets) are safely refused with `EPERM` (in `Filter` mode) or terminate
//! the offending thread (in `Strict` mode).

use std::{fmt, io};

/// Architecture constants for Linux audit / BPF filtering.
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_JSET: u16 = 0x40;
const BPF_RET: u16 = 0x06;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
/// `seccomp_data.args[i]`, low 32 bits (little-endian). Every argument checked here but
/// one is an int or a flag word the kernel reads as 32 bits, so the high half is
/// irrelevant; sendto's dest_addr pointer is checked on both halves ([`arg_hi`]).
const fn arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

/// `seccomp_data.args[i]`, high 32 bits: for the one pointer argument checked (sendto's
/// dest_addr, which must be NULL), both halves matter.
const fn arg_hi(i: u32) -> u32 {
    20 + 8 * i
}

/// The socket type flags masked out before the type is compared (SEC-R-012).
const SOCK_TYPE_FLAGS: u32 = (libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32;

/// Every namespace flag `clone` accepts (CLONE_NEWTIME is clone3/unshare only; in clone
/// that bit is part of CSIGNAL).
const CLONE_NEW_ANY: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u32;

/// `MFD_EXEC` (Linux 6.3): an executable memfd.
const MFD_EXEC: u32 = 0x0010;

/// What the filter does with one system call. Calls without a rule get the mode's
/// default deny (`EPERM` in filter mode, kill in strict mode); the explicit denials below
/// return their errno in both modes, so the code that makes them sees a defined error.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// Allowed.
    Allow,
    /// Always refused with this errno.
    Errno(i32),
    /// Allowed when argument `arg` equals `val`, else refused with `errno`.
    ArgEq { arg: u32, val: u32, errno: i32 },
    /// Refused with `errno` when argument `arg` equals `val`, else allowed.
    ArgNe { arg: u32, val: u32, errno: i32 },
    /// Allowed when argument `arg` has none of the bits in `mask`, else refused.
    ArgMaskClear { arg: u32, mask: u32, errno: i32 },
    /// Allowed when argument `arg` is one of `vals`, else refused.
    ArgIn {
        arg: u32,
        vals: &'static [u32],
        errno: i32,
    },
    /// `socket`/`socketpair`: allowed only for AF_UNIX (else EAFNOSUPPORT) with type
    /// SOCK_STREAM once SOCK_CLOEXEC/SOCK_NONBLOCK are masked out (else EPERM).
    UnixStream,
    /// Allowed when the full 64-bit argument `arg` is 0 (a NULL pointer), else refused.
    ArgZero64 { arg: u32, errno: i32 },
}

/// The ioctl requests the daemon makes, from strace of its test suites (HANDOFF-A2,
/// evidence a2-6-ioctl-trace.txt) and the source: FIONBIO (std's set_nonblocking),
/// FICLONE (reflink copy), FS_IOC_GETVERSION (inode generation), FS_IOC_GETFSUUID and
/// BTRFS_IOC_INO_LOOKUP (filesystem identity). The kernel reads the request as 32 bits.
const IOCTLS: &[u32] = &[
    libc::FIONBIO as u32,
    libc::FICLONE as u32,
    libc::FS_IOC_GETVERSION as u32,
    crate::fsid::FS_IOC_GETFSUUID,
    crate::fsid::BTRFS_IOC_INO_LOOKUP,
];

/// Sandboxing mode for `gungnird`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompMode {
    /// Sandboxing is disabled (useful in specialized testing or debug environments).
    #[default]
    Disabled,
    /// Disallowed system calls return `EPERM` (standard production hardening).
    Filter,
    /// Disallowed system calls terminate the process with `SECCOMP_RET_KILL_PROCESS`.
    Strict,
}

impl SeccompMode {
    /// Parse mode from CLI flag string or environment variable.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" | "filter" | "enabled" => Some(Self::Filter),
            "strict" | "kill" => Some(Self::Strict),
            "0" | "false" | "no" | "off" | "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

impl fmt::Display for SeccompMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Filter => write!(f, "filter"),
            Self::Strict => write!(f, "strict"),
        }
    }
}

#[inline]
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The rules for the current architecture: the allowed calls (sorted, deduplicated) and
/// the explicitly refused ones.
#[cfg(target_arch = "x86_64")]
fn rules() -> Vec<(u32, Rule)> {
    let allowed = [
        // Process & Thread lifecycle
        libc::SYS_read as u32,
        libc::SYS_write as u32,
        libc::SYS_open as u32,
        libc::SYS_close as u32,
        libc::SYS_stat as u32,
        libc::SYS_fstat as u32,
        libc::SYS_lstat as u32,
        // glibc >= 2.33 implements stat, lstat and fstatat with newfstatat: SQLite opening
        // its database in a re-execed daemon (live upgrade), std::fs metadata (BC-HC-F02).
        libc::SYS_newfstatat as u32,
        libc::SYS_poll as u32,
        libc::SYS_lseek as u32,
        libc::SYS_munmap as u32,
        libc::SYS_brk as u32,
        libc::SYS_rt_sigaction as u32,
        libc::SYS_rt_sigprocmask as u32,
        libc::SYS_rt_sigreturn as u32,
        libc::SYS_pread64 as u32,
        libc::SYS_pwrite64 as u32,
        libc::SYS_readv as u32,
        libc::SYS_writev as u32,
        libc::SYS_access as u32,
        libc::SYS_pipe as u32,
        libc::SYS_select as u32,
        libc::SYS_sched_yield as u32,
        libc::SYS_mremap as u32,
        libc::SYS_msync as u32,
        libc::SYS_mincore as u32,
        libc::SYS_madvise as u32,
        libc::SYS_dup as u32,
        libc::SYS_dup2 as u32,
        libc::SYS_nanosleep as u32,
        libc::SYS_getitimer as u32,
        libc::SYS_setitimer as u32,
        libc::SYS_getpid as u32,
        libc::SYS_accept as u32,
        libc::SYS_recvfrom as u32,
        libc::SYS_sendmsg as u32,
        libc::SYS_recvmsg as u32,
        libc::SYS_shutdown as u32,
        libc::SYS_bind as u32,
        libc::SYS_listen as u32,
        libc::SYS_getsockname as u32,
        libc::SYS_getpeername as u32,
        libc::SYS_setsockopt as u32,
        libc::SYS_getsockopt as u32,
        libc::SYS_fork as u32,
        libc::SYS_vfork as u32, // Live in-place upgrade re-exec handover
        libc::SYS_exit as u32,
        libc::SYS_wait4 as u32,
        libc::SYS_fcntl as u32,
        libc::SYS_flock as u32,
        libc::SYS_fsync as u32,
        libc::SYS_fdatasync as u32,
        libc::SYS_ftruncate as u32,
        libc::SYS_getdents as u32,
        libc::SYS_getcwd as u32,
        libc::SYS_mkdir as u32,
        libc::SYS_rmdir as u32,
        libc::SYS_unlink as u32,
        libc::SYS_readlink as u32,
        libc::SYS_chmod as u32,
        libc::SYS_fchmod as u32,
        libc::SYS_chown as u32,
        libc::SYS_fchown as u32,
        libc::SYS_umask as u32,
        libc::SYS_gettimeofday as u32,
        libc::SYS_getrlimit as u32,
        libc::SYS_getrusage as u32,
        libc::SYS_sysinfo as u32,
        libc::SYS_times as u32,
        libc::SYS_getuid as u32,
        libc::SYS_getgid as u32,
        libc::SYS_geteuid as u32,
        libc::SYS_getegid as u32,
        libc::SYS_sigaltstack as u32,
        libc::SYS_arch_prctl as u32,
        libc::SYS_setrlimit as u32,
        libc::SYS_statfs as u32,
        libc::SYS_fstatfs as u32,
        libc::SYS_sched_setaffinity as u32,
        libc::SYS_sched_getaffinity as u32,
        libc::SYS_restart_syscall as u32,
        libc::SYS_gettid as u32,
        libc::SYS_futex as u32,
        libc::SYS_epoll_create as u32,
        libc::SYS_epoll_ctl as u32,
        libc::SYS_epoll_wait as u32,
        libc::SYS_getdents64 as u32,
        libc::SYS_set_tid_address as u32,
        libc::SYS_clock_gettime as u32,
        libc::SYS_clock_getres as u32,
        libc::SYS_clock_nanosleep as u32,
        libc::SYS_exit_group as u32,
        libc::SYS_utimes as u32,
        libc::SYS_openat as u32,
        libc::SYS_mkdirat as u32,
        libc::SYS_unlinkat as u32,
        // Copying a symlink recreates it (ops io::symlink); AUD-02.
        libc::SYS_symlinkat as u32,
        libc::SYS_renameat as u32,
        libc::SYS_readlinkat as u32,
        libc::SYS_fchmodat as u32,
        libc::SYS_fchownat as u32,
        libc::SYS_faccessat as u32,
        libc::SYS_pselect6 as u32,
        libc::SYS_ppoll as u32,
        libc::SYS_set_robust_list as u32,
        libc::SYS_get_robust_list as u32,
        libc::SYS_splice as u32,
        libc::SYS_tee as u32,
        libc::SYS_sync_file_range as u32,
        libc::SYS_fallocate as u32,
        libc::SYS_utimensat as u32,
        libc::SYS_epoll_pwait as u32,
        libc::SYS_signalfd as u32,
        libc::SYS_signalfd4 as u32,
        libc::SYS_eventfd as u32,
        libc::SYS_eventfd2 as u32,
        libc::SYS_epoll_create1 as u32,
        libc::SYS_dup3 as u32,
        libc::SYS_pipe2 as u32,
        libc::SYS_preadv as u32,
        libc::SYS_pwritev as u32,
        libc::SYS_accept4 as u32,
        libc::SYS_prlimit64 as u32,
        libc::SYS_syncfs as u32,
        libc::SYS_sendmmsg as u32,
        libc::SYS_recvmmsg as u32,
        libc::SYS_getrandom as u32,
        libc::SYS_seccomp as u32,
        libc::SYS_renameat2 as u32,
        libc::SYS_copy_file_range as u32,
        libc::SYS_preadv2 as u32,
        libc::SYS_pwritev2 as u32,
        libc::SYS_statx as u32,
        // Rings are created, restricted and enabled before the filter is installed
        // (ops::io::prepare_sandbox_rings); afterwards only io_uring_enter (D-044).
        libc::SYS_io_uring_enter as u32,
        libc::SYS_openat2 as u32,
        libc::SYS_close_range as u32,
        libc::SYS_faccessat2 as u32,
        libc::SYS_rseq as u32,
        // Extended attributes
        libc::SYS_flistxattr as u32,
        libc::SYS_fgetxattr as u32,
        libc::SYS_fsetxattr as u32,
        libc::SYS_fremovexattr as u32,
        libc::SYS_llistxattr as u32,
        libc::SYS_lgetxattr as u32,
        libc::SYS_lsetxattr as u32,
        libc::SYS_lremovexattr as u32,
        libc::SYS_listxattr as u32,
        libc::SYS_getxattr as u32,
        libc::SYS_setxattr as u32,
        libc::SYS_removexattr as u32,
    ];
    let denied = [
        // No new rings, no ring registrations once sandboxed (D-044 item 1).
        (libc::SYS_io_uring_setup as u32, libc::EPERM),
        (libc::SYS_io_uring_register as u32, libc::EPERM),
        // No exec: a sandboxed live upgrade drains and exits instead (D-044 item 2).
        (libc::SYS_execve as u32, libc::EPERM),
        (libc::SYS_execveat as u32, libc::EPERM),
        // clone3 passes its flags in a struct the filter cannot read: ENOSYS makes glibc
        // fall back to clone, whose flags it can (D-044 item 4).
        (libc::SYS_clone3 as u32, libc::ENOSYS),
        // No new connections once sandboxed: the control socket is bound and the
        // liveness check of an old socket (ipc::socket_is_live) has run before the
        // filter goes in, and the daemon never connects anywhere afterwards, so the
        // user's session bus or systemd manager stays out of reach (SEC-R-012).
        (libc::SYS_connect as u32, libc::EPERM),
    ];
    let af_unix = |nr: libc::c_long| (nr as u32, Rule::UnixStream);
    // SAFETY: getpid has no preconditions.
    let own_tgid = unsafe { libc::getpid() } as u32;
    let checked = [
        // AF_UNIX stream sockets only: the control socket and its peers (D-044 item 3);
        // no datagram socket to send to journald, a notify socket or the like (SEC-R-012).
        af_unix(libc::SYS_socket),
        af_unix(libc::SYS_socketpair),
        // send/write on a connected socket only: an addressed sendto (dest_addr, arg 4,
        // not NULL) is refused (SEC-R-012). sendmsg stays: its msghdr is not readable
        // by the filter, but every socket the daemon can have is a stream socket, which
        // refuses an address in msg_name (EISCONN/EOPNOTSUPP); SCM_RIGHTS on the
        // connected IPC socket keeps working.
        (
            libc::SYS_sendto as u32,
            Rule::ArgZero64 {
                arg: 4,
                errno: libc::EPERM,
            },
        ),
        // Signals only to this process (its own tgid, read when the filter is built:
        // the sandboxed process never re-execs), e.g. raise/abort (D-044 item 7).
        (
            libc::SYS_kill as u32,
            Rule::ArgEq {
                arg: 0,
                val: own_tgid,
                errno: libc::EPERM,
            },
        ),
        (
            libc::SYS_tgkill as u32,
            Rule::ArgEq {
                arg: 0,
                val: own_tgid,
                errno: libc::EPERM,
            },
        ),
        // Thread names stay; the dumpable flag cleared by apply_sandbox stays cleared, or
        // /proc/self/mem would open again (SEC-F-008).
        (
            libc::SYS_prctl as u32,
            Rule::ArgNe {
                arg: 0,
                val: libc::PR_SET_DUMPABLE as u32,
                errno: libc::EPERM,
            },
        ),
        // Threads, not namespaces: clone with any CLONE_NEW* flag is refused (D-044 item 4).
        (
            libc::SYS_clone as u32,
            Rule::ArgMaskClear {
                arg: 0,
                mask: CLONE_NEW_ANY,
                errno: libc::EPERM,
            },
        ),
        // No executable memory once sandboxed: everything that needs it (the binary,
        // its libraries) is mapped by then (D-044 item 5).
        (
            libc::SYS_mmap as u32,
            Rule::ArgMaskClear {
                arg: 2,
                mask: libc::PROT_EXEC as u32,
                errno: libc::EPERM,
            },
        ),
        (
            libc::SYS_mprotect as u32,
            Rule::ArgMaskClear {
                arg: 2,
                mask: libc::PROT_EXEC as u32,
                errno: libc::EPERM,
            },
        ),
        // Only the ioctls the daemon makes; any other gets ENOTTY, what an unsupported
        // request returns anyway, so callers degrade as on a filesystem without it
        // (D-044 item 6).
        (
            libc::SYS_ioctl as u32,
            Rule::ArgIn {
                arg: 1,
                vals: IOCTLS,
                errno: libc::ENOTTY,
            },
        ),
        (
            libc::SYS_memfd_create as u32,
            Rule::ArgMaskClear {
                arg: 1,
                mask: MFD_EXEC,
                errno: libc::EPERM,
            },
        ),
    ];
    let mut list: Vec<(u32, Rule)> = denied.iter().map(|&(n, e)| (n, Rule::Errno(e))).collect();
    list.extend(checked);
    // A call with its own rule is never also plainly allowed.
    list.extend(
        allowed
            .iter()
            .filter(|&&n| !list.iter().any(|(m, _)| *m == n))
            .map(|&n| (n, Rule::Allow))
            .collect::<Vec<_>>(),
    );
    list.sort_by_key(|&(n, _)| n);
    list.dedup_by_key(|&mut (n, _)| n);
    list
}

#[cfg(not(target_arch = "x86_64"))]
fn rules() -> Vec<(u32, Rule)> {
    Vec::new()
}

/// BPF for one rule, run with the syscall number in A; ends in a return.
fn rule_block(rule: &Rule) -> Vec<libc::sock_filter> {
    let errno = |e: i32| bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ERRNO | (e as u32));
    let allow = bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW);
    let load = |arg: u32| bpf_stmt(BPF_LD | BPF_W | BPF_ABS, arg_lo(arg));
    match rule.clone() {
        Rule::Allow => vec![allow],
        Rule::Errno(e) => vec![errno(e)],
        // A = arg; A == val ? allow : errno
        Rule::ArgEq { arg, val, errno: e } => vec![
            load(arg),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val, 0, 1),
            allow,
            errno(e),
        ],
        // A = arg; A == val ? errno : allow
        Rule::ArgNe { arg, val, errno: e } => vec![
            load(arg),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, val, 0, 1),
            errno(e),
            allow,
        ],
        // A = arg; A == vals[i] for some i ? allow : errno
        Rule::ArgIn {
            arg,
            vals,
            errno: e,
        } => {
            let n = vals.len();
            let mut b = vec![load(arg)];
            for (i, &v) in vals.iter().enumerate() {
                // From instruction i (after the load) to the allow at n + 1.
                let jt = u8::try_from(n - i).unwrap_or(u8::MAX);
                b.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, v, jt, 0));
            }
            b.push(errno(e));
            b.push(allow);
            b
        }
        // A = arg0; A == AF_UNIX ? next : EAFNOSUPPORT;
        // A = arg1 & !flags; A == SOCK_STREAM ? allow : EPERM
        Rule::UnixStream => vec![
            load(0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::AF_UNIX as u32, 1, 0),
            errno(libc::EAFNOSUPPORT),
            load(1),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, !SOCK_TYPE_FLAGS),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SOCK_STREAM as u32, 0, 1),
            allow,
            errno(libc::EPERM),
        ],
        // lo == 0 && hi == 0 ? allow : errno
        Rule::ArgZero64 { arg, errno: e } => vec![
            load(arg),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, arg_hi(arg)),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
            allow,
            errno(e),
        ],
        // A = arg; A & mask ? errno : allow
        Rule::ArgMaskClear {
            arg,
            mask,
            errno: e,
        } => vec![
            load(arg),
            bpf_jump(BPF_JMP | BPF_JSET | BPF_K, mask, 1, 0),
            allow,
            errno(e),
        ],
    }
}

/// Build the BPF bytecode filter for the current platform and mode.
pub fn build_filter(mode: SeccompMode) -> io::Result<Vec<libc::sock_filter>> {
    if mode == SeccompMode::Disabled {
        return Ok(Vec::new());
    }

    #[cfg(target_arch = "x86_64")]
    let target_arch = AUDIT_ARCH_X86_64;
    #[cfg(target_arch = "aarch64")]
    let target_arch = AUDIT_ARCH_AARCH64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let target_arch = 0;

    let rules = rules();
    if rules.is_empty() {
        // Architecture not explicitly enumerated; allow all safely
        return Ok(vec![bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW)]);
    }

    let mut filter = Vec::with_capacity(rules.len() * 3 + 6);

    // 0: Load architecture
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    // 1: Verify arch matches expected target
    filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, target_arch, 1, 0));
    // 2: Mismatch -> return ENOSYS
    filter.push(bpf_stmt(
        BPF_RET | BPF_K,
        libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32),
    ));

    // Each rule: load the syscall number (an argument check may have replaced it in A),
    // skip the rule's block unless it matches, else run the block (which returns).
    for (nr, rule) in &rules {
        let block = rule_block(rule);
        let skip = u8::try_from(block.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "seccomp rule block too long")
        })?;
        filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
        filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, *nr, 0, skip));
        filter.extend(block);
    }

    // Default disallowed action:
    let deny_ret = match mode {
        SeccompMode::Strict => libc::SECCOMP_RET_KILL_PROCESS,
        _ => libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
    };
    filter.push(bpf_stmt(BPF_RET | BPF_K, deny_ret));
    if filter.len() > usize::from(u16::MAX).min(4096) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seccomp filter longer than BPF_MAXINSNS",
        ));
    }

    Ok(filter)
}

/// The outcome of `seccomp(SET_MODE_FILTER, TSYNC)`: 0 is success, a positive value the
/// id of a thread that could not be synchronized, -1 an error (`err`). Anything but 0
/// is an error: there is no fallback that would filter only the calling thread.
fn tsync_result(ret: libc::c_long, err: io::Error) -> io::Result<()> {
    match ret {
        0 => Ok(()),
        tid if tid > 0 => Err(io::Error::other(format!(
            "seccomp TSYNC: thread {tid} could not be synchronized; refusing to run unfiltered threads"
        ))),
        _ => Err(io::Error::new(
            err.kind(),
            format!("seccomp TSYNC failed ({err}); no single-thread fallback"),
        )),
    }
}

/// Apply the seccomp BPF sandbox to the current process.
pub fn apply_sandbox(mode: SeccompMode) -> io::Result<()> {
    if mode == SeccompMode::Disabled {
        return Ok(());
    }

    let filter = build_filter(mode)?;
    if filter.is_empty() {
        return Ok(());
    }

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    // Nothing to read back from a sandboxed daemon: no core file, and with dumpable off
    // /proc/self/mem cannot be opened to patch its own code past the PROT_EXEC rules. Its
    // /proc entries turn root-owned, but what it uses stays open to it: mountinfo is
    // world-readable and /proc/self/fd is always open to its own thread group (SEC-F-008).
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `no_core` outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const no_core) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain flag prctl.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // Ensure PR_SET_NO_NEW_PRIVS is enabled prior to applying seccomp filter
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Every thread of the process, at once (TSYNC): the daemon installs the filter after
    // its workers, monitor and DB threads exist. No single-thread fallback: if any thread
    // cannot be synchronized, or the kernel lacks TSYNC, fail closed (SEC-R-011).
    #[cfg(feature = "test-hooks")]
    if std::env::var_os("GUNGNIR_TEST_TSYNC_FAIL").is_some() {
        // Fault injection for the refusal path (DIR-A2-F01): as if TSYNC were missing.
        return tsync_result(-1, io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: `prog` points at `filter`, which outlives the call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const libc::sock_fprog,
        )
    };
    tsync_result(ret, io::Error::last_os_error())?;
    Ok(())
}

/// Query whether the host kernel supports seccomp BPF filtering.
#[must_use]
pub fn is_supported() -> bool {
    let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    ret >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(SeccompMode::parse("filter"), Some(SeccompMode::Filter));
        assert_eq!(SeccompMode::parse("1"), Some(SeccompMode::Filter));
        assert_eq!(SeccompMode::parse("strict"), Some(SeccompMode::Strict));
        assert_eq!(SeccompMode::parse("off"), Some(SeccompMode::Disabled));
        assert_eq!(SeccompMode::parse("0"), Some(SeccompMode::Disabled));
        assert_eq!(SeccompMode::parse("unknown_mode"), None);
    }

    #[test]
    fn filter_compiles_and_jump_offsets_fit() {
        for (mode, deny) in [
            (
                SeccompMode::Filter,
                libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
            ),
            (SeccompMode::Strict, libc::SECCOMP_RET_KILL_PROCESS),
        ] {
            let f = build_filter(mode).unwrap();
            assert!(f.len() > 50 && f.len() <= 4096, "{} instructions", f.len());
            // The last instruction is the default deny.
            let last = f[f.len() - 1];
            assert_eq!((last.code, last.k), (BPF_RET | BPF_K, deny));
            // Every jump lands inside the program.
            for (i, ins) in f.iter().enumerate() {
                if ins.code & 0x07 == BPF_JMP {
                    let far = i + 1 + usize::from(ins.jt.max(ins.jf));
                    assert!(far < f.len(), "jump at {i} leaves the program");
                }
            }
        }
    }

    #[test]
    fn io_uring_setup_and_register_are_refused_enter_allowed() {
        let r = rules();
        let get = |n: libc::c_long| {
            r.iter()
                .find(|(x, _)| *x == n as u32)
                .map(|(_, r)| r.clone())
        };
        assert_eq!(
            get(libc::SYS_io_uring_setup),
            Some(Rule::Errno(libc::EPERM))
        );
        assert_eq!(
            get(libc::SYS_io_uring_register),
            Some(Rule::Errno(libc::EPERM))
        );
        assert_eq!(get(libc::SYS_io_uring_enter), Some(Rule::Allow));
    }

    #[test]
    fn sockets_are_af_unix_only() {
        let r = rules();
        for n in [libc::SYS_socket, libc::SYS_socketpair] {
            let got = r
                .iter()
                .find(|(x, _)| *x == n as u32)
                .map(|(_, r)| r.clone());
            assert_eq!(got, Some(Rule::UnixStream), "syscall {n}");
        }
    }

    /// SEC-R-012: AF_UNIX stream sockets only, no connect, no addressed sendto.
    #[test]
    fn the_filter_allows_only_unix_stream_sockets_and_no_new_connections() {
        let f = build_filter(SeccompMode::Strict).unwrap();
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let eafno = libc::SECCOMP_RET_ERRNO | libc::EAFNOSUPPORT as u32;
        let allow = libc::SECCOMP_RET_ALLOW;
        let unix = libc::AF_UNIX as u64;
        let stream = libc::SOCK_STREAM as u64;
        let flags = u64::from(SOCK_TYPE_FLAGS);
        for nr in [libc::SYS_socket as u32, libc::SYS_socketpair as u32] {
            assert_eq!(decide(&f, nr, [unix, stream, 0, 0, 0, 0]), allow);
            assert_eq!(decide(&f, nr, [unix, stream | flags, 0, 0, 0, 0]), allow);
            for t in [libc::SOCK_DGRAM, libc::SOCK_SEQPACKET, libc::SOCK_RAW] {
                let t = t as u64;
                assert_eq!(decide(&f, nr, [unix, t, 0, 0, 0, 0]), eperm, "{t}");
                assert_eq!(decide(&f, nr, [unix, t | flags, 0, 0, 0, 0]), eperm);
            }
            assert_eq!(
                decide(&f, nr, [libc::AF_INET as u64, stream, 0, 0, 0, 0]),
                eafno
            );
        }
        let connect = libc::SYS_connect as u32;
        assert_eq!(decide(&f, connect, [3, 0x1000, 110, 0, 0, 0]), eperm);
        let sendto = libc::SYS_sendto as u32;
        assert_eq!(decide(&f, sendto, [3, 0x1000, 8, 0, 0, 0]), allow);
        for dest in [0x1000u64, 1 << 32, (1 << 32) | 0x10, 0x7fff_0000_0000] {
            assert_eq!(
                decide(&f, sendto, [3, 0x1000, 8, 0, dest, 110]),
                eperm,
                "{dest:#x}"
            );
        }
        assert_eq!(
            decide(&f, libc::SYS_sendmsg as u32, [3, 0x1000, 0, 0, 0, 0]),
            allow
        );
    }

    /// SEC-F-008: the dumpable flag cannot be turned back on; other prctls still pass.
    #[test]
    fn the_filter_refuses_set_dumpable_only() {
        let f = build_filter(SeccompMode::Strict).unwrap();
        let nr = libc::SYS_prctl as u32;
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let dumpable = libc::PR_SET_DUMPABLE as u64;
        assert_eq!(decide(&f, nr, [dumpable, 1, 0, 0, 0, 0]), eperm);
        assert_eq!(decide(&f, nr, [dumpable, 0, 0, 0, 0, 0]), eperm);
        assert_eq!(
            decide(&f, nr, [libc::PR_SET_NAME as u64, 0x1000, 0, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn clone_without_namespaces_clone3_enosys() {
        let r = rules();
        let get = |n: libc::c_long| {
            r.iter()
                .find(|(x, _)| *x == n as u32)
                .map(|(_, r)| r.clone())
        };
        assert_eq!(get(libc::SYS_clone3), Some(Rule::Errno(libc::ENOSYS)));
        assert_eq!(
            get(libc::SYS_clone),
            Some(Rule::ArgMaskClear {
                arg: 0,
                mask: CLONE_NEW_ANY,
                errno: libc::EPERM
            })
        );
        assert_eq!(CLONE_NEW_ANY & libc::CSIGNAL as u32, 0);
    }

    #[test]
    fn no_executable_memory() {
        let r = rules();
        let get = |n: libc::c_long| {
            r.iter()
                .find(|(x, _)| *x == n as u32)
                .map(|(_, r)| r.clone())
        };
        let prot = |arg| Rule::ArgMaskClear {
            arg,
            mask: libc::PROT_EXEC as u32,
            errno: libc::EPERM,
        };
        assert_eq!(get(libc::SYS_mmap), Some(prot(2)));
        assert_eq!(get(libc::SYS_mprotect), Some(prot(2)));
        assert_eq!(
            get(libc::SYS_memfd_create),
            Some(Rule::ArgMaskClear {
                arg: 1,
                mask: MFD_EXEC,
                errno: libc::EPERM
            })
        );
        assert_eq!(
            get(libc::SYS_pkey_mprotect),
            None,
            "pkey_mprotect stays denied"
        );
    }

    /// A classic-BPF interpreter for the subset the builder emits, to check what the
    /// filter decides for a given call (seccomp_data: nr, arch, ip, args).
    fn decide(f: &[libc::sock_filter], nr: u32, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_le_bytes());
        for (i, a) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
        }
        let (mut a, mut pc) = (0u32, 0usize);
        loop {
            let ins = f[pc];
            pc += 1;
            match ins.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    let k = ins.k as usize;
                    a = u32::from_le_bytes(data[k..k + 4].try_into().unwrap());
                }
                c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += usize::from(if a == ins.k { ins.jt } else { ins.jf });
                }
                c if c == BPF_ALU | BPF_AND | BPF_K => a &= ins.k,
                c if c == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += usize::from(if a & ins.k != 0 { ins.jt } else { ins.jf });
                }
                c if c == BPF_RET | BPF_K => return ins.k,
                c => panic!("unexpected BPF opcode {c:#x}"),
            }
        }
    }

    #[test]
    fn the_filter_decides_ioctls_by_request() {
        let f = build_filter(SeccompMode::Strict).unwrap();
        let nr = libc::SYS_ioctl as u32;
        let enotty = libc::SECCOMP_RET_ERRNO | libc::ENOTTY as u32;
        for &v in IOCTLS {
            assert_eq!(
                decide(&f, nr, [3, u64::from(v), 0, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
            // The high half of the request is ignored, as by the kernel.
            let hi = u64::from(v) | (1 << 40);
            assert_eq!(decide(&f, nr, [3, hi, 0, 0, 0, 0]), libc::SECCOMP_RET_ALLOW);
        }
        for v in [libc::TCGETS, libc::TIOCSTI, 0x5451, 0] {
            assert_eq!(decide(&f, nr, [3, v, 0, 0, 0, 0]), enotty, "{v:#x}");
        }
        // A call with no rule gets the mode's default, an allowed one is allowed.
        assert_eq!(
            decide(&f, libc::SYS_ptrace as u32, [0; 6]),
            libc::SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            decide(&f, libc::SYS_getpid as u32, [0; 6]),
            libc::SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn signals_only_to_this_process_and_no_set_id() {
        let f = build_filter(SeccompMode::Strict).unwrap();
        let me = u64::from(std::process::id());
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let kill = libc::SYS_kill as u32;
        let tgkill = libc::SYS_tgkill as u32;
        assert_eq!(
            decide(&f, kill, [me, 15, 0, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            decide(&f, tgkill, [me, me, 6, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        // Another pid, a process group (0, -1, -pgid): refused.
        for other in [
            me + 1,
            1,
            0,
            u64::from(u32::MAX),
            u64::from(-(me as i64) as u32),
        ] {
            assert_eq!(decide(&f, kill, [other, 15, 0, 0, 0, 0]), eperm, "{other}");
            assert_eq!(
                decide(&f, tgkill, [other, other, 6, 0, 0, 0]),
                eperm,
                "{other}"
            );
        }
        for n in [libc::SYS_setuid, libc::SYS_setgid, libc::SYS_tkill] {
            assert_eq!(
                decide(&f, n as u32, [0; 6]),
                libc::SECCOMP_RET_KILL_PROCESS,
                "syscall {n}"
            );
        }
    }

    #[test]
    fn tsync_failure_of_any_kind_fails_closed() {
        assert!(tsync_result(0, io::Error::from_raw_os_error(0)).is_ok());
        // ENOSYS / EINVAL (no TSYNC) used to fall back to a filter on one thread.
        for e in [
            libc::ENOSYS,
            libc::EINVAL,
            libc::EFAULT,
            libc::ENOMEM,
            libc::EACCES,
        ] {
            let r = tsync_result(-1, io::Error::from_raw_os_error(e));
            assert!(r.is_err(), "errno {e}");
        }
        let r = tsync_result(4242, io::Error::from_raw_os_error(0)).unwrap_err();
        assert!(r.to_string().contains("thread 4242"), "{r}");
    }

    #[test]
    fn ioctl_allowlist() {
        let r = rules();
        let got = r
            .iter()
            .find(|(x, _)| *x == libc::SYS_ioctl as u32)
            .map(|(_, r)| r.clone());
        assert_eq!(
            got,
            Some(Rule::ArgIn {
                arg: 1,
                vals: IOCTLS,
                errno: libc::ENOTTY
            })
        );
        assert_eq!(IOCTLS.len(), 5);
        // Decoded from the strace run (evidence a2-6-ioctl-trace.txt).
        for v in [0x5421, 0x4004_9409, 0x8008_7601, 0x8011_1500, 0xd000_9412] {
            assert!(IOCTLS.contains(&v), "{v:#x}");
        }
    }

    #[test]
    fn exec_is_refused() {
        let r = rules();
        for n in [libc::SYS_execve, libc::SYS_execveat] {
            let got = r
                .iter()
                .find(|(x, _)| *x == n as u32)
                .map(|(_, r)| r.clone());
            assert_eq!(got, Some(Rule::Errno(libc::EPERM)), "syscall {n}");
        }
    }
}
