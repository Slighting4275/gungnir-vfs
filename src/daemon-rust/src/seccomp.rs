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
const BPF_RET: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// What the filter does with one system call. Calls without a rule get the mode's
/// default deny (`EPERM` in filter mode, kill in strict mode); the explicit denials below
/// return their errno in both modes, so the code that makes them sees a defined error.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// Allowed.
    Allow,
    /// Always refused with this errno.
    Errno(i32),
}

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
        libc::SYS_mmap as u32,
        libc::SYS_mprotect as u32,
        libc::SYS_munmap as u32,
        libc::SYS_brk as u32,
        libc::SYS_rt_sigaction as u32,
        libc::SYS_rt_sigprocmask as u32,
        libc::SYS_rt_sigreturn as u32,
        libc::SYS_ioctl as u32,
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
        libc::SYS_socket as u32,
        libc::SYS_connect as u32,
        libc::SYS_accept as u32,
        libc::SYS_sendto as u32,
        libc::SYS_recvfrom as u32,
        libc::SYS_sendmsg as u32,
        libc::SYS_recvmsg as u32,
        libc::SYS_shutdown as u32,
        libc::SYS_bind as u32,
        libc::SYS_listen as u32,
        libc::SYS_getsockname as u32,
        libc::SYS_getpeername as u32,
        libc::SYS_socketpair as u32,
        libc::SYS_setsockopt as u32,
        libc::SYS_getsockopt as u32,
        libc::SYS_clone as u32,
        libc::SYS_fork as u32,
        libc::SYS_vfork as u32, // Live in-place upgrade re-exec handover
        libc::SYS_exit as u32,
        libc::SYS_wait4 as u32,
        libc::SYS_kill as u32,
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
        libc::SYS_setuid as u32,
        libc::SYS_setgid as u32,
        libc::SYS_geteuid as u32,
        libc::SYS_getegid as u32,
        libc::SYS_sigaltstack as u32,
        libc::SYS_arch_prctl as u32,
        libc::SYS_prctl as u32,
        libc::SYS_setrlimit as u32,
        libc::SYS_statfs as u32,
        libc::SYS_fstatfs as u32,
        libc::SYS_sched_setaffinity as u32,
        libc::SYS_sched_getaffinity as u32,
        libc::SYS_restart_syscall as u32,
        libc::SYS_gettid as u32,
        libc::SYS_tkill as u32,
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
        libc::SYS_tgkill as u32,
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
        libc::SYS_memfd_create as u32,
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
        libc::SYS_clone3 as u32,
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
    ];
    let mut list: Vec<(u32, Rule)> = allowed.iter().map(|&n| (n, Rule::Allow)).collect();
    list.extend(denied.iter().map(|&(n, e)| (n, Rule::Errno(e))));
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
    match *rule {
        Rule::Allow => vec![allow],
        Rule::Errno(e) => vec![errno(e)],
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

    // Ensure PR_SET_NO_NEW_PRIVS is enabled prior to applying seccomp filter
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Attempt to apply seccomp with thread synchronization (TSYNC)
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const libc::sock_fprog,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) || err.raw_os_error() == Some(libc::EINVAL) {
            // Fallback to prctl
            let prctl_ret =
                unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) };
            if prctl_ret != 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            return Err(err);
        }
    }

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
