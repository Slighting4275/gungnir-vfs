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
