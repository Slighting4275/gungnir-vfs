//! Test-only helper (feature `test-hooks`, never installed): connect to the socket at
//! the path given, send a hello and say what the daemon did. Run as another user by the
//! cross-user tests. Exit 0 "REPLY" (a hello reply came back), 3 "CLOSED" (the daemon
//! hung up without one), 4 "CONNECT <error>", 5 "TIMEOUT".

use std::{
    io::{ErrorKind, Read, Write},
    os::unix::net::UnixStream,
    process::ExitCode,
    time::Duration,
};

use gungnird::ipc::{FRAME_LEN, Frame};

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: gungnir-peer-probe <socket>");
        return ExitCode::from(2);
    };
    let mut s = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => {
            println!("CONNECT {e}");
            return ExitCode::from(4);
        }
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    if let Err(e) = s.write_all(&Frame::hello().encode()) {
        println!("CLOSED (write: {e})");
        return ExitCode::from(3);
    }
    let mut buf = [0u8; FRAME_LEN];
    match s.read_exact(&mut buf) {
        Ok(()) => {
            println!("REPLY");
            ExitCode::SUCCESS
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            println!("TIMEOUT");
            ExitCode::from(5)
        }
        Err(e) => {
            println!("CLOSED ({e})");
            ExitCode::from(3)
        }
    }
}
