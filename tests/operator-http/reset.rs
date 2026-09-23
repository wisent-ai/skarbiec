//! A connection its client resets before the vault accepts it.

use super::CliFixture;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::process::Command;

/// Connections queued and reset while the service is stopped.
const RESETS: usize = 8;
/// Process-state reads allowed before the stop is taken as not having landed.
const STOP_CHECKS: usize = 200;

/// A client that resets its connection while it still waits in the listen
/// queue ends only that connection. The kernel reports it as ECONNABORTED
/// from `accept`, and the one process used to end its HTTP component - and
/// with it the whole vault - on the first one.
#[test]
fn a_connection_reset_before_accept_leaves_the_vault_serving() {
    let fixture = CliFixture::new("reset");
    fixture.init("Reset Test <reset@test.local>");
    let mut broker = fixture.serve();
    let pid = broker.pid().to_string();
    signal("-STOP", &pid);
    // Each state read is a real `ps` run, which is what paces this wait.
    let stopped = (0..STOP_CHECKS).any(|_| {
        let state = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid])
            .output()
            .expect("read the service's process state");
        String::from_utf8_lossy(&state.stdout)
            .trim_start()
            .starts_with('T')
    });
    assert!(
        stopped,
        "the service never stopped, so no connection waited in its queue"
    );
    let queued: Vec<TcpStream> = (0..RESETS)
        .map(|_| {
            TcpStream::connect(("127.0.0.1", broker.port()))
                .expect("queue a connection behind the stopped service")
        })
        .collect();
    queued.into_iter().for_each(reset);
    signal("-CONT", &pid);

    let mut stream =
        TcpStream::connect(("127.0.0.1", broker.port())).expect("reach the resumed service");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("send a health request");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    assert!(
        answer.starts_with("HTTP/1.1 ") && answer.contains("\"service\":\"skarbiec\""),
        "the vault did not answer after {RESETS} connections were reset before accept: {answer:?}"
    );
    assert!(
        broker.exited().is_none(),
        "the vault exited after connections were reset before accept"
    );
}

fn signal(which: &str, pid: &str) {
    let status = Command::new("kill")
        .args([which, pid])
        .status()
        .expect("signal the service");
    assert!(status.success(), "kill {which} {pid} failed: {status}");
}

/// Close `stream` with a reset rather than a FIN, the way a client that gives
/// up on a connection still waiting to be accepted does.
fn reset(stream: TcpStream) {
    let abortive = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: the descriptor is the stream's own open socket and `abortive`
    // outlives the call that reads it.
    let armed = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            std::ptr::addr_of!(abortive).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(
        armed,
        0,
        "arm an abortive close: {}",
        std::io::Error::last_os_error()
    );
    drop(stream);
}
