//! A gpg child stranded on an agent that never answers is ended by daemon
//! recovery. The agent socket of the isolated keyring is replaced by a
//! stand-in: a connection from a child of the waiting `skarbiec get` is
//! accepted and never answered, so its gpg waits as one waits on a wedged
//! agent; every other connection (the recovery's own `gpgconf --kill` and
//! daemon queries) is answered `OK` to each line and closed on `KILLAGENT` or
//! `BYE`. `skarbiec recover-daemons`, run beside it, has to end that gpg
//! child, and the waiting read has to fail instead of standing on. With the
//! stand-in gone, the real agent starts again and the value reads back.
use super::{fs, Journey};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;

/// The process at the other end of a Unix stream.
#[cfg(target_os = "macos")]
pub(super) fn peer(stream: &UnixStream) -> libc::pid_t {
    let mut pid: libc::pid_t = unsafe { std::mem::zeroed() };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::pid_t>()).unwrap();
    let read = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast(),
            &mut length,
        )
    };
    // getsockopt answers a negative value when it fails, with errno set.
    assert!(!read.is_negative(), "{}", std::io::Error::last_os_error());
    pid
}

/// The process at the other end of a Unix stream.
#[cfg(target_os = "linux")]
pub(super) fn peer(stream: &UnixStream) -> libc::pid_t {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).unwrap();
    let read = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    };
    // getsockopt answers a negative value when it fails, with errno set.
    assert!(!read.is_negative(), "{}", std::io::Error::last_os_error());
    credentials.pid
}

/// The parent of `pid`, as the process table names it; none when the process
/// is gone and `ps` names nobody.
pub(super) fn parent(pid: libc::pid_t) -> Option<u32> {
    let output = Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .expect("ps runs");
    let named = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!named.is_empty()).then(|| named.parse().expect("ps names a parent by its pid"))
}

/// Answer one connection as an agent that accepts every command, until the
/// caller says `KILLAGENT` or `BYE` or goes away.
pub(super) fn answer(stream: UnixStream) {
    let mut writer = stream.try_clone().expect("the stand-in clones its stream");
    if writer.write_all(b"OK stand-in agent\n").is_err() {
        return;
    }
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { return };
        if writer.write_all(b"OK\n").is_err() {
            return;
        }
        let verb = line.split_whitespace().next().map(str::to_ascii_uppercase);
        if matches!(verb.as_deref(), Some("KILLAGENT" | "BYE")) {
            return;
        }
    }
}

impl Journey {
    pub(super) fn stranded_child_ended(&mut self, item: &str, value: &str) {
        let mut directories = Command::new("gpgconf");
        directories
            .args(["--list-dirs", "agent-socket"])
            .env("GNUPGHOME", &self.keyring);
        let socket = self.run("agent-socket", &mut directories);
        let socket = std::path::PathBuf::from(String::from_utf8(socket.stdout).unwrap().trim());
        let mut kill = Command::new("gpgconf");
        kill.args(["--kill", "gpg-agent"])
            .env("GNUPGHOME", &self.keyring);
        self.run("kill-real-agent", &mut kill);
        if socket.exists() {
            fs::remove_file(&socket).unwrap();
        }
        let listener = UnixListener::bind(&socket).expect("the stand-in binds the agent socket");

        let mut read = self.command(&["get", item, "--field", "value"]);
        read.stdout(Stdio::piped()).stderr(Stdio::piped());
        let waiting = read.spawn().expect("the waiting read starts");
        let reader = waiting.id();
        let (held, stranded) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.expect("the stand-in accepts");
                let pid = peer(&stream);
                if parent(pid) == Some(reader) {
                    // Kept open and never answered: the child waits on it.
                    held.send((pid, stream))
                        .expect("the test holds the stranded child");
                } else {
                    std::thread::spawn(move || answer(stream));
                }
            }
        });
        let (child, _connection) = stranded.recv().expect("the read's gpg reaches the agent");
        fs::write(self.root.join("stranded-child.pid"), child.to_string()).unwrap();

        let recovery = self.skarbiec("recover-stranded", &["recover-daemons"]);
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&recovery.stdout),
            String::from_utf8_lossy(&recovery.stderr)
        );
        assert!(
            said.contains(&format!("sent TERM to gpg child {child}")),
            "recovery did not end the gpg child stranded on the agent: {said}"
        );

        let ended = waiting.wait_with_output().expect("the waiting read ends");
        fs::write(self.root.join("stranded-read.stdout"), &ended.stdout).unwrap();
        fs::write(self.root.join("stranded-read.stderr"), &ended.stderr).unwrap();
        self.commands
            .push(serde_json::json!({"label": "stranded-read",
            "exit": ended.status.code(), "status": ended.status.to_string()}));
        self.save();
        assert!(
            !ended.status.success(),
            "the read whose gpg was ended reported success"
        );

        fs::remove_file(&socket).expect("the stand-in socket is removed");
        let after = self.skarbiec("read-after-stranded", &["get", item, "--field", "value"]);
        assert_eq!(String::from_utf8_lossy(&after.stdout).trim(), value);
    }
}
