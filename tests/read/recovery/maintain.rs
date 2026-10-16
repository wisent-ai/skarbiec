//! `skarbiec maintain` recovers a gpg-agent that accepts and never answers.
//! The agent socket of the isolated keyring is replaced by the same stand-in
//! the stranded journey uses: the gpg child of a waiting `skarbiec get` is
//! accepted and never answered, every other connection is answered. With
//! that read's only run waiting on the agent, the maintenance pass has to
//! replace the daemons, say why on stderr, journal a `daemon-recover` row in
//! the vault's audit file, end the waiting read, and leave the value readable
//! once the stand-in is gone.
use super::stranded::{answer, parent, peer};
use super::{fs, Journey};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;

impl Journey {
    pub(super) fn maintain_recovers_silent_agent(&mut self, item: &str, value: &str) {
        let mut directories = Command::new("gpgconf");
        directories
            .args(["--list-dirs", "agent-socket"])
            .env("GNUPGHOME", &self.keyring);
        let socket = self.run("maintain-agent-socket", &mut directories);
        let socket = std::path::PathBuf::from(String::from_utf8(socket.stdout).unwrap().trim());
        let mut kill = Command::new("gpgconf");
        kill.args(["--kill", "gpg-agent"])
            .env("GNUPGHOME", &self.keyring);
        self.run("maintain-kill-real-agent", &mut kill);
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
                    held.send((pid, stream))
                        .expect("the test holds the silent agent's caller");
                } else {
                    std::thread::spawn(move || answer(stream));
                }
            }
        });
        let (child, _connection) = stranded.recv().expect("the read's gpg reaches the agent");
        fs::write(
            self.root.join("maintain-waiting-child.pid"),
            child.to_string(),
        )
        .unwrap();

        let maintained = self.skarbiec("maintain-silent-agent", &["maintain"]);
        let said = String::from_utf8_lossy(&maintained.stderr);
        assert!(
            said.contains("skarbiec maintain: replaced the GnuPG daemons")
                && said.contains("asked gpg-agent for its key without an answer"),
            "maintain did not recover the silent agent: {said}"
        );
        let journal = fs::read_to_string(self.root.join("audit.jsonl")).expect("the audit file");
        let recovered = journal
            .lines()
            .find(|line| line.contains("daemon-recover"))
            .expect("maintain journaled no daemon-recover row");
        assert!(
            recovered.contains(&format!("pid {child}")),
            "the journal row does not name the waiting gpg run: {recovered}"
        );

        let ended = waiting.wait_with_output().expect("the waiting read ends");
        fs::write(self.root.join("maintain-read.stderr"), &ended.stderr).unwrap();
        self.commands
            .push(serde_json::json!({"label": "maintain-waiting-read",
            "exit": ended.status.code(), "status": ended.status.to_string()}));
        self.save();
        assert!(
            !ended.status.success(),
            "the read whose gpg was ended reported success"
        );

        fs::remove_file(&socket).expect("the stand-in socket is removed");
        let after = self.skarbiec("read-after-maintain", &["get", item, "--field", "value"]);
        assert_eq!(String::from_utf8_lossy(&after.stdout).trim(), value);
    }
}
