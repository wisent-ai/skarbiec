use super::{fs, Journey};
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};

impl Journey {
    pub(super) fn refused_lock(&mut self, label: &str, pid: &str, host: &str) {
        let lock = self.keyring.join("pubring.kbx.lock");
        let contents = format!("{pid}\n{host}\n");
        fs::write(&lock, &contents).unwrap();
        fs::write(self.root.join(format!("{label}.lock.before")), &contents).unwrap();
        let output = self.skarbiec(label, &["keyring", "recover"]);
        let after = fs::read_to_string(&lock).expect("recovery must preserve the unowned lock");
        assert_eq!(after, contents, "{label} changed the unowned lock");
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        let identity = if pid.is_empty() {
            "names no holder pid"
        } else {
            pid
        };
        assert!(
            diagnostic.contains(lock.to_str().unwrap()) && diagnostic.contains(identity),
            "{label} omitted the observed lock and process identity: {diagnostic}"
        );
        fs::write(self.root.join(format!("{label}.lock.after")), after).unwrap();
        fs::remove_file(lock).unwrap();
    }

    /// A read whose gpg waits on a keyring lock a live process of this host
    /// holds, which gpg alone waits out for tens of minutes. Maintenance
    /// passes run until one replaces the daemons: a run seen before any
    /// status only once is deferred, not judged. The replacement ends the
    /// waiting run, so the read ends refused, naming the holder in gpg's own
    /// words, instead of standing; once the holder is gone the value reads.
    pub(super) fn read_behind_held_lock(&mut self, item: &str, value: &str, node: &str) {
        let mut holder = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("the lock holder starts");
        let mut kill = Command::new("gpgconf");
        kill.args(["--kill", "keyboxd"])
            .env("GNUPGHOME", &self.keyring);
        self.run("held-lock-kill-keyboxd", &mut kill);
        // The lock gpg takes is keyboxd's database lock when the keyring
        // uses keyboxd, and the legacy keybox lock otherwise.
        let lock = match self.keyring.join("public-keys.d").is_dir() {
            true => self.keyring.join("public-keys.d/pubring.db.lock"),
            false => self.keyring.join("pubring.kbx.lock"),
        };
        fs::write(&lock, format!("{}\n{node}\n", holder.id())).unwrap();

        let mut read = self.command(&["get", item, "--field", "value"]);
        read.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut waiting = read.spawn().expect("the read behind the lock starts");
        // The read's gpg must be in flight before a pass looks: a pass with no
        // run to defer on would prove readiness with a canary behind the lock.
        // The read announces the gpg it waits on (`czekam: gpg …`) on its own
        // stderr; a stderr that ends without that line fails the journey.
        let mut said = BufReader::new(waiting.stderr.take().expect("the read's stderr"));
        let mut before = String::new();
        loop {
            let mut line = String::new();
            said.read_line(&mut line)
                .expect("the read's stderr can be read");
            assert!(
                !line.is_empty(),
                "the read ended without starting gpg: {before}"
            );
            before.push_str(&line);
            if line.starts_with("czekam: gpg") {
                break;
            }
        }
        // A keyboxd database lock kept by a process that does not serve the
        // keyboxd socket is plain at first sight, and the first pass replaces
        // the daemons. Otherwise the first pass sees the run before any status
        // and defers, and the second finds it still there and replaces them.
        let mut pass = self.command(&["maintain"]);
        let first =
            String::from_utf8_lossy(&self.observe("held-lock-maintain-first", &mut pass).stderr)
                .into_owned();
        if !(first.contains("replaced the GnuPG daemons")
            && first.contains("does not serve the keyboxd socket"))
        {
            assert!(
                !first.contains("replaced the GnuPG daemons")
                    && first.contains("deferred to the next pass")
                    && first.contains("has written no status"),
                "the first pass neither deferred on the run before any status nor named the orphaned lock: {first}"
            );
            let mut again = self.command(&["maintain"]);
            let second = String::from_utf8_lossy(
                &self.observe("held-lock-maintain-second", &mut again).stderr,
            )
            .into_owned();
            assert!(
                second.contains("replaced the GnuPG daemons") && second.contains("has written no status and was still there"),
                "the second pass did not replace the daemons behind the run that stood; first: {first}; second: {second}"
            );
        }

        let mut rest = String::new();
        said.read_to_string(&mut rest)
            .expect("the rest of the read's stderr");
        let ended = waiting
            .wait_with_output()
            .expect("the read behind the lock ends");
        let refused = format!("{before}{rest}");
        fs::write(self.root.join("held-lock-read.stderr"), &refused).unwrap();
        self.commands
            .push(serde_json::json!({"label": "held-lock-read",
            "exit": ended.status.code(), "status": ended.status.to_string()}));
        self.save();
        assert!(
            !ended.status.success() && refused.contains(&holder.id().to_string()),
            "the read behind the lock did not end naming its holder: {refused}"
        );

        drop(holder.stdin.take());
        holder.wait().expect("the lock holder ends");
        fs::remove_file(&lock).expect("the held lock is removed");
        let after = self.skarbiec("read-after-held-lock", &["get", item, "--field", "value"]);
        assert_eq!(String::from_utf8_lossy(&after.stdout).trim(), value);
    }
}
