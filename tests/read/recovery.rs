//! Real recovery and ownership refusals. Run on an isolated OS account only:
//! recover-daemons can control account-wide GnuPG daemons. Requires SKARBIEC
//! and SKARBIEC_TEST_SOURCE_REVISION; reports and isolated data stay in target.
use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::{Command, Output}, time::{SystemTime, UNIX_EPOCH}};
use std::os::unix::fs::DirBuilderExt;

#[path = "../../src/core/crypto/execution/lock_holder/process_identity.rs"]
mod process_identity;

struct Journey {
    root: PathBuf,
    keyring: PathBuf,
    binary: PathBuf,
    revision: String,
    commands: Vec<Value>,
    active: bool,
    passed: bool,
}

impl Journey {
    fn save(&self) {
        let report = json!({"revision": self.revision, "binary": self.binary,
            "commands": self.commands, "passed": self.passed});
        fs::write(self.root.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }

    fn run(&mut self, label: &str, command: &mut Command) -> Output {
        let output = match command.output() {
            Ok(output) => output,
            Err(error) => {
                self.commands.push(json!({"label": label, "error": error.to_string()}));
                self.save();
                panic!("{label}: {error}");
            }
        };
        fs::write(self.root.join(format!("{label}.stdout")), &output.stdout).unwrap();
        fs::write(self.root.join(format!("{label}.stderr")), &output.stderr).unwrap();
        self.commands.push(json!({"label": label,
            "program": command.get_program().to_string_lossy(),
            "args": command.get_args().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>(),
            "exit": output.status.code(), "status": output.status.to_string()}));
        self.save();
        assert!(output.status.success(), "{label}: {}", String::from_utf8_lossy(&output.stderr));
        output
    }

    fn skarbiec(&mut self, label: &str, args: &[&str]) -> Output {
        let mut command = Command::new(&self.binary);
        command.args(args).env("GNUPGHOME", &self.keyring)
            .env("SKARBIEC_VAULT_FILE", self.root.join("vault.json"))
            .env("SKARBIEC_AUDIT_FILE", self.root.join("audit.jsonl"));
        self.run(label, &mut command)
    }

    fn refused_lock(&mut self, label: &str, pid: &str, host: &str) {
        let lock = self.keyring.join("pubring.kbx.lock");
        let contents = format!("{pid}\n{host}\n");
        fs::write(&lock, &contents).unwrap();
        fs::write(self.root.join(format!("{label}.lock.before")), &contents).unwrap();
        let output = self.skarbiec(label, &["recover-daemons"]);
        let after = fs::read_to_string(&lock).expect("recovery must preserve the unowned lock");
        assert_eq!(after, contents, "{label} changed the unowned lock");
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains(lock.to_str().unwrap()) && diagnostic.contains(pid),
            "{label} omitted the observed lock and process identity: {diagnostic}");
        fs::write(self.root.join(format!("{label}.lock.after")), after).unwrap();
        fs::remove_file(lock).unwrap();
    }
}

impl Drop for Journey {
    fn drop(&mut self) {
        if self.active {
            let lock = self.keyring.join("pubring.kbx.lock");
            if lock.exists() { fs::remove_file(lock).unwrap(); }
            match Command::new("gpgconf").arg("--homedir").arg(&self.keyring)
                .args(["--kill", "all"]).output() {
                Ok(output) => {
                    fs::write(self.root.join("cleanup.stdout"), output.stdout).unwrap();
                    fs::write(self.root.join("cleanup.stderr"), output.stderr).unwrap();
                    self.commands.push(json!({"label": "cleanup", "program": "gpgconf",
                        "args": ["--homedir", self.keyring.to_str().unwrap(), "--kill", "all"],
                        "exit": output.status.code(), "status": output.status.to_string()}));
                    self.passed &= output.status.success();
                }
                Err(error) => {
                    self.passed = false;
                    self.commands.push(json!({"label": "cleanup", "error": error.to_string()}));
                }
            }
            fs::remove_dir_all(&self.keyring).unwrap();
        }
        self.save();
        if !std::thread::panicking() {
            assert!(self.passed, "recovery journey failed; inspect {}", self.root.display());
        }
    }
}

fn source_revision() -> String {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let revision = std::env::var("SKARBIEC_TEST_SOURCE_REVISION").expect("set candidate revision");
    let head = Command::new("git").args(["rev-parse", "HEAD"]).current_dir(&repo).output().unwrap();
    assert!(head.status.success());
    assert_eq!(String::from_utf8_lossy(&head.stdout).trim(), revision);
    let clean = Command::new("git").args(["status", "--porcelain"]).current_dir(&repo).output().unwrap();
    assert!(clean.status.success() && clean.stdout.is_empty(), "candidate source must be clean");
    revision
}

#[test]
#[ignore = "requires an isolated OS account, SKARBIEC and SKARBIEC_TEST_SOURCE_REVISION"]
fn recovery_preserves_values_and_refuses_unowned_locks() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = fs::canonicalize(std::env::var_os("SKARBIEC").expect("set SKARBIEC")).unwrap();
    let revision = source_revision();
    let run = format!("{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
    let root = repo.join("target/real-tests/recovery").join(&run);
    fs::DirBuilder::new().recursive(true).mode(libc::S_IRWXU.into()).create(&root).unwrap();
    let keyring = repo.join("target").join(format!("g{}", std::process::id()));
    let mut journey = Journey { root, keyring, binary, revision,
        commands: Vec::new(), active: false, passed: false };
    let mut version = Command::new(&journey.binary);
    journey.run("version", version.arg("--version"));
    let components = journey.run("components", Command::new("gpgconf").arg("--list-components"));
    let components = String::from_utf8(components.stdout).unwrap();
    let programs = components.lines().map(|line| {
        let mut fields = line.split(':');
        let _name = fields.next();
        let _description = fields.next();
        let program = fields.next().expect("gpgconf program field");
        assert!(!program.is_empty(), "component has no executable: {line}");
        PathBuf::from(percent_encoding::percent_decode_str(program).decode_utf8().unwrap().as_ref())
    }).collect::<Vec<_>>();
    let uid = journey.run("uid", Command::new("id").arg("-u"));
    let uid = String::from_utf8(uid.stdout).unwrap();
    let processes = journey.run("processes", Command::new("ps").args(["-u", uid.trim(), "-o", "comm="]));
    for running in String::from_utf8_lossy(&processes.stdout).lines() {
        let executable = PathBuf::from(running.trim());
        assert!(!programs.iter().any(|program| program.file_name() == executable.file_name()),
            "account already runs {running}; use an isolated OS account");
    }
    fs::DirBuilder::new().mode(libc::S_IRWXU.into()).create(&journey.keyring).unwrap();
    journey.active = true;
    fs::write(journey.keyring.join("common.conf"), "").unwrap();
    let owner = format!("recovery-owner-{run}");
    let item = format!("recovery-item-{run}");
    let value = format!("recovery-value-{run}");
    journey.skarbiec("init", &["init", &owner]);
    journey.skarbiec("set", &["set", &item, "--type", "note", &format!("value={value}")]);
    journey.skarbiec("recover", &["recover-daemons"]);
    let before = journey.skarbiec("read-before", &["get", &item, "--field", "value"]);
    assert_eq!(String::from_utf8_lossy(&before.stdout).trim(), value);
    let node = journey.run("node", Command::new("uname").arg("-n"));
    let node = String::from_utf8(node.stdout).unwrap();
    let pid = std::process::id().to_string();
    journey.refused_lock("foreign-host", &pid, &format!("{run}.foreign"));
    journey.refused_lock("invalid-pid", "invalid-process", node.trim());
    journey.refused_lock("other-executable", &pid, node.trim());
    let after = journey.skarbiec("read-after", &["get", &item, "--field", "value"]);
    assert_eq!(String::from_utf8_lossy(&after.stdout).trim(), value);
    journey.passed = true;
}

/// A pipe reader is a real process that stays alive until its owned input
/// closes. Cleanup never signals a process this test did not create.
struct OwnedReader(std::process::Child);

impl OwnedReader {
    fn spawn() -> Self {
        Self(Command::new("cat").stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null()).spawn().expect("start pipe reader"))
    }
}

impl Drop for OwnedReader {
    fn drop(&mut self) {
        if self.0.try_wait().expect("inspect owned reader").is_none() {
            self.0.kill().expect("stop owned reader");
            self.0.wait().expect("reap owned reader");
        }
    }
}

#[test]
#[ignore = "requires the authorized real qualification stage"]
fn process_identity_signals_its_target_and_refuses_a_dead_handle() {
    use std::os::unix::process::ExitStatusExt;
    let revision = source_revision();
    let mut first = OwnedReader::spawn();
    let pid = libc::pid_t::try_from(first.0.id()).unwrap();
    let mut identity = process_identity::Identity::open(pid).expect("bind actual process lifetime");
    let executable = identity.executable().expect("inspect identity-qualified executable");
    let sent = identity.terminate();
    assert!(sent.is_ok(), "identity-qualified SIGTERM: {sent:?}");
    let exited = first.0.wait().expect("reap signaled process");
    let mut second = OwnedReader::spawn();
    let stale = identity.terminate();
    let survivor = second.0.try_wait().expect("inspect unrelated owned process");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/real-tests/recovery")
        .join(format!("identity-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("report.json"), serde_json::to_vec_pretty(&json!({
        "source_revision": revision,
        "target_pid": pid, "executable": executable,
        "target_exit": exited.to_string(), "target_signal": exited.signal(),
        "stale_identity_error": stale.as_ref().err(), "other_pid": second.0.id(),
        "other_exit": survivor.map(|status| status.to_string()),
    })).unwrap()).unwrap();
    assert_eq!(exited.signal(), Some(libc::SIGTERM));
    assert!(stale.is_err(), "a dead process identity must not accept a signal");
    assert!(survivor.is_none(), "signaling the old identity affected another process");
}
