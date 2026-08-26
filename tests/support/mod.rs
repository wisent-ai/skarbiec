#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CliFixture {
    pub root: PathBuf,
    pub gnupg: PathBuf,
    pub vault: PathBuf,
}

impl CliFixture {
    pub fn new(area: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        // GnuPG places sockets below GNUPGHOME. Keep this path short enough
        // for macOS AF_UNIX while using the operator-designated scratch root.
        let root = PathBuf::from(env!("HOME"))
            .join(".stado")
            .join("work")
            .join(format!(
                "{area}-{:x}{:08x}",
                std::process::id(),
                unique & 0xffff_ffff
            ));
        let gnupg = root.join("gnupg");
        fs::create_dir_all(&gnupg).expect("create isolated GPG home");
        fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700))
            .expect("protect isolated GPG home");
        Self {
            vault: root.join("vault.json"),
            root,
            gnupg,
        }
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command(args)
            .output()
            .expect("run real skarbiec binary")
    }

    pub fn run_with_vault(&self, vault: &Path, args: &[&str]) -> Output {
        let mut command = self.command(args);
        command.env("SKARBIEC_VAULT_FILE", vault);
        command.output().expect("run real skarbiec binary")
    }

    pub fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start real skarbiec binary");
        child
            .stdin
            .take()
            .expect("open child stdin")
            .write_all(stdin.as_bytes())
            .expect("write command stdin");
        child.wait_with_output().expect("collect command output")
    }

    pub fn init(&self, owner: &str) {
        let output = self.run(&["init", owner]);
        assert_success("initialize isolated vault", &output);
    }

    pub fn assert_vault_exists(&self) {
        assert!(Path::new(&self.vault).is_file(), "vault was not written");
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_skarbiec"));
        command
            .args(args)
            .env("HOME", &self.root)
            .env("GNUPGHOME", &self.gnupg)
            .env("SKARBIEC_VAULT_FILE", &self.vault)
            .env("SKARBIEC_AUDIT_FILE", self.root.join("audit.jsonl"));
        command
    }
}

impl Drop for CliFixture {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", &self.gnupg)
            .args(["--kill", "all"])
            .status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn assert_success(context: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{context} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}
