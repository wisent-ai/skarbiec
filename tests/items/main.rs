use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct CliFixture {
    root: PathBuf,
    gnupg: PathBuf,
    vault: PathBuf,
}

impl CliFixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "skarbiec-cli-items-{}-{unique}",
            std::process::id()
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

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_skarbiec"))
            .args(args)
            .env("HOME", &self.root)
            .env("GNUPGHOME", &self.gnupg)
            .env("SKARBIEC_VAULT_FILE", &self.vault)
            .env("SKARBIEC_AUDIT_FILE", self.root.join("audit.jsonl"))
            .output()
            .expect("run real skarbiec binary")
    }

    fn seed_login(&self) {
        let init = self.run(&[
            "init",
            "Skarbiec CLI test <skarbiec-cli-test@example.invalid>",
        ]);
        assert_success("init fixture vault", &init);

        let set = self.run(&[
            "set",
            "example-login",
            "--type",
            "login",
            "username=reader@example.invalid",
            "password=correct-horse-battery-staple",
        ]);
        assert_success("seed fixture item", &set);
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

fn assert_success(context: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{context} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}

#[test]
fn get_reads_one_exact_field_and_refuses_unknown_paths() {
    let fixture = CliFixture::new();
    fixture.seed_login();

    let read = fixture.run(&["get", "example-login", "--field", "password"]);
    assert_success("read one exact field", &read);
    assert_eq!(
        String::from_utf8_lossy(&read.stdout),
        "correct-horse-battery-staple\n"
    );

    let unknown_field = fixture.run(&["get", "example-login", "--field", "missing"]);
    assert_eq!(unknown_field.status.code(), Some(1));
    assert_eq!(
        stderr(&unknown_field),
        "Error: item example-login has no field missing"
    );

    let unknown_item = fixture.run(&["get", "missing", "--field", "password"]);
    assert_eq!(unknown_item.status.code(), Some(1));
    assert_eq!(stderr(&unknown_item), "Error: no item: missing");

    assert!(Path::new(&fixture.vault).is_file());
}
