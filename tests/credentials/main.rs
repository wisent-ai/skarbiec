use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

struct CliFixture {
    root: PathBuf,
    gnupg: PathBuf,
    vault: PathBuf,
    bridge: PathBuf,
    request: PathBuf,
}

impl CliFixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        let root = PathBuf::from("/private/tmp").join(format!(
            "sbc{:x}{:08x}",
            std::process::id(),
            unique & 0xffff_ffff
        ));
        let gnupg = root.join("gnupg");
        fs::create_dir_all(&gnupg).expect("create isolated GPG home");
        fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700))
            .expect("protect isolated GPG home");

        let request = root.join("weles-request.json");
        let bridge = root.join("weles-credential-bridge");
        let script = format!(
            "#!/bin/sh\ncat > '{}'\nprintf '%s\\n' '{{\"status\":\"operation_plan\",\"operation\":\"acquire\",\"provider\":\"openrouter\",\"vaultItemId\":\"openrouter\"}}'\n",
            request.display()
        );
        fs::write(&bridge, script).expect("write isolated Weles protocol fixture");
        fs::set_permissions(&bridge, fs::Permissions::from_mode(0o700))
            .expect("protect isolated Weles protocol fixture");

        Self {
            vault: root.join("vault.json"),
            root,
            gnupg,
            bridge,
            request,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_skarbiec"))
            .args(args)
            .env("HOME", &self.root)
            .env("GNUPGHOME", &self.gnupg)
            .env("SKARBIEC_VAULT_FILE", &self.vault)
            .env("SKARBIEC_AUDIT_FILE", self.root.join("audit.jsonl"))
            .env("SKARBIEC_WELES_CREDENTIAL_COMMAND", &self.bridge)
            .output()
            .expect("run real skarbiec binary")
    }

    fn init(&self) {
        let output = self.run(&[
            "init",
            "Skarbiec credential test <skarbiec-credential-test@example.invalid>",
        ]);
        assert_success("init fixture vault", &output);
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
fn acquire_plans_one_missing_generic_credential_and_refuses_malformed_origins() {
    let fixture = CliFixture::new();
    fixture.init();

    let planned = fixture.run(&[
        "credential",
        "acquire",
        "openrouter",
        "--provider",
        "openrouter",
        "--consumer",
        "design-assets",
        "--purpose",
        "read approved design assets",
        "--signup-origin",
        "https://openrouter.ai",
        "--dry-run",
        "--local",
    ]);
    assert_success("plan missing generic credential acquisition", &planned);
    let response: Value = serde_json::from_slice(&planned.stdout).expect("parse command response");
    assert_eq!(response.get("ok"), Some(&Value::Bool(true)));
    assert_eq!(response["operation"], "acquire");
    assert_eq!(response["credential"], "openrouter");
    assert_eq!(response["weles"]["status"], "operation_plan");

    let request: Value = serde_json::from_slice(
        &fs::read(&fixture.request).expect("read the request sent to the Weles bridge"),
    )
    .expect("parse the request sent to the Weles bridge");
    assert_eq!(request["mode"], "submit");
    assert_eq!(request["operation"], "acquire");
    assert_eq!(request["credential_id"], "openrouter");
    assert_eq!(request["provider"], "openrouter");
    assert_eq!(request["consumer"], "design-assets");
    assert_eq!(request["purpose"], "read approved design assets");
    assert_eq!(request["signup_origin"], "https://openrouter.ai");
    assert_eq!(request["field"], "api_key");
    assert_eq!(request["dry_run"], true);

    let absent = fixture.run(&["get", "openrouter", "--field", "api_key"]);
    assert_eq!(absent.status.code(), Some(1));
    assert_eq!(stderr(&absent), "Error: no item: openrouter");

    let malformed_origin = fixture.run(&[
        "credential",
        "acquire",
        "openrouter",
        "--provider",
        "openrouter",
        "--consumer",
        "design-assets",
        "--signup-origin",
        "https://openrouter.ai/signup?source=test",
        "--dry-run",
        "--local",
    ]);
    assert_eq!(malformed_origin.status.code(), Some(1));
    assert_eq!(
        stderr(&malformed_origin),
        "Error: --signup-origin must be https://<host>[:<port>]: an absolute https origin, lowercase host, no userinfo, path, query or fragment"
    );
}
