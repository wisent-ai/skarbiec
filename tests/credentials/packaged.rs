use crate::support::{assert_success, CliFixture};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create packaged bridge directory");
    for entry in fs::read_dir(source).expect("read immutable bridge input") {
        let entry = entry.expect("read bridge input entry");
        let target = destination.join(entry.file_name());
        let kind = entry.file_type().expect("read bridge entry type");
        assert!(
            !kind.is_symlink(),
            "release bridge input must not contain links"
        );
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy real release bridge input");
        }
    }
}

#[test]
#[ignore = "requires the WISENT_INPUT_WELES_CLIENT_DIR build input"]
fn installed_symlink_uses_packaged_bridge_and_persists_missing_authority() {
    let input = std::env::var_os("WISENT_INPUT_WELES_CLIENT_DIR")
        .expect("the actual Weles client build input is required");
    let input = Path::new(&input);
    let input = if input.join("package").is_dir() {
        input.join("package")
    } else {
        input.to_path_buf()
    };
    let source = Path::new(env!("CARGO_MANIFEST_DIR"));
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let evidence = source
        .join("target/credential-bridge-tests")
        .join(unique.to_string());
    let release = evidence.join("release");
    fs::create_dir_all(release.join("bin")).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_skarbiec"), release.join("bin/skarbiec")).unwrap();
    let packaged = release.join("share/skarbiec/weles-client");
    for member in ["bin", "src"] {
        copy_tree(&input.join(member), &packaged.join(member));
    }
    for member in ["package.json", "LICENSE"] {
        fs::copy(input.join(member), packaged.join(member)).unwrap();
    }
    let installed = evidence.join("skarbiec");
    symlink(release.join("bin/skarbiec"), &installed).unwrap();

    let fixture = CliFixture::new("bridge");
    fixture.init("Skarbiec bridge test <bridge@example.invalid>");
    let args = [
        "credential",
        "acquire",
        "winston",
        "--provider",
        "winston",
        "--consumer",
        "winston-writer",
        "--signup-origin",
        "https://dev.gowinston.ai",
        "--local",
    ];
    let mut command = Command::new(&installed);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SKARBIEC_") {
            command.env_remove(key);
        }
    }
    let output = command
        .args(args)
        .env("HOME", &fixture.root)
        .env("GNUPGHOME", &fixture.gnupg)
        .env("SKARBIEC_VAULT_FILE", &fixture.vault)
        .env("SKARBIEC_AUDIT_FILE", fixture.root.join("audit.jsonl"))
        .env("STADO_FORWARDS_DIR", evidence.join("missing-forwards"))
        .output()
        .expect("invoke installed Skarbiec with its real bridge");
    fs::write(evidence.join("stdout.json"), &output.stdout).unwrap();
    fs::write(evidence.join("stderr.txt"), &output.stderr).unwrap();
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(source)
        .output()
        .unwrap();
    fs::write(
        evidence.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "revision": std::env::var("WISENT_SOURCE_COMMIT").ok()
                .unwrap_or_else(|| String::from_utf8_lossy(&revision.stdout).trim().to_string()),
            "program": installed, "args": args, "exit_status": output.status.code(),
            "bridge_input": input,
            "claim": "Real packaged bridge discovery and persisted refusal; no provider acquisition"
        }))
        .unwrap(),
    )
    .unwrap();
    println!("Packaged bridge evidence: {}", evidence.display());
    assert_success("read the real bridge refusal", &output);
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["status"], "needs_configuration");
    assert_eq!(response["weles"]["code"], "WELES_ENDPOINT_UNRESOLVED");
    let status = fixture.run(&["credential", "status", "winston", "--local"]);
    fs::write(evidence.join("status.json"), &status.stdout).unwrap();
    assert_success("read the persisted acquisition refusal", &status);
    let persisted: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(persisted["status"], "needs_configuration");
    assert!(!fixture
        .run(&["get", "winston", "--field", "api_key"])
        .status
        .success());
    fs::remove_dir_all(release).unwrap();
    fs::remove_file(installed).unwrap();
}
