//! Real native messaging against a directory-selected broker, never the operator's.
use super::support::{assert_success, CliFixture};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn request(root: &Path, token: &Path) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_skarbiec"))
        .arg("native-host")
        .env("HOME", root)
        .env("STADO_FORWARDS_DIR", root.join("forwards"))
        .env("SKARBIEC_BROWSER_TOKEN_FILE", token)
        .env("SKARBIEC_BROWSER_CONSUMER", "native-test")
        .env("SKARBIEC_URL", "http://invalid.invalid:1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let body = serde_json::to_vec(&json!({"action":"fill", "id":"isolated-login"})).unwrap();
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(&u32::try_from(body.len()).unwrap().to_le_bytes())
        .unwrap();
    input.write_all(&body).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    fs::write(root.join("stdout.bin"), &output.stdout).unwrap();
    fs::write(root.join("stderr.log"), &output.stderr).unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout[std::mem::size_of::<u32>()..]).unwrap()
}

fn evidence(name: &str) -> std::path::PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("native-endpoint")
        .join(format!("{name}-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn native_host_refuses_a_missing_directory_endpoint() {
    let root = evidence("missing");
    let reply = request(&root, &root.join("absent-token"));
    assert_eq!(reply["ok"], false);
    assert!(
        reply["error"]
            .as_str()
            .unwrap()
            .contains("SKARBIEC_ENDPOINT_UNRESOLVED"),
        "{reply}"
    );
}

#[test]
fn native_host_reads_the_declared_broker_and_refuses_removed_discovery() {
    let fixture = CliFixture::new("native");
    fixture.init("Native test <native@example.invalid>");
    assert_success(
        "seed login",
        &fixture.run(&[
            "set",
            "isolated-login",
            "username=alice",
            "password=native-test-password",
        ]),
    );
    let issued = fixture.run(&[
        "grant",
        "issue",
        "native-test",
        "--capabilities",
        "read:isolated-login#username,read:isolated-login#password",
    ]);
    assert_success("issue narrow grant", &issued);
    let grant: Value = serde_json::from_slice(&issued.stdout).unwrap();
    let token = fixture.root.join("native-token");
    fs::write(&token, grant["token"].as_str().unwrap()).unwrap();
    let broker = fixture.serve();
    let root = evidence("broker");
    let forwards = root.join("forwards");
    fs::create_dir_all(&forwards).unwrap();
    let marker = forwards.join("skarbiec.local");
    fs::write(&marker, broker.url("")).unwrap();
    let reply = request(&root, &token);
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["username"], "alice");
    assert_eq!(reply["password"], "native-test-password");
    fs::write(
        root.join("success.json"),
        serde_json::to_vec(&reply).unwrap(),
    )
    .unwrap();
    fs::remove_file(marker).unwrap();
    let refused = request(&root, &token);
    assert_eq!(refused["ok"], false);
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("SKARBIEC_ENDPOINT_UNRESOLVED"),
        "{refused}"
    );
    assert!(fixture.vault.is_file());
}
