//! What a declared grant actually lets a caller do: read the field it names,
//! redeem an acquisition, and resolve one mapped capability resource.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

use crate::fixture::{fixture, mint, CONSUMER, ITEM};
use crate::support::{assert_success, stderr, CliFixture};

/// The bearer a declared grant hands back is the one the serving path
/// accepts, and revoking the declaration stops that same read.
///
/// A capability row in the vault is a weaker claim than a read that succeeds:
/// the broker matches the presented bearer, resolves the item and consults the
/// credential lifecycle, so this drives the real route rather than asserting
/// that a row was written.
#[test]
fn a_declared_grant_reads_the_field_it_names_until_it_is_revoked() {
    let fixture = fixture();
    let issued = mint(&fixture, "read:brama-router#api_key");
    let bearer = issued["token"]
        .as_str()
        .expect("bearer shown once")
        .to_owned();
    let broker = fixture.serve();
    let url = broker.url("/v1/items/read");
    let body = format!(r#"{{"id":"{ITEM}","field":"api_key"}}"#);

    let (status, payload) = read_field(&url, CONSUMER, &bearer, &body);
    assert_eq!(status, 200, "the declared read was refused: {payload}");
    assert!(payload.contains("sekret-123"), "read returned {payload}");

    assert_success(
        "revoke the declaration",
        &fixture.run(&["grant", "revoke", CONSUMER]),
    );
    let (status, payload) = read_field(&url, CONSUMER, &bearer, &body);
    assert_eq!(status, 403, "a revoked grant still read: {payload}");
    assert!(
        payload.contains("consumer not authorized to read item field"),
        "refusal was {payload}"
    );
}

fn read_field(url: &str, consumer: &str, bearer: &str, body: &str) -> (u32, String) {
    let output = Command::new("curl")
        .args([
            "-s",
            "-m",
            "60",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            "-X",
            "POST",
            url,
            "-H",
            &format!("X-Consumer: {consumer}"),
            "-H",
            &format!("Authorization: Bearer {bearer}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
        ])
        .output()
        .expect("run curl");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let (payload, status) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (
        status.trim().parse().unwrap_or_default(),
        payload.to_string(),
    )
}

/// An acquire declaration hands out no bearer at all, and states how it is
/// spent.
///
/// This is what `invite` was for: the operator who declares one holds nothing,
/// so the contract has to arrive with the declaration or not at all.
#[test]
fn an_acquire_grant_returns_no_bearer_and_states_its_redemption() {
    let fixture = fixture();
    let key = fixture.root.join("workload.pub.pem");
    write_workload_key(&fixture, &key);
    let path = key.to_str().expect("utf-8 key path");

    let output = fixture.run(&[
        "grant",
        "issue",
        "probe-workload",
        "--capabilities",
        "acquire:brama-router#api_key",
        "--workload-public-key-file",
        path,
    ]);
    assert_success("declare one workload-bound acquire grant", &output);
    let declared: Value = serde_json::from_slice(&output.stdout).expect("parse issue response");
    assert_eq!(declared["workload_bound"], true);
    assert_eq!(
        declared["token"],
        Value::Null,
        "an acquire grant hands out no standing bearer"
    );
    assert_eq!(declared["redeem"][0]["item"], ITEM);
    assert_eq!(declared["redeem"][0]["field"], "api_key");
    assert!(declared["redeem"][0]["how"]
        .as_str()
        .expect("redemption sentence")
        .contains("skarbiec acquisition-request probe-workload brama-router api_key"));

    // No key, no acquire declaration; and a key with nothing to acquire is
    // refused from the other side.
    let output = fixture.run(&[
        "grant",
        "issue",
        "keyless",
        "--capabilities",
        "acquire:brama-router#api_key",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("acquire capabilities require --workload-public-key-file"));
    let output = fixture.run(&[
        "grant",
        "issue",
        "direct",
        "--capabilities",
        "read:brama-router#api_key",
        "--workload-public-key-file",
        path,
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("workload public keys are valid only for acquire capabilities")
    );
}

fn write_workload_key(fixture: &CliFixture, public: &Path) {
    let private = fixture.root.join("workload.pem");
    let generated = Command::new("openssl")
        .args(["genpkey", "-algorithm", "ed25519", "-out"])
        .arg(&private)
        .status()
        .expect("run openssl genpkey");
    assert!(generated.success(), "openssl generated no Ed25519 key");
    let derived = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&private)
        .args(["-pubout", "-out"])
        .arg(public)
        .status()
        .expect("run openssl pkey");
    assert!(derived.success(), "openssl derived no public half");
    fs::set_permissions(public, fs::Permissions::from_mode(0o600))
        .expect("protect the workload public key");
}

/// `grant capability` issues one bounded redemption of a declaration that
/// already exists, and refuses at issue time rather than at redemption.
#[test]
fn grant_capability_refuses_an_unmapped_resource_and_issues_a_mapped_one() {
    let fixture = fixture();
    mint(&fixture, "read:brama-router#api_key");

    let output = fixture.run(&[
        "grant",
        "capability",
        "--agent",
        CONSUMER,
        "--purpose",
        "declared-grant-test",
        "--target",
        "demo",
        "--resource",
        "provider:unmapped",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains(
        "grant capability refused for provider:unmapped: nothing declares provider:unmapped and no capability route names it"
    ));

    assert_success(
        "declare the resource on the item that answers it",
        &fixture.run(&["retag", ITEM, "--tags=brama:provider:demo"]),
    );
    let output = fixture.run(&[
        "grant",
        "capability",
        "--agent",
        CONSUMER,
        "--purpose",
        "declared-grant-test",
        "--target",
        "demo",
        "--resource",
        "provider:demo",
    ]);
    assert_success("issue one bounded redemption", &output);
    let issued: Value = serde_json::from_slice(&output.stdout).expect("parse capability response");
    assert_eq!(issued["status"], "issued");
    assert_eq!(
        issued["capability_id"]
            .as_str()
            .expect("capability id")
            .len(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".len()
    );

    // The group owns its namespace: a subcommand it does not carry is refused
    // by name instead of falling through to another dispatcher.
    let output = fixture.run(&["grant", "__surface_probe__"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown grant command: __surface_probe__"));
}

/// Widening a declaration that was never written is refused by that name.
#[test]
fn grant_ensure_refuses_a_consumer_with_no_declaration() {
    let fixture = fixture();
    let bearer_file = fixture.root.join("absent.txt");
    fs::write(&bearer_file, "deadbeef").expect("write bearer file");
    fs::set_permissions(&bearer_file, fs::Permissions::from_mode(0o600))
        .expect("protect bearer file");
    let output = fixture.run(&[
        "grant",
        "ensure",
        "nobody",
        ITEM,
        "--field",
        "api_key",
        "--token-file",
        bearer_file.to_str().expect("utf-8 bearer path"),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("consumer has no existing grant"));
}
