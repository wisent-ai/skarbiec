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

/// The stored bearer hash is computed in process, and it is the same hash.
///
/// Verifying a bearer used to spawn `shasum` on EVERY authenticated route,
/// into the bounded pool the gpg decryptions share. This crate's own source
/// records the cost on 2026-09-05: four verifier sweeps reading 48 mapped
/// items made a grant metadata call — which decrypts nothing — take 14.4s,
/// and `GET /readyz` 9.7s. Minting spent `openssl rand` the same way.
///
/// Moving both in process is only safe if the bytes do not change, because
/// every bearer already in a vault was hashed by `shasum`. The oracle is the
/// system's own `shasum`, not a second copy of the implementation, and the
/// bearer is then redeemed through the real broker to prove the stored hash
/// still authenticates.
#[test]
fn the_stored_bearer_hash_is_the_hash_the_system_computes() {
    use std::io::Write;
    use std::process::Stdio;

    let fixture = fixture();
    let issued = mint(&fixture, "read:brama-router#api_key");
    let bearer = issued["token"]
        .as_str()
        .expect("bearer shown once")
        .to_owned();
    assert_eq!(bearer.len(), 64, "a minted bearer is 64 hex characters");

    let mut child = Command::new("shasum")
        .args(["-a", "256", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the system hash is available as an oracle");
    child
        .stdin
        .take()
        .expect("oracle stdin")
        .write_all(bearer.as_bytes())
        .expect("feed the oracle");
    let oracle = child.wait_with_output().expect("the oracle answers");
    let expected = String::from_utf8_lossy(&oracle.stdout)
        .split_whitespace()
        .next()
        .expect("shasum printed a digest")
        .to_string();

    let vault: Value =
        serde_json::from_str(&fs::read_to_string(&fixture.vault).expect("read the vault state"))
            .expect("the vault state is JSON");
    assert_eq!(
        vault["tokens"][CONSUMER]["hash"].as_str(),
        Some(expected.as_str()),
        "the in-process hash differs from the system's, so every bearer stored \
         before today would stop authenticating"
    );

    let broker = fixture.serve();
    let (status, payload) = read_field(
        &broker.url("/v1/items/read"),
        CONSUMER,
        &bearer,
        &format!(r#"{{"id":"{ITEM}","field":"api_key"}}"#),
    );
    assert_eq!(
        status, 200,
        "the stored hash refused its own bearer: {payload}"
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


#[path = "redemption/acquisition.rs"]
mod acquisition;
