//! Certificate chains OpenSSL made (tests/vectors/x509/make.sh), checked the
//! way the TLS client checks a server's: the chains a CA would issue are
//! accepted with each signature algorithm, and each fault is refused naming
//! what is wrong.

use skarbiec_crypto::x509::{verify_server_chain, Anchor, Certificate, SubjectKey};
use std::path::PathBuf;

fn der(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/x509")
        .join(format!("{name}.der"));
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn anchors() -> Vec<Anchor> {
    ["root-rsa", "root-ed25519"]
        .iter()
        .map(|name| Anchor::from_der(&der(name)).expect(name))
        .collect()
}

/// 2030-01-01T00:00:00Z, inside every fixture's 2000–2099 validity.
const NOW: i64 = 1_893_456_000;

fn check(chain: &[&str], host: &str, now: i64) -> Result<SubjectKey, String> {
    let chain: Vec<Vec<u8>> = chain.iter().map(|name| der(name)).collect();
    verify_server_chain(&chain, &anchors(), host, now).map_err(|error| error.to_string())
}

fn refused(chain: &[&str], host: &str, now: i64, says: &str) {
    match check(chain, host, now) {
        Ok(_) => panic!("{chain:?} for {host} was accepted; it should be refused with {says:?}"),
        Err(error) => assert!(error.contains(says), "{chain:?}: {error}"),
    }
}

#[test]
fn chains_a_ca_issues_are_accepted() {
    // RSA root → P-256 intermediate (sha256WithRSA) → P-384 leaf
    // (ecdsa-with-SHA384).
    let key = check(&["leaf-p384", "inter-p256"], "host.test", NOW).expect("rsa/ecdsa chain");
    assert!(matches!(key, SubjectKey::P384 { .. }));
    // The intermediate sent out of order, and a root sent along, change nothing.
    check(&["leaf-p384", "root-rsa", "inter-p256"], "host.test", NOW).expect("root sent along");
    // Ed25519 root → RSA leaf.
    let key = check(&["leaf-ed25519"], "host.test", NOW).expect("ed25519 chain");
    assert!(matches!(key, SubjectKey::Rsa { .. }));
}

#[test]
fn the_leaf_must_name_the_host() {
    check(&["leaf-p384", "inter-p256"], "HOST.test.", NOW).expect("case and a trailing dot");
    check(&["leaf-p384", "inter-p256"], "a.wild.test", NOW).expect("a wildcard covers one label");
    check(&["leaf-p384", "inter-p256"], "127.0.0.1", NOW).expect("an IP address entry");
    refused(
        &["leaf-p384", "inter-p256"],
        "other.test",
        NOW,
        "does not name other.test",
    );
    refused(
        &["leaf-p384", "inter-p256"],
        "a.b.wild.test",
        NOW,
        "does not name a.b.wild.test",
    );
    refused(
        &["leaf-p384", "inter-p256"],
        "wild.test",
        NOW,
        "does not name wild.test",
    );
    refused(
        &["leaf-p384", "inter-p256"],
        "127.0.0.2",
        NOW,
        "does not name 127.0.0.2",
    );
}

#[test]
fn time_outside_validity_is_refused() {
    // 1999-12-31 and 2100-01-01.
    refused(
        &["leaf-p384", "inter-p256"],
        "host.test",
        946_684_799,
        "is not valid yet",
    );
    refused(
        &["leaf-p384", "inter-p256"],
        "host.test",
        4_102_444_800,
        "expired",
    );
}

#[test]
fn broken_chains_are_refused() {
    refused(&[], "host.test", NOW, "sent no certificate");
    refused(
        &["leaf-p384"],
        "host.test",
        NOW,
        "nor among the certificates the server sent",
    );
    refused(
        &["leaf-under-notca", "inter-notca"],
        "host.test",
        NOW,
        "is not a CA",
    );
    refused(
        &["leaf-deep", "inter-deep", "inter-p256"],
        "host.test",
        NOW,
        "pathLenConstraint",
    );
    refused(
        &["leaf-client", "inter-p256"],
        "host.test",
        NOW,
        "lacks serverAuth",
    );
    refused(
        &["leaf-critical", "inter-p256"],
        "host.test",
        NOW,
        "critical",
    );
    // One flipped bit of the signature: the issuer is named, but did not sign it.
    let mut forged = der("leaf-p384");
    let last = forged.len() - 3;
    forged[last] ^= 1;
    let error = verify_server_chain(&[forged, der("inter-p256")], &anchors(), "host.test", NOW)
        .expect_err("a forged signature");
    assert!(
        error
            .to_string()
            .contains("no certificate of that name signed it"),
        "{error}"
    );
}

#[test]
fn malformed_der_is_refused_never_panics() {
    let whole = der("leaf-p384");
    for length in 0..whole.len() {
        assert!(
            Certificate::from_der(&whole[..length]).is_err(),
            "cut to {length} bytes"
        );
    }
    let mut trailing = whole.clone();
    trailing.push(0);
    assert!(Certificate::from_der(&trailing).is_err());
    // Every single-byte change is read or refused, never a panic; a change
    // the reader accepts (a byte of a key or a name) still reads a key.
    let mut accepted = 0;
    for index in 0..whole.len() {
        let mut changed = whole.clone();
        changed[index] ^= 0xff;
        if let Ok(certificate) = Certificate::from_der(&changed) {
            assert!(certificate.not_after() > 0);
            accepted += 1;
        }
    }
    assert!(accepted < whole.len(), "every change was accepted");
}
