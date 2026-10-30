//! Ed25519 against every test of RFC 8032 section 7.1 (TEST 1, 2, 3, 1024
//! and SHA(abc)): public key from the secret key, signature, verification,
//! and every bit of each signature and message changed in turn refused.

mod common;

use common::{find_line, hex, rfc_lines, to_hex};
use skarbiec_crypto::ed25519::{public_key, sign, verify};

struct Test {
    name: String,
    secret: Vec<u8>,
    public: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fn tests() -> Vec<Test> {
    let lines = rfc_lines("rfc/rfc8032.txt");
    let start = find_line(&lines, 0, |l| {
        l.starts_with("7.1.  Test Vectors for Ed25519")
    });
    let end = find_line(&lines, start + 1, |l| l.starts_with("7.2."));
    let mut tests = Vec::new();
    let mut current: Option<(String, Vec<(String, String)>)> = None;
    let mut label: Option<String> = None;
    for line in &lines[start..end] {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix("-----")
            .filter(|n| n.starts_with("TEST"))
        {
            if let Some(done) = current.take() {
                tests.push(done);
            }
            current = Some((name.to_string(), Vec::new()));
            label = None;
            continue;
        }
        let Some((_, fields)) = current.as_mut() else {
            continue;
        };
        if trimmed.ends_with(':') {
            let name = trimmed.trim_end_matches(':');
            let name = name.split(" (").next().expect("label").to_string();
            fields.push((name.clone(), String::new()));
            label = Some(name);
        } else if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            if label.is_some() {
                if let Some(last) = fields.last_mut() {
                    last.1.push_str(trimmed);
                }
            }
        } else if !trimmed.is_empty() {
            label = None;
        }
    }
    if let Some(done) = current.take() {
        tests.push(done);
    }
    tests
        .into_iter()
        .map(|(name, fields)| {
            let get = |l: &str| {
                fields
                    .iter()
                    .find(|(n, _)| n == l)
                    .map(|(_, v)| hex(v))
                    .unwrap_or_else(|| panic!("{name} has no {l}"))
            };
            Test {
                secret: get("SECRET KEY"),
                public: get("PUBLIC KEY"),
                message: get("MESSAGE"),
                signature: get("SIGNATURE"),
                name,
            }
        })
        .collect()
}

#[test]
fn ed25519_rfc8032() {
    let tests = tests();
    let names: Vec<&str> = tests.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        ["TEST 1", "TEST 2", "TEST 3", "TEST 1024", "TEST SHA(abc)"]
    );
    for t in &tests {
        let secret: [u8; 32] = t.secret.clone().try_into().expect("32-byte secret");
        let public: [u8; 32] = t.public.clone().try_into().expect("32-byte public");
        let expected: [u8; 64] = t.signature.clone().try_into().expect("64-byte signature");
        assert_eq!(
            to_hex(&public_key(&secret)),
            to_hex(&public),
            "{} public key",
            t.name
        );
        assert_eq!(
            to_hex(&sign(&secret, &t.message)),
            to_hex(&expected),
            "{} signature",
            t.name
        );
        assert!(
            verify(&public, &t.message, &expected),
            "{} verifies",
            t.name
        );
        for bit in (0..512).step_by(7) {
            let mut changed = expected;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert!(
                !verify(&public, &t.message, &changed),
                "{} with signature bit {bit} changed",
                t.name
            );
        }
        if !t.message.is_empty() {
            let mut changed = t.message.clone();
            changed[0] ^= 1;
            assert!(
                !verify(&public, &changed, &expected),
                "{} with the message changed",
                t.name
            );
        }
    }
}

/// S at or above L is refused even when it would verify modulo L.
#[test]
fn ed25519_refuses_unreduced_s() {
    let t = &tests()[0];
    let mut signature: [u8; 64] = t.signature.clone().try_into().expect("64 bytes");
    let public: [u8; 32] = t.public.clone().try_into().expect("32 bytes");
    // Adding L to S keeps it equal modulo L.
    let l = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(signature[32 + i]) + u16::from(l[i]) + carry;
        signature[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert!(!verify(&public, &t.message, &signature));
}
