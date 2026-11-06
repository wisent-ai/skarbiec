//! X25519 against RFC 7748: both section 5.2 input/output pairs, the
//! iterated test after 1, 1,000 and 1,000,000 iterations, and the
//! Diffie-Hellman example of section 6.1.

mod common;

use common::{find_line, hex, rfc_lines, to_hex};
use skarbiec_crypto::x25519::{public_key, shared_secret, x25519, BASE};

/// The hex on the lines after the `index`-th line from `from` on that
/// `label` matches, up to a line that is not hex.
fn after(lines: &[String], from: usize, label: &str, index: usize) -> (Vec<u8>, usize) {
    let mut at = from;
    for _ in 0..=index {
        at = find_line(lines, at, |l| l.trim() == label) + 1;
    }
    let mut text = String::new();
    for line in &lines[at..] {
        let t = line.trim();
        if t.is_empty() || !t.chars().all(|c| c.is_ascii_hexdigit()) {
            break;
        }
        text.push_str(t);
    }
    (hex(&text), at)
}

fn bytes32(v: Vec<u8>) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

#[test]
fn x25519_rfc7748_pairs() {
    let lines = rfc_lines("rfc/rfc7748.txt");
    let section = find_line(&lines, 0, |l| l.starts_with("5.2.  Test Vectors"));
    let x25519_at = find_line(&lines, section, |l| l.trim() == "X25519:");
    for case in 0..2 {
        let (scalar, _) = after(&lines, x25519_at, "Input scalar:", case);
        let (u, _) = after(&lines, x25519_at, "Input u-coordinate:", case);
        let (expected, _) = after(&lines, x25519_at, "Output u-coordinate:", case);
        assert_eq!(
            to_hex(&x25519(&bytes32(scalar), &bytes32(u))),
            to_hex(&expected),
            "RFC 7748 5.2 pair {}",
            case + 1
        );
    }
}

#[test]
fn x25519_rfc7748_iterated() {
    let lines = rfc_lines("rfc/rfc7748.txt");
    let section = find_line(&lines, 0, |l| l.contains("The second type of test vector"));
    let x25519_at = find_line(&lines, section, |l| l.trim() == "X25519:");
    let checkpoints = [
        (1usize, "After one iteration:"),
        (1000, "After 1,000 iterations:"),
        (1_000_000, "After 1,000,000 iterations:"),
    ];
    let mut k = BASE;
    let mut u = BASE;
    let mut done = 0;
    for (target, label) in checkpoints {
        let (expected, _) = after(&lines, x25519_at, label, 0);
        while done < target {
            let next = x25519(&k, &u);
            u = k;
            k = next;
            done += 1;
        }
        assert_eq!(to_hex(&k), to_hex(&expected), "RFC 7748 5.2 {label}");
    }
}

#[test]
fn x25519_rfc7748_diffie_hellman() {
    let lines = rfc_lines("rfc/rfc7748.txt");
    let section = find_line(&lines, 0, |l| l.starts_with("6.1.  Curve25519"));
    let (alice, _) = after(&lines, section, "Alice's private key, a:", 0);
    let (alice_public, _) = after(&lines, section, "Alice's public key, X25519(a, 9):", 0);
    let (bob, _) = after(&lines, section, "Bob's private key, b:", 0);
    let (bob_public, _) = after(&lines, section, "Bob's public key, X25519(b, 9):", 0);
    let (shared, _) = after(&lines, section, "Their shared secret, K:", 0);
    let (alice, bob) = (bytes32(alice), bytes32(bob));
    assert_eq!(to_hex(&public_key(&alice)), to_hex(&alice_public));
    assert_eq!(to_hex(&public_key(&bob)), to_hex(&bob_public));
    assert_eq!(
        to_hex(&shared_secret(&alice, &bytes32(bob_public)).expect("shared")),
        to_hex(&shared)
    );
    assert_eq!(
        to_hex(&shared_secret(&bob, &bytes32(alice_public)).expect("shared")),
        to_hex(&shared)
    );
}

/// A peer key of small order yields an all-zero shared secret, refused.
#[test]
fn small_order_peer_is_refused() {
    let zero = [0u8; 32];
    let mut one = [0u8; 32];
    one[0] = 1;
    assert!(shared_secret(&[7u8; 32], &zero).is_none());
    assert!(shared_secret(&[7u8; 32], &one).is_none());
}
