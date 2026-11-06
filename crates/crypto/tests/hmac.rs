//! HMAC-SHA256 against every case of RFC 4231 section 4, and HKDF-SHA256
//! against every SHA-256 case of RFC 5869 Appendix A.

mod common;

use common::{find_line, hex, labelled, rfc_lines, to_hex};
use skarbiec_crypto::hmac::{hkdf_sha256, hkdf_sha256_extract, hmac_sha256};

#[test]
fn hmac_sha256_rfc4231() {
    let lines = rfc_lines("rfc/rfc4231.txt");
    let body = find_line(&lines, 0, |l| l.starts_with("4.2.  Test Case 1"));
    let mut checked = 0;
    for case in 1..=7 {
        let heading = format!("4.{}.  Test Case {case}", case + 1);
        let at = find_line(&lines, body, |l| l.starts_with(&heading));
        let fields = labelled(&lines, at, |l| l.starts_with("4.") || l.starts_with("5."));
        let get = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| hex(v))
                .unwrap_or_else(|| panic!("case {case} has no {name}"))
        };
        let (key, data, expected) = (get("Key"), get("Data"), get("HMAC-SHA-256"));
        let mac = hmac_sha256(&key, &data);
        // Case 5 states the output truncated to 128 bits.
        assert_eq!(
            to_hex(&mac[..expected.len()]),
            to_hex(&expected),
            "RFC 4231 test case {case}"
        );
        checked += 1;
    }
    assert_eq!(checked, 7);
}

#[test]
fn hkdf_sha256_rfc5869() {
    let lines = rfc_lines("rfc/rfc5869.txt");
    let appendix = find_line(&lines, 0, |l| l.starts_with("Appendix A.  Test Vectors"));
    let mut checked = 0;
    for case in 1..=7 {
        let heading = format!("A.{case}.  Test Case {case}");
        let at = find_line(&lines, appendix, |l| l.starts_with(&heading));
        let fields = labelled(&lines, at, |l| {
            l.starts_with("A.") || l.starts_with("Appendix") || l.starts_with("Authors")
        });
        let text = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        if text("Hash").as_deref() != Some("SHA-256") {
            continue;
        }
        // RFC 5869 writes an absent salt or info as an empty line.
        let get = |name: &str| match text(name) {
            Some(value) => hex(&value),
            None => Vec::new(),
        };
        let length: usize = text("L").expect("L").parse().expect("L is a number");
        let (ikm, salt, info) = (get("IKM"), get("salt"), get("info"));
        assert_eq!(
            to_hex(&hkdf_sha256_extract(&salt, &ikm)),
            to_hex(&get("PRK")),
            "RFC 5869 A.{case} PRK"
        );
        let okm = hkdf_sha256(&salt, &ikm, &info, length).expect("length within 255 blocks");
        assert_eq!(to_hex(&okm), to_hex(&get("OKM")), "RFC 5869 A.{case} OKM");
        checked += 1;
    }
    assert_eq!(checked, 3, "RFC 5869 has three SHA-256 cases");
}

#[test]
fn hkdf_refuses_more_than_255_blocks() {
    assert!(hkdf_sha256(b"salt", b"ikm", b"info", 255 * 32).is_some());
    assert!(hkdf_sha256(b"salt", b"ikm", b"info", 255 * 32 + 1).is_none());
}
