//! AES-GCM against every case of the NIST CAVP decryption vectors for
//! 128- and 256-bit keys (SP 800-38D, GCMVS): each case that opens must give
//! its plaintext and seal back to its ciphertext and tag, and each case
//! marked FAIL must be refused. Nonces of 8, 96 and 1024 bits, tags of 32
//! to 128 bits, and every associated-data and plaintext length the files
//! hold are covered.

mod common;

use common::{hex, to_hex, vector_file};
use skarbiec_crypto::gcm::Gcm;

fn cases(file: &str) -> (usize, usize) {
    let text = vector_file(file);
    let (mut opened, mut refused) = (0, 0);
    let mut tag_bits = 128usize;
    let mut record: Vec<(String, String)> = Vec::new();
    let mut check = |record: &Vec<(String, String)>, tag_bits: usize| {
        let get = |name: &str| {
            record
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("{file}: a case has no {name}: {record:?}"))
        };
        let fail = record.iter().any(|(n, _)| n == "FAIL");
        let key = hex(get("Key"));
        let iv = hex(get("IV"));
        let ct = hex(get("CT"));
        let aad = hex(get("AAD"));
        let tag = hex(get("Tag"));
        assert_eq!(tag.len() * 8, tag_bits, "{file} Count = {}", get("Count"));
        let gcm = Gcm::new(&key).expect("a 128- or 256-bit key");
        let mut sealed = ct.clone();
        sealed.extend_from_slice(&tag);
        let answer = gcm.open_with_tag(&iv, &aad, &sealed, tag.len());
        if fail {
            assert!(
                answer.is_err(),
                "{file} Count = {} opened a FAIL case",
                get("Count")
            );
            return false;
        }
        let pt = answer.unwrap_or_else(|_| panic!("{file} Count = {} did not open", get("Count")));
        assert_eq!(
            to_hex(&pt),
            to_hex(&hex(get("PT"))),
            "{file} Count = {}",
            get("Count")
        );
        let resealed = gcm.seal(&iv, &aad, &pt);
        let (ours_ct, ours_tag) = resealed.split_at(pt.len());
        assert_eq!(
            to_hex(ours_ct),
            to_hex(&ct),
            "{file} Count = {} ciphertext",
            get("Count")
        );
        assert_eq!(
            to_hex(&ours_tag[..tag.len()]),
            to_hex(&tag),
            "{file} Count = {} tag",
            get("Count")
        );
        true
    };
    for line in text.lines().map(str::trim) {
        if let Some(bits) = line
            .strip_prefix("[Taglen = ")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            tag_bits = bits.parse().expect("Taglen");
            continue;
        }
        if line.starts_with('[') || line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if record.iter().any(|(n, _)| n == "Count") {
                if check(&record, tag_bits) {
                    opened += 1;
                } else {
                    refused += 1;
                }
            }
            record.clear();
            continue;
        }
        match line.split_once('=') {
            Some((name, value)) => record.push((name.trim().to_string(), value.trim().to_string())),
            None => record.push((line.to_string(), String::new())),
        }
    }
    if record.iter().any(|(n, _)| n == "Count") {
        if check(&record, tag_bits) {
            opened += 1;
        } else {
            refused += 1;
        }
    }
    assert!(
        opened > 0 && refused > 0,
        "{file}: {opened} opened, {refused} refused"
    );
    (opened, refused)
}

#[test]
fn aes128_gcm_cavp() {
    let (opened, refused) = cases("gcm/gcmDecrypt128.rsp");
    assert_eq!(opened + refused, 7875);
}

#[test]
fn aes256_gcm_cavp() {
    let (opened, refused) = cases("gcm/gcmDecrypt256.rsp");
    assert_eq!(opened + refused, 7875);
}

/// A changed byte of the ciphertext, tag or associated data is refused.
#[test]
fn any_change_is_refused() {
    let gcm = Gcm::new(&[7u8; 16]).expect("key");
    let nonce = [9u8; 12];
    let sealed = gcm.seal(&nonce, b"header", b"a message of some length");
    for at in 0..sealed.len() {
        let mut changed = sealed.clone();
        changed[at] ^= 1;
        assert!(gcm.open(&nonce, b"header", &changed).is_err(), "byte {at}");
    }
    assert!(gcm.open(&nonce, b"headex", &sealed).is_err());
    assert_eq!(
        gcm.open(&nonce, b"header", &sealed).expect("opens"),
        b"a message of some length"
    );
}
