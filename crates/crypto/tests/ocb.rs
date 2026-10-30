//! OCB against all of RFC 7253 Appendix A: the sixteen (N, A, P, C) tuples,
//! the 96-bit-tag tuple, and the iterated test for AES-128/192/256 with
//! 128, 96 and 64-bit tags.

mod common;

use common::{find_line, hex, labelled, rfc_lines, to_hex};
use skarbiec_crypto::aes::Aes;
use skarbiec_crypto::ocb::{Ocb, OcbError};

/// One (K, N, A, P, C) tuple of Appendix A, with the key in force.
type Tuple = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn tuples() -> Vec<Tuple> {
    let lines = rfc_lines("rfc/rfc7253.txt");
    let start = find_line(&lines, 0, |l| l.starts_with("Appendix A.  Sample Results"));
    let fields = labelled(&lines, start, |l| l.contains("tests a wider variety"));
    let mut key = Vec::new();
    let mut current: Vec<(String, Vec<u8>)> = Vec::new();
    let mut tuples = Vec::new();
    for (name, value) in fields {
        match name.as_str() {
            "K" => key = hex(&value),
            "N" | "A" | "P" => current.push((name, hex(&value))),
            "C" => {
                let get = |n: &str| {
                    current
                        .iter()
                        .find(|(m, _)| m == n)
                        .map(|(_, v)| v.clone())
                        .expect("field")
                };
                tuples.push((key.clone(), get("N"), get("A"), get("P"), hex(&value)));
                current.clear();
            }
            _ => current.clear(),
        }
    }
    tuples
}

#[test]
fn ocb_rfc7253_tuples() {
    let tuples = tuples();
    assert_eq!(
        tuples.len(),
        17,
        "Appendix A gives sixteen 128-bit-tag tuples and one 96-bit one"
    );
    for (index, (key, nonce, associated, plaintext, expected)) in tuples.iter().enumerate() {
        let aes = Aes::new(key).expect("key");
        let tag_len = expected.len() - plaintext.len();
        let ocb = Ocb::new(&aes, tag_len).expect("tag length");
        let sealed = ocb.seal(nonce, associated, plaintext).expect("seal");
        assert_eq!(to_hex(&sealed), to_hex(expected), "RFC 7253 tuple {index}");
        assert_eq!(
            ocb.open(nonce, associated, expected).expect("open"),
            *plaintext,
            "RFC 7253 tuple {index} open"
        );
        for at in 0..expected.len() {
            let mut tampered = expected.clone();
            tampered[at] ^= 0x01;
            assert_eq!(
                ocb.open(nonce, associated, &tampered),
                Err(OcbError::Forged),
                "tuple {index}, byte {at} changed"
            );
        }
        if !associated.is_empty() {
            let mut other = associated.clone();
            other[0] ^= 0x80;
            assert_eq!(
                ocb.open(nonce, &other, expected),
                Err(OcbError::Forged),
                "tuple {index}, associated data changed"
            );
        }
    }
}

fn num(value: u32, bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; bytes];
    out[bytes - 4..].copy_from_slice(&value.to_be_bytes());
    out
}

#[test]
fn ocb_rfc7253_iterated() {
    let lines = rfc_lines("rfc/rfc7253.txt");
    let mut checked = 0;
    for line in &lines {
        let Some(rest) = line.trim().strip_prefix("AEAD_AES_") else {
            continue;
        };
        let (name, output) = rest.split_once("Output").expect("Output");
        let output = hex(output.trim_start_matches([' ', ':']));
        let mut parts = name.trim().split('_');
        let key_bits: usize = parts.next().expect("key size").parse().expect("number");
        let tag_bits: usize = parts
            .nth(1)
            .expect("TAGLEN")
            .trim_start_matches("TAGLEN")
            .parse()
            .expect("number");
        let mut key = vec![0u8; key_bits / 8];
        let last = key.len() - 1;
        key[last] = tag_bits as u8;
        let aes = Aes::new(&key).expect("key");
        let ocb = Ocb::new(&aes, tag_bits / 8).expect("tag");
        let mut c = Vec::new();
        for i in 0..128u32 {
            // zeros(8i) is 8i bits: i bytes.
            let s = vec![0u8; i as usize];
            c.extend(ocb.seal(&num(3 * i + 1, 12), &s, &s).expect("seal"));
            c.extend(ocb.seal(&num(3 * i + 2, 12), &[], &s).expect("seal"));
            c.extend(ocb.seal(&num(3 * i + 3, 12), &s, &[]).expect("seal"));
        }
        let result = ocb.seal(&num(385, 12), &c, &[]).expect("seal");
        assert_eq!(
            to_hex(&result),
            to_hex(&output),
            "RFC 7253 iterated AES-{key_bits} TAGLEN{tag_bits}"
        );
        checked += 1;
    }
    assert_eq!(checked, 9);
}

#[test]
fn ocb_refusals_name_the_length() {
    let aes = Aes::new(&[0u8; 16]).expect("key");
    assert_eq!(Ocb::new(&aes, 0).err(), Some(OcbError::TagLength(0)));
    assert_eq!(Ocb::new(&aes, 17).err(), Some(OcbError::TagLength(17)));
    for short in [1, 4, 7, 15] {
        assert_eq!(
            Ocb::new(&aes, short).err(),
            Some(OcbError::TagLength(short))
        );
    }
    let ocb = Ocb::new(&aes, 16).expect("tag");
    assert_eq!(
        ocb.seal(&[0u8; 16], &[], b"x").err(),
        Some(OcbError::NonceLength(16))
    );
    assert_eq!(
        ocb.seal(&[], &[], b"x").err(),
        Some(OcbError::NonceLength(0))
    );
    assert_eq!(
        ocb.open(&[1u8; 12], &[], &[0u8; 15]).err(),
        Some(OcbError::TooShort)
    );
    assert_eq!(
        OcbError::Forged.to_string(),
        "the OCB tag does not match: the data or its key is not the one sealed"
    );
}
