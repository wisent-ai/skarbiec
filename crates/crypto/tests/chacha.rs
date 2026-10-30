//! ChaCha20, Poly1305 and ChaCha20-Poly1305 against every test vector of
//! RFC 8439 Appendix A (A.1 block function #1-#5, A.2 encryption #1-#3, A.3
//! Poly1305 #1-#11, A.4 key generation #1-#3, A.5 AEAD decryption) and the
//! AEAD example of section 2.8.2.

mod common;

use common::{find_line, hex, rfc_lines, to_hex};
use skarbiec_crypto::chacha::{
    chacha20_block, chacha20_xor, open, poly1305, poly1305_key, seal, OpenError,
};

/// The bytes a line of RFC 8439 holds, in any of its three spellings: a
/// hex dump (`016  4c 61 …  ascii`), bare pairs (`02 00 00 …`) or colon
/// pairs (`9f:7b:e9:…`). `None` for any other line.
fn line_bytes(line: &str) -> Option<Vec<u8>> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let pair = |w: &str| w.len() == 2 && w.chars().all(|c| c.is_ascii_hexdigit());
    if let Some((offset, rest)) = trimmed.split_once("  ") {
        if offset.len() == 3 && offset.chars().all(|c| c.is_ascii_digit()) {
            let words: Vec<&str> = rest.split(' ').take_while(|w| pair(w)).collect();
            return Some(hex(&words.concat()));
        }
    }
    let colon: Vec<&str> = trimmed.trim_end_matches(':').split(':').collect();
    if colon.len() > 1 && colon.iter().all(|w| pair(w)) {
        return Some(hex(&colon.concat()));
    }
    let words: Vec<&str> = trimmed.split(' ').collect();
    if words.iter().all(|w| pair(w)) {
        return Some(hex(&words.concat()));
    }
    None
}

/// Labelled values between `from` and `to`: each label line (any other line
/// that is not blank, with a trailing colon dropped) and the bytes on the
/// value lines after it; `Name = number` lines are kept as numbers.
struct Block {
    values: Vec<(String, Vec<u8>)>,
    numbers: Vec<(String, u32)>,
}

impl Block {
    fn get(&self, label: &str) -> Vec<u8> {
        self.values
            .iter()
            .find(|(l, v)| l.trim_end_matches(':') == label && !v.is_empty())
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| {
                panic!(
                    "no {label} among {:?}",
                    self.values.iter().map(|v| &v.0).collect::<Vec<_>>()
                )
            })
    }
    fn number(&self, label: &str) -> u32 {
        self.numbers
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| *v)
            .unwrap_or_else(|| panic!("no {label}"))
    }
}

fn block(lines: &[String]) -> Block {
    let mut values: Vec<(String, Vec<u8>)> = Vec::new();
    let mut numbers = Vec::new();
    for line in lines {
        if let Some(bytes) = line_bytes(line) {
            if let Some(last) = values.last_mut() {
                last.1.extend(bytes);
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((name, value)) = trimmed.split_once(" = ") {
            if let Ok(value) = value.trim().parse() {
                numbers.push((name.trim().to_string(), value));
                continue;
            }
        }
        values.push((trimmed.trim_end_matches(':').to_string(), Vec::new()));
    }
    Block { values, numbers }
}

/// The `Test Vector #n` blocks of the subsection that starts with `section`
/// and ends before `next`.
fn vectors(section: &str, next: &str) -> Vec<(usize, Block)> {
    let lines = rfc_lines("rfc/rfc8439.txt");
    let start = find_line(&lines, 0, |l| l.starts_with(section));
    let end = find_line(&lines, start + 1, |l| l.starts_with(next));
    let heads: Vec<usize> = (start..end)
        .filter(|&i| lines[i].trim().starts_with("Test Vector #"))
        .collect();
    heads
        .iter()
        .enumerate()
        .map(|(n, &head)| {
            let stop = heads.get(n + 1).copied().unwrap_or(end);
            let number = lines[head].trim()["Test Vector #".len()..]
                .split(':')
                .next()
                .expect("number")
                .parse()
                .expect("number");
            (number, block(&lines[head + 1..stop]))
        })
        .collect()
}

fn key(bytes: Vec<u8>) -> [u8; 32] {
    bytes.try_into().expect("32-byte key")
}
fn nonce(bytes: Vec<u8>) -> [u8; 12] {
    bytes.try_into().expect("12-byte nonce")
}

#[test]
fn chacha20_block_a1() {
    let vectors = vectors("A.1.  The ChaCha20 Block Functions", "A.2.");
    assert_eq!(vectors.len(), 5);
    for (n, v) in &vectors {
        let out = chacha20_block(
            &key(v.get("Key")),
            v.number("Block Counter"),
            &nonce(v.get("Nonce")),
        );
        assert_eq!(to_hex(&out), to_hex(&v.get("Keystream")), "A.1 #{n}");
    }
}

#[test]
fn chacha20_encryption_a2() {
    let vectors = vectors("A.2.  ChaCha20 Encryption", "A.3.");
    assert_eq!(vectors.len(), 3);
    for (n, v) in &vectors {
        let mut data = v.get("Plaintext");
        chacha20_xor(
            &key(v.get("Key")),
            v.number("Initial Block Counter"),
            &nonce(v.get("Nonce")),
            &mut data,
        );
        assert_eq!(to_hex(&data), to_hex(&v.get("Ciphertext")), "A.2 #{n}");
    }
}

#[test]
fn poly1305_a3() {
    let vectors = vectors("A.3.  Poly1305 Message Authentication Code", "A.4.");
    assert_eq!(vectors.len(), 11);
    for (n, v) in &vectors {
        // Vectors #1-#4 give the one-time key whole; #5-#11 give R and S.
        let (one_time, text) = if *n <= 4 {
            (v.get("One-time Poly1305 Key"), v.get("Text to MAC"))
        } else {
            let mut joined = v.get("R");
            joined.extend(v.get("S"));
            (joined, v.get("data"))
        };
        let expected = if *n <= 4 { v.get("Tag") } else { v.get("tag") };
        assert_eq!(
            to_hex(&poly1305(&key(one_time), &text)),
            to_hex(&expected),
            "A.3 #{n}"
        );
    }
}

#[test]
fn poly1305_key_generation_a4() {
    let vectors = vectors("A.4.  Poly1305 Key Generation Using ChaCha20", "A.5.");
    assert_eq!(vectors.len(), 3);
    for (n, v) in &vectors {
        let derived = poly1305_key(&key(v.get("The ChaCha20 Key")), &nonce(v.get("The nonce")));
        assert_eq!(
            to_hex(&derived),
            to_hex(&v.get("Poly1305 one-time key")),
            "A.4 #{n}"
        );
    }
}

#[test]
fn aead_decryption_a5() {
    let lines = rfc_lines("rfc/rfc8439.txt");
    let start = find_line(&lines, 0, |l| {
        l.starts_with("A.5.  ChaCha20-Poly1305 AEAD Decryption")
    });
    let end = find_line(&lines, start + 1, |l| l.starts_with("Appendix B"));
    let v = block(&lines[start + 1..end]);
    let (k, n, aad) = (
        key(v.get("The ChaCha20 Key")),
        nonce(v.get("The nonce")),
        v.get("The AAD"),
    );
    let mut sealed = v.get("Ciphertext");
    sealed.extend(v.get("Received Tag"));
    let plain = open(&k, &n, &aad, &sealed).expect("A.5 opens");
    assert_eq!(to_hex(&plain), to_hex(&v.get("Plaintext")), "A.5 plaintext");
    assert_eq!(
        to_hex(&seal(&k, &n, &aad, &plain)),
        to_hex(&sealed),
        "A.5 sealed again"
    );
    for at in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[at] ^= 0x20;
        assert_eq!(
            open(&k, &n, &aad, &tampered),
            Err(OpenError::Forged),
            "A.5 byte {at} changed"
        );
    }
}

#[test]
fn aead_encryption_2_8_2() {
    let lines = rfc_lines("rfc/rfc8439.txt");
    let start = find_line(&lines, 0, |l| {
        l.starts_with("2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305")
    });
    let end = find_line(&lines, start + 1, |l| {
        l.starts_with("3.  Implementation Advice")
    });
    let v = block(&lines[start + 1..end]);
    let mut n = v.get("32-bit fixed-common part");
    n.extend(v.get("IV"));
    let (k, n, aad, plaintext) = (
        key(v.get("Key")),
        nonce(n),
        v.get("AAD"),
        v.get("Plaintext"),
    );
    let mut expected = v.get("Ciphertext");
    expected.extend(v.get("Tag"));
    assert_eq!(
        to_hex(&seal(&k, &n, &aad, &plaintext)),
        to_hex(&expected),
        "2.8.2"
    );
    assert_eq!(open(&k, &n, &aad, &expected).expect("opens"), plaintext);
}

#[test]
fn open_refusals_say_why() {
    assert_eq!(
        open(&[0; 32], &[0; 12], &[], &[0; 15]),
        Err(OpenError::TooShort)
    );
    assert_eq!(
        OpenError::Forged.to_string(),
        "the ChaCha20-Poly1305 tag does not match: the data was changed or this is not its key"
    );
}
