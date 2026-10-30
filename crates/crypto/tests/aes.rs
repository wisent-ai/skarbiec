//! AES against every NIST CAVP ECB known-answer (GFSbox, KeySbox, VarKey,
//! VarTxt) and multi-block message vector for 128, 192 and 256-bit keys;
//! CFB128 against every CFB128 KAT and MMT vector; AES key wrap against all
//! six cases of RFC 3394 section 4.

mod common;

use common::{find_line, hex, rfc_lines, rsp, to_hex};
use skarbiec_crypto::aes::{cfb_decrypt, cfb_encrypt, key_unwrap, key_wrap, Aes};

const SIZES: [u32; 3] = [128, 192, 256];
const KAT: [&str; 4] = ["GFSbox", "KeySbox", "VarKey", "VarTxt"];

fn ecb(file: &str) -> usize {
    let mut checked = 0;
    for record in rsp(file) {
        let aes = Aes::new(&hex(record.get("KEY"))).expect("key length");
        let plain = hex(record.get("PLAINTEXT"));
        let cipher = hex(record.get("CIPHERTEXT"));
        let (from, to) = if record.section == "[ENCRYPT]" {
            (&plain, &cipher)
        } else {
            (&cipher, &plain)
        };
        let mut out = from.clone();
        for block in out.chunks_mut(16) {
            let block: &mut [u8; 16] = block.try_into().expect("whole blocks");
            if record.section == "[ENCRYPT]" {
                aes.encrypt_block(block);
            } else {
                aes.decrypt_block(block);
            }
        }
        assert_eq!(
            to_hex(&out),
            to_hex(to),
            "{file} {} COUNT = {}",
            record.section,
            record.get("COUNT")
        );
        checked += 1;
    }
    assert!(checked > 0, "{file} held no vectors");
    checked
}

fn cfb(file: &str) -> usize {
    let mut checked = 0;
    for record in rsp(file) {
        let aes = Aes::new(&hex(record.get("KEY"))).expect("key length");
        let iv: [u8; 16] = hex(record.get("IV")).try_into().expect("16-byte IV");
        let plain = hex(record.get("PLAINTEXT"));
        let cipher = hex(record.get("CIPHERTEXT"));
        if record.section == "[ENCRYPT]" {
            let mut out = plain.clone();
            cfb_encrypt(&aes, &iv, &mut out);
            assert_eq!(
                to_hex(&out),
                to_hex(&cipher),
                "{file} ENCRYPT COUNT = {}",
                record.get("COUNT")
            );
        } else {
            let mut out = cipher.clone();
            cfb_decrypt(&aes, &iv, &mut out);
            assert_eq!(
                to_hex(&out),
                to_hex(&plain),
                "{file} DECRYPT COUNT = {}",
                record.get("COUNT")
            );
        }
        checked += 1;
    }
    assert!(checked > 0, "{file} held no vectors");
    checked
}

#[test]
fn aes_ecb_cavp() {
    let mut checked = 0;
    for size in SIZES {
        for kind in KAT {
            checked += ecb(&format!("aes/ECB{kind}{size}.rsp"));
        }
        checked += ecb(&format!("aes/ECBMMT{size}.rsp"));
    }
    println!("AES ECB: {checked} CAVP vectors");
}

#[test]
fn aes_cfb128_cavp() {
    let mut checked = 0;
    for size in SIZES {
        for kind in KAT {
            checked += cfb(&format!("aes/CFB128{kind}{size}.rsp"));
        }
        checked += cfb(&format!("aes/CFB128MMT{size}.rsp"));
    }
    println!("AES CFB128: {checked} CAVP vectors");
}

/// CFB over a length that is not a whole number of blocks, as OpenPGP uses
/// it, decrypts what it encrypted.
#[test]
fn cfb_partial_block_round_trip() {
    let aes = Aes::new(&[7u8; 32]).expect("key");
    let message: Vec<u8> = (0..77u8).collect();
    let mut data = message.clone();
    cfb_encrypt(&aes, &[0u8; 16], &mut data);
    assert_ne!(data, message);
    cfb_decrypt(&aes, &[0u8; 16], &mut data);
    assert_eq!(data, message);
}

/// The hex words on the line that starts with `label` in RFC 3394 section
/// `section`, and on the lines after it until a blank one.
fn rfc3394_value(lines: &[String], section: usize, label: &str) -> Vec<u8> {
    let at = find_line(lines, section, |l| l.trim_start().starts_with(label));
    let mut text = lines[at].trim_start()[label.len()..]
        .trim_start_matches(':')
        .to_string();
    for line in &lines[at + 1..] {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == ' ') {
            break;
        }
        text.push_str(trimmed);
    }
    hex(&text)
}

#[test]
fn key_wrap_rfc3394() {
    let lines = rfc_lines("rfc/rfc3394.txt");
    for case in 1..=6 {
        let heading = format!("4.{case} Wrap");
        let section = find_line(&lines, 0, |l| l.starts_with(&heading));
        let kek = rfc3394_value(&lines, section, "KEK");
        let key_data = rfc3394_value(&lines, section, "Key Data");
        let ciphertext = rfc3394_value(&lines, section, "Ciphertext");
        let aes = Aes::new(&kek).expect("KEK length");
        let wrapped = key_wrap(&aes, &key_data).expect("key data length");
        assert_eq!(
            to_hex(&wrapped),
            to_hex(&ciphertext),
            "RFC 3394 4.{case} wrap"
        );
        let unwrapped = key_unwrap(&aes, &ciphertext).expect("integrity check");
        assert_eq!(
            to_hex(&unwrapped),
            to_hex(&key_data),
            "RFC 3394 4.{case} unwrap"
        );
        let mut tampered = ciphertext.clone();
        tampered[10] ^= 1;
        assert!(
            key_unwrap(&aes, &tampered).is_none(),
            "RFC 3394 4.{case}: a changed byte must fail the check"
        );
    }
}

#[test]
fn aes_refuses_a_key_of_another_length() {
    for length in [0, 15, 17, 31, 33] {
        let refused = Aes::new(&vec![0u8; length]).err().expect("refused");
        assert_eq!(
            refused.to_string(),
            format!("an AES key is 16, 24 or 32 bytes, not {length}")
        );
    }
}
