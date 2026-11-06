//! SHA-1, SHA-256, SHA-384 and SHA-512 against every NIST CAVP
//! byte-oriented vector: ShortMsg, LongMsg and the Monte Carlo test
//! (FIPS 180-4, SHAVS).

mod common;

use common::{hex, rsp, to_hex};
use skarbiec_crypto::sha::{sha1, sha256, sha384, sha512, Digest, Sha1, Sha256, Sha512};

fn messages(file: &str, hash: fn(&[u8]) -> Vec<u8>) -> usize {
    let records = rsp(file);
    let mut checked = 0;
    for record in &records {
        let bits: usize = record.get("Len").parse().expect("Len");
        let message = hex(record.get("Msg"));
        let message = &message[..bits / 8];
        assert_eq!(
            to_hex(&hash(message)),
            record.get("MD").to_lowercase(),
            "{file} Len = {bits}"
        );
        checked += 1;
    }
    assert!(checked > 0, "{file} held no vectors");
    checked
}

/// SHAVS Monte Carlo: from the seed, 100 checkpoints of 1000 chained hashes.
fn monte(file: &str, hash: fn(&[u8]) -> Vec<u8>) -> usize {
    let records = rsp(file);
    let mut seed = hex(records[0].get("Seed"));
    let mut checked = 0;
    for record in records.iter().skip(1) {
        let (mut a, mut b, mut c) = (seed.clone(), seed.clone(), seed.clone());
        for _ in 0..1000 {
            let mut input = a.clone();
            input.extend_from_slice(&b);
            input.extend_from_slice(&c);
            let next = hash(&input);
            a = b;
            b = c;
            c = next;
        }
        assert_eq!(
            to_hex(&c),
            record.get("MD"),
            "{file} COUNT = {}",
            record.get("COUNT")
        );
        seed = c;
        checked += 1;
    }
    assert_eq!(checked, 100, "{file} held {checked} checkpoints, not 100");
    checked
}

fn s1(m: &[u8]) -> Vec<u8> {
    sha1(m).to_vec()
}
fn s256(m: &[u8]) -> Vec<u8> {
    sha256(m).to_vec()
}
fn s512(m: &[u8]) -> Vec<u8> {
    sha512(m).to_vec()
}
fn s384(m: &[u8]) -> Vec<u8> {
    sha384(m).to_vec()
}

#[test]
fn sha1_cavp() {
    messages("sha/SHA1ShortMsg.rsp", s1);
    messages("sha/SHA1LongMsg.rsp", s1);
    monte("sha/SHA1Monte.rsp", s1);
}

#[test]
fn sha256_cavp() {
    messages("sha/SHA256ShortMsg.rsp", s256);
    messages("sha/SHA256LongMsg.rsp", s256);
    monte("sha/SHA256Monte.rsp", s256);
}

#[test]
fn sha512_cavp() {
    messages("sha/SHA512ShortMsg.rsp", s512);
    messages("sha/SHA512LongMsg.rsp", s512);
    monte("sha/SHA512Monte.rsp", s512);
}

#[test]
fn sha384_cavp() {
    messages("sha/SHA384ShortMsg.rsp", s384);
    messages("sha/SHA384LongMsg.rsp", s384);
    monte("sha/SHA384Monte.rsp", s384);
}

/// A message fed in pieces of every size hashes as it does whole: the
/// buffering across block boundaries is what this checks.
#[test]
fn incremental_equals_one_shot() {
    let message: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
    for piece in [1, 3, 63, 64, 65, 127, 128, 129, 500] {
        let mut a = Sha1::new();
        let mut b = Sha256::new();
        let mut c = Sha512::new();
        for chunk in message.chunks(piece) {
            a.update(chunk);
            b.update(chunk);
            c.update(chunk);
        }
        let (mut x, mut y, mut z) = ([0u8; 20], [0u8; 32], [0u8; 64]);
        a.finish_into(&mut x);
        b.finish_into(&mut y);
        c.finish_into(&mut z);
        assert_eq!(x, sha1(&message), "SHA-1 in pieces of {piece}");
        assert_eq!(y, sha256(&message), "SHA-256 in pieces of {piece}");
        assert_eq!(z, sha512(&message), "SHA-512 in pieces of {piece}");
    }
}
