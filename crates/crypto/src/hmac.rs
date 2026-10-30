//! HMAC (RFC 2104) over any hash here, and HKDF-SHA256 (RFC 5869).

use crate::sha::{Digest, Sha256};
use crate::wipe::wipe;

/// HMAC of `message` under `key` with hash `D`, written into `out`.
pub fn hmac_into<D: Digest>(key: &[u8], message: &[u8], out: &mut [u8]) {
    let mut block = vec![0u8; D::BLOCK];
    if key.len() > D::BLOCK {
        let mut hash = D::new();
        hash.update(key);
        hash.finish_into(&mut block[..D::OUTPUT]);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut pad = vec![0u8; D::BLOCK];
    for (p, k) in pad.iter_mut().zip(&block) {
        *p = k ^ 0x36;
    }
    let mut inner = D::new();
    inner.update(&pad);
    inner.update(message);
    let mut inner_digest = vec![0u8; D::OUTPUT];
    inner.finish_into(&mut inner_digest);
    for (p, k) in pad.iter_mut().zip(&block) {
        *p = k ^ 0x5c;
    }
    let mut outer = D::new();
    outer.update(&pad);
    outer.update(&inner_digest);
    outer.finish_into(out);
    wipe(&mut block);
    wipe(&mut pad);
    wipe(&mut inner_digest);
}

/// HMAC-SHA256 of `message` under `key`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hmac_into::<Sha256>(key, message, &mut out);
    out
}

/// HKDF-SHA256 (RFC 5869): `length` bytes from `ikm`, `salt` and `info`.
/// `None` when more than 255 blocks are asked for, which RFC 5869 forbids.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Option<Vec<u8>> {
    if length > 255 * 32 {
        return None;
    }
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    let mut prk = hmac_sha256(salt, ikm);
    let okm = hkdf_expand(&prk, info, length);
    wipe(&mut prk);
    Some(okm)
}

fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(length);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < length {
        let mut input = previous.clone();
        input.extend_from_slice(info);
        input.push(counter);
        let block = hmac_sha256(prk, &input);
        wipe(&mut input);
        let take = (length - okm.len()).min(32);
        okm.extend_from_slice(&block[..take]);
        wipe(&mut previous);
        previous = block.to_vec();
        counter = counter.wrapping_add(1);
    }
    wipe(&mut previous);
    okm
}

/// HKDF-Extract (RFC 5869 section 2.2), for the test vectors that state it.
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    hmac_sha256(salt, ikm)
}
