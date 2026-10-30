//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439): the cipher
//! of Skarbiec's own sealed format. ChaCha20 is additions, rotations and
//! exclusive-ors only; Poly1305 is computed in 26-bit limbs with no branch
//! on secret data.

use crate::wipe::{equal, wipe, wipe_words};

fn quarter(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// The ChaCha20 block function (RFC 8439 section 2.3).
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        state[4 + i] = word(&key[4 * i..]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = word(&nonce[4 * i..]);
    }
    let mut working = state;
    for _ in 0..10 {
        quarter(&mut working, 0, 4, 8, 12);
        quarter(&mut working, 1, 5, 9, 13);
        quarter(&mut working, 2, 6, 10, 14);
        quarter(&mut working, 3, 7, 11, 15);
        quarter(&mut working, 0, 5, 10, 15);
        quarter(&mut working, 1, 6, 11, 12);
        quarter(&mut working, 2, 7, 8, 13);
        quarter(&mut working, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&working[i].wrapping_add(state[i]).to_le_bytes());
    }
    wipe_words(&mut state);
    wipe_words(&mut working);
    out
}

/// ChaCha20 encryption (RFC 8439 section 2.4): `data` exclusive-ored with
/// the keystream from block `counter` on.
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let mut block = chacha20_block(key, counter.wrapping_add(i as u32), nonce);
        for (byte, key) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= key;
        }
        wipe(&mut block);
    }
}

/// Poly1305 (RFC 8439 section 2.5) of `message` under the one-time `key`.
pub fn poly1305(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let r0 = word(&key[0..]) & 0x03ff_ffff;
    let r1 = (word(&key[3..]) >> 2) & 0x03ff_ff03;
    let r2 = (word(&key[6..]) >> 4) & 0x03ff_c0ff;
    let r3 = (word(&key[9..]) >> 6) & 0x03f0_3fff;
    let r4 = (word(&key[12..]) >> 8) & 0x000f_ffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let mut h = [0u32; 5];
    for chunk in message.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;
        h[0] = h[0].wrapping_add(word(&block[0..]) & 0x03ff_ffff);
        h[1] = h[1].wrapping_add((word(&block[3..]) >> 2) & 0x03ff_ffff);
        h[2] = h[2].wrapping_add((word(&block[6..]) >> 4) & 0x03ff_ffff);
        h[3] = h[3].wrapping_add((word(&block[9..]) >> 6) & 0x03ff_ffff);
        h[4] = h[4].wrapping_add((word(&block[12..]) >> 8) | (u32::from(block[16]) << 24));
        let [h0, h1, h2, h3, h4] = h.map(u64::from);
        let (r0, r1, r2, r3, r4) = (r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64);
        let (s1, s2, s3, s4) = (s1 as u64, s2 as u64, s3 as u64, s4 as u64);
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        let mut carry = d0 >> 26;
        h[0] = (d0 as u32) & 0x03ff_ffff;
        d1 += carry;
        carry = d1 >> 26;
        h[1] = (d1 as u32) & 0x03ff_ffff;
        d2 += carry;
        carry = d2 >> 26;
        h[2] = (d2 as u32) & 0x03ff_ffff;
        d3 += carry;
        carry = d3 >> 26;
        h[3] = (d3 as u32) & 0x03ff_ffff;
        d4 += carry;
        carry = d4 >> 26;
        h[4] = (d4 as u32) & 0x03ff_ffff;
        h[0] = h[0].wrapping_add((carry as u32) * 5);
        let c = h[0] >> 26;
        h[0] &= 0x03ff_ffff;
        h[1] = h[1].wrapping_add(c);
        wipe(&mut block);
    }
    // Full carry, then h - p chosen without a branch.
    let mut c = h[1] >> 26;
    h[1] &= 0x03ff_ffff;
    h[2] = h[2].wrapping_add(c);
    c = h[2] >> 26;
    h[2] &= 0x03ff_ffff;
    h[3] = h[3].wrapping_add(c);
    c = h[3] >> 26;
    h[3] &= 0x03ff_ffff;
    h[4] = h[4].wrapping_add(c);
    c = h[4] >> 26;
    h[4] &= 0x03ff_ffff;
    h[0] = h[0].wrapping_add(c * 5);
    c = h[0] >> 26;
    h[0] &= 0x03ff_ffff;
    h[1] = h[1].wrapping_add(c);
    let mut g = [0u32; 5];
    g[0] = h[0].wrapping_add(5);
    c = g[0] >> 26;
    g[0] &= 0x03ff_ffff;
    for i in 1..4 {
        g[i] = h[i].wrapping_add(c);
        c = g[i] >> 26;
        g[i] &= 0x03ff_ffff;
    }
    // g = h + 5 - 2^130: its top bit says whether h was below p.
    g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);
    let mask = (g[4] >> 31).wrapping_sub(1);
    for i in 0..5 {
        h[i] = (h[i] & !mask) | (g[i] & mask);
    }
    let h0 = h[0] | (h[1] << 26);
    let h1 = (h[1] >> 6) | (h[2] << 20);
    let h2 = (h[2] >> 12) | (h[3] << 14);
    let h3 = (h[3] >> 18) | (h[4] << 8);
    let mut f = u64::from(h0) + u64::from(word(&key[16..]));
    let t0 = f as u32;
    f = u64::from(h1) + u64::from(word(&key[20..])) + (f >> 32);
    let t1 = f as u32;
    f = u64::from(h2) + u64::from(word(&key[24..])) + (f >> 32);
    let t2 = f as u32;
    f = u64::from(h3) + u64::from(word(&key[28..])) + (f >> 32);
    let t3 = f as u32;
    let mut tag = [0u8; 16];
    for (i, t) in [t0, t1, t2, t3].iter().enumerate() {
        tag[4 * i..4 * i + 4].copy_from_slice(&t.to_le_bytes());
    }
    wipe_words(&mut h);
    wipe_words(&mut g);
    tag
}

/// The Poly1305 one-time key for a ChaCha20 key and nonce (RFC 8439
/// section 2.6).
pub fn poly1305_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut block = chacha20_block(key, 0, nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&block[..32]);
    wipe(&mut block);
    out
}

fn mac_data(associated: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let pad = |n: usize| (16 - n % 16) % 16;
    let mut data = Vec::with_capacity(associated.len() + ciphertext.len() + 48);
    data.extend_from_slice(associated);
    data.resize(data.len() + pad(associated.len()), 0);
    data.extend_from_slice(ciphertext);
    data.resize(data.len() + pad(ciphertext.len()), 0);
    data.extend_from_slice(&(associated.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    data
}

/// ChaCha20-Poly1305 encryption (RFC 8439 section 2.8): ciphertext followed
/// by the 16-byte tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], associated: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut one_time = poly1305_key(key, nonce);
    let mut out = plaintext.to_vec();
    chacha20_xor(key, 1, nonce, &mut out);
    let tag = poly1305(&one_time, &mac_data(associated, &out));
    out.extend_from_slice(&tag);
    wipe(&mut one_time);
    out
}

/// A ChaCha20-Poly1305 message that does not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    TooShort,
    Forged,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "the sealed data is shorter than its 16-byte tag"),
            Self::Forged => write!(
                formatter,
                "the ChaCha20-Poly1305 tag does not match: the data was changed or this is not its key"
            ),
        }
    }
}

impl std::error::Error for OpenError {}

/// ChaCha20-Poly1305 decryption: the plaintext only when the tag verifies.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, OpenError> {
    if sealed.len() < 16 {
        return Err(OpenError::TooShort);
    }
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    let mut one_time = poly1305_key(key, nonce);
    let expected = poly1305(&one_time, &mac_data(associated, ciphertext));
    wipe(&mut one_time);
    if !equal(&expected, tag) {
        return Err(OpenError::Forged);
    }
    let mut out = ciphertext.to_vec();
    chacha20_xor(key, 1, nonce, &mut out);
    Ok(out)
}
