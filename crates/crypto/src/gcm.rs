//! AES-GCM (NIST SP 800-38D), the AEAD TLS 1.3 names TLS_AES_128_GCM_SHA256
//! and TLS_AES_256_GCM_SHA384 over. GHASH multiplies in GF(2^128) bit by bit
//! with masks rather than branches or tables, so its timing does not depend
//! on the key or the data.

use crate::aes::Aes;
use crate::wipe::wipe;

/// The tag GCM appends: 16 bytes, the length TLS uses.
pub const TAG: usize = 16;

/// Why a sealed message did not open: its tag does not match, so it was
/// changed, or it was sealed under another key, nonce or associated data.
#[derive(Debug, PartialEq, Eq)]
pub struct OpenError;

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the AES-GCM tag does not match: the message was changed, or it was sealed under \
             another key, nonce or associated data",
        )
    }
}

impl std::error::Error for OpenError {}

/// Multiply `x` by `y` in GCM's GF(2^128) (SP 800-38D algorithm 1), both
/// read as big-endian 128-bit values.
fn multiply(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe1 << 120;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        z ^= v & 0u128.wrapping_sub(bit);
        let low = v & 1;
        v = (v >> 1) ^ (R & 0u128.wrapping_sub(low));
    }
    z
}

/// GHASH under subkey `h` of `data` padded with zeros to whole blocks,
/// continuing from `state`.
fn ghash_blocks(h: u128, mut state: u128, data: &[u8]) -> u128 {
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        state = multiply(state ^ u128::from_be_bytes(block), h);
    }
    state
}

/// The GHASH of associated data and ciphertext with their bit lengths.
fn ghash(h: u128, associated: &[u8], ciphertext: &[u8]) -> u128 {
    let state = ghash_blocks(h, 0, associated);
    let state = ghash_blocks(h, state, ciphertext);
    let lengths = ((associated.len() as u128 * 8) << 64) | (ciphertext.len() as u128 * 8);
    multiply(state ^ lengths, h)
}

/// The counter block a message starts from: the nonce with a 32-bit
/// counter of 1 when it is 12 bytes, else GHASH of the nonce.
fn first_counter(h: u128, nonce: &[u8]) -> u128 {
    if nonce.len() == 12 {
        let mut block = [0u8; 16];
        block[..12].copy_from_slice(nonce);
        block[15] = 1;
        return u128::from_be_bytes(block);
    }
    let state = ghash_blocks(h, 0, nonce);
    multiply(state ^ (nonce.len() as u128 * 8), h)
}

/// Add one to the low 32 bits of a counter block, as GCM's inc32 does.
fn increment(counter: u128) -> u128 {
    let high = counter & !0xffff_ffffu128;
    let low = (counter as u32).wrapping_add(1);
    high | u128::from(low)
}

fn encrypt(aes: &Aes, block: u128) -> u128 {
    let mut bytes = block.to_be_bytes();
    aes.encrypt_block(&mut bytes);
    u128::from_be_bytes(bytes)
}

/// XOR `data` in place with the key stream from `counter` on.
fn ctr(aes: &Aes, mut counter: u128, data: &mut [u8]) {
    for chunk in data.chunks_mut(16) {
        let mut stream = encrypt(aes, counter).to_be_bytes();
        for (byte, key) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= key;
        }
        wipe(&mut stream);
        counter = increment(counter);
    }
}

/// An AES-GCM key: the expanded AES key and the GHASH subkey it gives.
pub struct Gcm {
    aes: Aes,
    h: u128,
}

impl Drop for Gcm {
    fn drop(&mut self) {
        self.h = 0;
    }
}

impl Gcm {
    /// A key of 16, 24 or 32 bytes; `None` for any other length.
    pub fn new(key: &[u8]) -> Option<Self> {
        let aes = Aes::new(key).ok()?;
        let h = encrypt(&aes, 0);
        Some(Self { aes, h })
    }

    fn tag(&self, j0: u128, associated: &[u8], ciphertext: &[u8]) -> [u8; TAG] {
        (encrypt(&self.aes, j0) ^ ghash(self.h, associated, ciphertext)).to_be_bytes()
    }

    /// Encrypt `plaintext` under `nonce` with `associated` data bound in;
    /// answers the ciphertext followed by its 16-byte tag.
    pub fn seal(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let j0 = first_counter(self.h, nonce);
        let mut out = plaintext.to_vec();
        ctr(&self.aes, increment(j0), &mut out);
        let tag = self.tag(j0, associated, &out);
        out.extend_from_slice(&tag);
        out
    }

    /// Check the tag `sealed` ends with, then decrypt the rest. Nothing is
    /// decrypted when the tag does not match.
    pub fn open(
        &self,
        nonce: &[u8],
        associated: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, OpenError> {
        self.open_with_tag(nonce, associated, sealed, TAG)
    }

    /// As `open`, for a tag of `tag_len` bytes (4 to 16), as the NIST
    /// vectors state shorter ones; TLS uses 16.
    pub fn open_with_tag(
        &self,
        nonce: &[u8],
        associated: &[u8],
        sealed: &[u8],
        tag_len: usize,
    ) -> Result<Vec<u8>, OpenError> {
        if !(4..=TAG).contains(&tag_len) || sealed.len() < tag_len {
            return Err(OpenError);
        }
        let (ciphertext, tag) = sealed.split_at(sealed.len() - tag_len);
        let j0 = first_counter(self.h, nonce);
        let expected = self.tag(j0, associated, ciphertext);
        let difference = expected[..tag_len]
            .iter()
            .zip(tag)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if difference != 0 {
            return Err(OpenError);
        }
        let mut out = ciphertext.to_vec();
        ctr(&self.aes, increment(j0), &mut out);
        Ok(out)
    }
}
