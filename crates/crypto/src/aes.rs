//! AES-128, AES-192 and AES-256 (FIPS 197), with no table indexed by secret
//! data: the S-box is computed for each byte as the multiplicative inverse
//! in GF(2^8) (by a fixed chain of multiplications) followed by the affine
//! map, and every multiplication runs the same eight steps whatever its
//! inputs. That is slower than tables, and the vault encrypts kilobytes.

use crate::wipe::{wipe, wipe_words};

/// A product in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, in constant time.
fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        product ^= a & 0u8.wrapping_sub(b & 1);
        let high = a >> 7;
        a = (a << 1) ^ (0x1b & 0u8.wrapping_sub(high));
        b >>= 1;
    }
    product
}

/// x^254, which is x^-1 for x != 0 and 0 for 0: always the same eleven
/// multiplications.
fn invert(x: u8) -> u8 {
    let x2 = multiply(x, x);
    let x3 = multiply(x2, x);
    let x6 = multiply(x3, x3);
    let x12 = multiply(x6, x6);
    let x15 = multiply(x12, x3);
    let x30 = multiply(x15, x15);
    let x60 = multiply(x30, x30);
    let x120 = multiply(x60, x60);
    let x240 = multiply(x120, x120);
    let x252 = multiply(x240, x12);
    multiply(x252, x2)
}

fn sub_byte(x: u8) -> u8 {
    let b = invert(x);
    b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
}

fn inv_sub_byte(s: u8) -> u8 {
    invert(s.rotate_left(1) ^ s.rotate_left(3) ^ s.rotate_left(6) ^ 0x05)
}

/// An expanded AES key, zeroed when dropped.
pub struct Aes {
    round_keys: Vec<[u8; 16]>,
}

impl Drop for Aes {
    fn drop(&mut self) {
        for key in &mut self.round_keys {
            wipe(key);
        }
    }
}

/// A key that is not 16, 24 or 32 bytes long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadKeyLength(pub usize);

impl std::fmt::Display for BadKeyLength {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "an AES key is 16, 24 or 32 bytes, not {}",
            self.0
        )
    }
}

impl std::error::Error for BadKeyLength {}

impl Aes {
    /// Expand `key` (FIPS 197 section 5.2).
    pub fn new(key: &[u8]) -> Result<Self, BadKeyLength> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            other => return Err(BadKeyLength(other)),
        };
        let rounds = nk + 6;
        let total = 4 * (rounds + 1);
        let mut words: Vec<[u8; 4]> = Vec::with_capacity(total);
        for chunk in key.chunks(4) {
            words.push([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut rcon = 1u8;
        for i in nk..total {
            let mut temp = words[i - 1];
            if i % nk == 0 {
                temp = [
                    sub_byte(temp[1]) ^ rcon,
                    sub_byte(temp[2]),
                    sub_byte(temp[3]),
                    sub_byte(temp[0]),
                ];
                rcon = multiply(rcon, 2);
            } else if nk > 6 && i % nk == 4 {
                temp = temp.map(sub_byte);
            }
            let previous = words[i - nk];
            words.push([
                previous[0] ^ temp[0],
                previous[1] ^ temp[1],
                previous[2] ^ temp[2],
                previous[3] ^ temp[3],
            ]);
        }
        let round_keys = words
            .chunks(4)
            .map(|four| {
                let mut key = [0u8; 16];
                for (column, word) in four.iter().enumerate() {
                    key[4 * column..4 * column + 4].copy_from_slice(word);
                }
                key
            })
            .collect();
        wipe_words(&mut words);
        Ok(Self { round_keys })
    }

    fn rounds(&self) -> usize {
        self.round_keys.len() - 1
    }

    /// Encrypt one 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        add(block, &self.round_keys[0]);
        for round in 1..=self.rounds() {
            for byte in block.iter_mut() {
                *byte = sub_byte(*byte);
            }
            shift_rows(block);
            if round != self.rounds() {
                mix_columns(block);
            }
            add(block, &self.round_keys[round]);
        }
    }

    /// Decrypt one 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let rounds = self.rounds();
        add(block, &self.round_keys[rounds]);
        for round in (0..rounds).rev() {
            inv_shift_rows(block);
            for byte in block.iter_mut() {
                *byte = inv_sub_byte(*byte);
            }
            add(block, &self.round_keys[round]);
            if round != 0 {
                inv_mix_columns(block);
            }
        }
    }
}

fn add(block: &mut [u8; 16], key: &[u8; 16]) {
    for (b, k) in block.iter_mut().zip(key) {
        *b ^= k;
    }
}

/// The state is column-major: byte `4 * column + row`.
fn shift_rows(block: &mut [u8; 16]) {
    let s = *block;
    for row in 1..4 {
        for column in 0..4 {
            block[4 * column + row] = s[4 * ((column + row) % 4) + row];
        }
    }
}

fn inv_shift_rows(block: &mut [u8; 16]) {
    let s = *block;
    for row in 1..4 {
        for column in 0..4 {
            block[4 * ((column + row) % 4) + row] = s[4 * column + row];
        }
    }
}

fn mix_columns(block: &mut [u8; 16]) {
    for column in block.chunks_mut(4) {
        let [a, b, c, d] = [column[0], column[1], column[2], column[3]];
        column[0] = multiply(a, 2) ^ multiply(b, 3) ^ c ^ d;
        column[1] = a ^ multiply(b, 2) ^ multiply(c, 3) ^ d;
        column[2] = a ^ b ^ multiply(c, 2) ^ multiply(d, 3);
        column[3] = multiply(a, 3) ^ b ^ c ^ multiply(d, 2);
    }
}

fn inv_mix_columns(block: &mut [u8; 16]) {
    for column in block.chunks_mut(4) {
        let [a, b, c, d] = [column[0], column[1], column[2], column[3]];
        column[0] = multiply(a, 14) ^ multiply(b, 11) ^ multiply(c, 13) ^ multiply(d, 9);
        column[1] = multiply(a, 9) ^ multiply(b, 14) ^ multiply(c, 11) ^ multiply(d, 13);
        column[2] = multiply(a, 13) ^ multiply(b, 9) ^ multiply(c, 14) ^ multiply(d, 11);
        column[3] = multiply(a, 11) ^ multiply(b, 13) ^ multiply(c, 9) ^ multiply(d, 14);
    }
}

/// CFB with a full-block segment (NIST SP 800-38A section 6.3, CFB128), the
/// mode OpenPGP's symmetrically encrypted integrity protected data uses with
/// an all-zero IV (RFC 4880 section 5.13). A last partial block is the
/// leading bytes of the keystream block.
pub fn cfb_encrypt(aes: &Aes, iv: &[u8; 16], data: &mut [u8]) {
    let mut feedback = *iv;
    for chunk in data.chunks_mut(16) {
        aes.encrypt_block(&mut feedback);
        for (byte, key) in chunk.iter_mut().zip(feedback.iter()) {
            *byte ^= key;
        }
        feedback[..chunk.len()].copy_from_slice(chunk);
    }
    wipe(&mut feedback);
}

/// The inverse of [`cfb_encrypt`].
pub fn cfb_decrypt(aes: &Aes, iv: &[u8; 16], data: &mut [u8]) {
    let mut feedback = *iv;
    for chunk in data.chunks_mut(16) {
        let mut next = [0u8; 16];
        next[..chunk.len()].copy_from_slice(chunk);
        aes.encrypt_block(&mut feedback);
        for (byte, key) in chunk.iter_mut().zip(feedback.iter()) {
            *byte ^= key;
        }
        feedback = next;
    }
    wipe(&mut feedback);
}

/// AES key wrap (RFC 3394 section 2.2.1): `key_data` is a whole number of
/// 8-byte blocks, at least two.
pub fn key_wrap(kek: &Aes, key_data: &[u8]) -> Option<Vec<u8>> {
    if key_data.len() < 16 || !key_data.len().is_multiple_of(8) {
        return None;
    }
    let n = key_data.len() / 8;
    let mut a = [0xa6u8; 8];
    let mut r: Vec<[u8; 8]> = key_data
        .chunks(8)
        .map(|c| c.try_into().expect("8 bytes"))
        .collect();
    for j in 0..6 {
        for (i, block) in r.iter_mut().enumerate() {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(block);
            kek.encrypt_block(&mut b);
            let t = (n * j + i + 1) as u64;
            a.copy_from_slice(&b[..8]);
            for (x, y) in a.iter_mut().zip(t.to_be_bytes()) {
                *x ^= y;
            }
            block.copy_from_slice(&b[8..]);
            wipe(&mut b);
        }
    }
    let mut out = a.to_vec();
    for block in &mut r {
        out.extend_from_slice(block);
        wipe(block);
    }
    Some(out)
}

/// AES key unwrap (RFC 3394 section 2.2.2), `None` when the integrity check
/// fails or the input is not a whole number of 8-byte blocks, at least three.
pub fn key_unwrap(kek: &Aes, wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return None;
    }
    let n = wrapped.len() / 8 - 1;
    let mut a: [u8; 8] = wrapped[..8].try_into().expect("8 bytes");
    let mut r: Vec<[u8; 8]> = wrapped[8..]
        .chunks(8)
        .map(|c| c.try_into().expect("8 bytes"))
        .collect();
    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n * j + i + 1) as u64;
            let mut b = [0u8; 16];
            for (x, (y, z)) in b.iter_mut().zip(a.iter().zip(t.to_be_bytes())) {
                *x = y ^ z;
            }
            b[8..].copy_from_slice(&r[i]);
            kek.decrypt_block(&mut b);
            a.copy_from_slice(&b[..8]);
            r[i].copy_from_slice(&b[8..]);
            wipe(&mut b);
        }
    }
    let mut out = Vec::with_capacity(8 * n);
    for block in &mut r {
        out.extend_from_slice(block);
        wipe(block);
    }
    if crate::wipe::equal(&a, &[0xa6; 8]) {
        Some(out)
    } else {
        wipe(&mut out);
        None
    }
}
