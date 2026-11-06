//! SHA-1, SHA-256 and SHA-512 (FIPS 180-4). SHA-1 is here only because
//! OpenPGP uses it: the modification detection code of older items, v4 key
//! fingerprints and the S2K of protected keys. Nothing new is written with it.

use crate::wipe::wipe;

/// A hash this crate computes, in one interface.
pub trait Digest: Sized {
    /// Bytes of the digest.
    const OUTPUT: usize;
    /// Bytes of one block, as HMAC needs it.
    const BLOCK: usize;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    /// The digest, written into `out` (`OUTPUT` bytes).
    fn finish_into(self, out: &mut [u8]);
}

macro_rules! buffered {
    ($name:ident, $block:expr, $state:ty, $len:ty) => {
        pub struct $name {
            state: $state,
            buffer: [u8; $block],
            filled: usize,
            length: $len,
        }

        impl Drop for $name {
            fn drop(&mut self) {
                wipe(&mut self.buffer);
            }
        }

        impl $name {
            fn absorb(&mut self, mut data: &[u8]) {
                self.length = self.length.wrapping_add(data.len() as $len);
                if self.filled > 0 {
                    let take = ($block - self.filled).min(data.len());
                    self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);
                    self.filled += take;
                    data = &data[take..];
                    if self.filled < $block {
                        return;
                    }
                    let block = self.buffer;
                    Self::compress(&mut self.state, &block);
                    self.filled = 0;
                }
                while data.len() >= $block {
                    let mut block = [0u8; $block];
                    block.copy_from_slice(&data[..$block]);
                    Self::compress(&mut self.state, &block);
                    data = &data[$block..];
                }
                self.buffer[..data.len()].copy_from_slice(data);
                self.filled = data.len();
            }
        }
    };
}

buffered!(Sha1, 64, [u32; 5], u64);
buffered!(Sha256, 64, [u32; 8], u64);
buffered!(Sha512, 128, [u64; 8], u128);

impl Sha1 {
    fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
}

impl Digest for Sha1 {
    const OUTPUT: usize = 20;
    const BLOCK: usize = 64;
    fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            buffer: [0; 64],
            filled: 0,
            length: 0,
        }
    }
    fn update(&mut self, data: &[u8]) {
        self.absorb(data);
    }
    fn finish_into(mut self, out: &mut [u8]) {
        let bits = self.length.wrapping_mul(8);
        pad64(&mut self, bits);
        for (chunk, word) in out.chunks_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

/// The FIPS 180-4 padding of a 64-byte-block hash: 0x80, zeros, the bit
/// length in 8 big-endian bytes.
fn pad64<H: Pad64>(hash: &mut H, bits: u64) {
    let mut tail = [0u8; 72];
    tail[0] = 0x80;
    let filled = hash.filled();
    let zeros = if filled < 56 {
        55 - filled
    } else {
        119 - filled
    };
    tail[1 + zeros..9 + zeros].copy_from_slice(&bits.to_be_bytes());
    hash.absorb_raw(&tail[..9 + zeros]);
}

trait Pad64 {
    fn filled(&self) -> usize;
    fn absorb_raw(&mut self, data: &[u8]);
}

impl Pad64 for Sha1 {
    fn filled(&self) -> usize {
        self.filled
    }
    fn absorb_raw(&mut self, data: &[u8]) {
        self.absorb(data);
    }
}

impl Pad64 for Sha256 {
    fn filled(&self) -> usize {
        self.filled
    }
    fn absorb_raw(&mut self, data: &[u8]) {
        self.absorb(data);
    }
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

impl Digest for Sha256 {
    const OUTPUT: usize = 32;
    const BLOCK: usize = 64;
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            filled: 0,
            length: 0,
        }
    }
    fn update(&mut self, data: &[u8]) {
        self.absorb(data);
    }
    fn finish_into(mut self, out: &mut [u8]) {
        let bits = self.length.wrapping_mul(8);
        pad64(&mut self, bits);
        for (chunk, word) in out.chunks_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

impl Sha512 {
    fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&block[8 * i..8 * i + 8]);
            *word = u64::from_be_bytes(bytes);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

impl Digest for Sha512 {
    const OUTPUT: usize = 64;
    const BLOCK: usize = 128;
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0; 128],
            filled: 0,
            length: 0,
        }
    }
    fn update(&mut self, data: &[u8]) {
        self.absorb(data);
    }
    fn finish_into(mut self, out: &mut [u8]) {
        let bits = self.length.wrapping_mul(8);
        let mut tail = [0u8; 144];
        tail[0] = 0x80;
        let filled = self.filled;
        let zeros = if filled < 112 {
            111 - filled
        } else {
            239 - filled
        };
        tail[1 + zeros..17 + zeros].copy_from_slice(&bits.to_be_bytes());
        self.absorb(&tail[..17 + zeros]);
        for (chunk, word) in out.chunks_mut(8).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

impl Sha512 {
    /// SHA-512's padding, leaving the state for SHA-512 or SHA-384 to read.
    fn pad(&mut self) {
        let bits = self.length.wrapping_mul(8);
        let mut tail = [0u8; 144];
        tail[0] = 0x80;
        let filled = self.filled;
        let zeros = if filled < 112 {
            111 - filled
        } else {
            239 - filled
        };
        tail[1 + zeros..17 + zeros].copy_from_slice(&bits.to_be_bytes());
        self.absorb(&tail[..17 + zeros]);
    }
}

/// SHA-384 (FIPS 180-4 section 6.5): SHA-512 from its own initial hash
/// value, the output cut to 48 bytes. TLS 1.3 hashes its transcript with it
/// for TLS_AES_256_GCM_SHA384, and certificates sign with ECDSA over it.
pub struct Sha384(Sha512);

impl Digest for Sha384 {
    const OUTPUT: usize = 48;
    const BLOCK: usize = 128;
    fn new() -> Self {
        Self(Sha512 {
            state: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            buffer: [0; 128],
            filled: 0,
            length: 0,
        })
    }
    fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }
    fn finish_into(mut self, out: &mut [u8]) {
        self.0.pad();
        for (chunk, word) in out.chunks_mut(8).zip(self.0.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

/// SHA-1 of `data`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    one_shot::<Sha1, 20>(data)
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    one_shot::<Sha256, 32>(data)
}

/// SHA-512 of `data`.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    one_shot::<Sha512, 64>(data)
}

/// SHA-384 of `data`.
pub fn sha384(data: &[u8]) -> [u8; 48] {
    one_shot::<Sha384, 48>(data)
}

fn one_shot<D: Digest, const N: usize>(data: &[u8]) -> [u8; N] {
    let mut hash = D::new();
    hash.update(data);
    let mut out = [0u8; N];
    hash.finish_into(&mut out);
    out
}
