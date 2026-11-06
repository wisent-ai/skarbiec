//! Arithmetic modulo p = 2^255 - 19, the field of Curve25519 and Ed25519,
//! in five 51-bit limbs. Every operation runs the same instructions whatever
//! the values: carries are shifts and masks, selection is by mask.

use crate::wipe::wipe_words;

const MASK: u64 = (1 << 51) - 1;

#[derive(Clone, Copy, Debug)]
pub struct Fe(pub(crate) [u64; 5]);

impl Fe {
    pub const ZERO: Fe = Fe([0; 5]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    pub fn from_small(value: u64) -> Fe {
        Fe([value, 0, 0, 0, 0])
    }

    /// The element whose little-endian encoding is `bytes`, the top bit
    /// ignored (RFC 7748 section 5). A value at or above p is taken modulo p.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let word =
            |i: usize| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().expect("8 bytes"));
        let (w0, w1, w2, w3) = (word(0), word(1), word(2), word(3));
        Fe([
            w0 & MASK,
            ((w0 >> 51) | (w1 << 13)) & MASK,
            ((w1 >> 38) | (w2 << 26)) & MASK,
            ((w2 >> 25) | (w3 << 39)) & MASK,
            (w3 >> 12) & MASK,
        ])
    }

    /// The canonical little-endian encoding, fully reduced below p.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut h = self.carry().0;
        // Make each limb below 2^51, then subtract p once when h >= p.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        h[1] += h[0] >> 51;
        h[0] &= MASK;
        h[2] += h[1] >> 51;
        h[1] &= MASK;
        h[3] += h[2] >> 51;
        h[2] &= MASK;
        h[4] += h[3] >> 51;
        h[3] &= MASK;
        h[4] &= MASK;
        let words = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        let mut out = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&w.to_le_bytes());
        }
        wipe_words(&mut h);
        out
    }

    /// Limbs brought below 2^51 (plus a small carry into limb 0).
    fn carry(&self) -> Fe {
        let mut h = self.0;
        let c = h[0] >> 51;
        h[0] &= MASK;
        h[1] += c;
        let c = h[1] >> 51;
        h[1] &= MASK;
        h[2] += c;
        let c = h[2] >> 51;
        h[2] &= MASK;
        h[3] += c;
        let c = h[3] >> 51;
        h[3] &= MASK;
        h[4] += c;
        let c = h[4] >> 51;
        h[4] &= MASK;
        h[0] += 19 * c;
        Fe(h)
    }

    pub fn add(&self, other: &Fe) -> Fe {
        Fe(std::array::from_fn(|i| self.0[i] + other.0[i])).carry()
    }

    /// `self - other`, computed as `self + 4p - other` so no limb goes
    /// below zero.
    pub fn sub(&self, other: &Fe) -> Fe {
        const FOUR_P: [u64; 5] = [
            0x1f_ffff_ffff_ffb4,
            0x1f_ffff_ffff_fffc,
            0x1f_ffff_ffff_fffc,
            0x1f_ffff_ffff_fffc,
            0x1f_ffff_ffff_fffc,
        ];
        let a = self.carry();
        let b = other.carry();
        let mut h = [0u64; 5];
        for i in 0..5 {
            h[i] = a.0[i] + FOUR_P[i] - b.0[i];
        }
        Fe(h).carry()
    }

    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    pub fn mul(&self, other: &Fe) -> Fe {
        let [a0, a1, a2, a3, a4] = self.carry().0.map(u128::from);
        let [b0, b1, b2, b3, b4] = other.carry().0.map(u128::from);
        let (b1_19, b2_19, b3_19, b4_19) = (b1 * 19, b2 * 19, b3 * 19, b4 * 19);
        let t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
        let mask = u128::from(MASK);
        let mut h = [0u64; 5];
        t1 += t0 >> 51;
        h[0] = (t0 & mask) as u64;
        t2 += t1 >> 51;
        h[1] = (t1 & mask) as u64;
        t3 += t2 >> 51;
        h[2] = (t2 & mask) as u64;
        t4 += t3 >> 51;
        h[3] = (t3 & mask) as u64;
        let c = (t4 >> 51) as u64;
        h[4] = (t4 & mask) as u64;
        h[0] += c * 19;
        h[1] += h[0] >> 51;
        h[0] &= MASK;
        Fe(h)
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    fn square_n(&self, n: usize) -> Fe {
        let mut x = *self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    /// (z^(2^250 - 1), z^11): the shared start of inversion and the square
    /// root exponent (the addition chain of the Ed25519 reference code).
    fn pow_2_250_1(&self) -> (Fe, Fe) {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(&z2);
        let z_5_0 = z11.square().mul(&z9);
        let z_10_0 = z_5_0.square_n(5).mul(&z_5_0);
        let z_20_0 = z_10_0.square_n(10).mul(&z_10_0);
        let z_40_0 = z_20_0.square_n(20).mul(&z_20_0);
        let z_50_0 = z_40_0.square_n(10).mul(&z_10_0);
        let z_100_0 = z_50_0.square_n(50).mul(&z_50_0);
        let z_200_0 = z_100_0.square_n(100).mul(&z_100_0);
        let z_250_0 = z_200_0.square_n(50).mul(&z_50_0);
        (z_250_0, z11)
    }

    /// z^(p-2), the inverse of a nonzero z, and 0 for 0.
    pub fn invert(&self) -> Fe {
        let (z_250_0, z11) = self.pow_2_250_1();
        z_250_0.square_n(5).mul(&z11)
    }

    /// z^((p-5)/8) = z^(2^252 - 3), the square root exponent.
    pub fn pow_p58(&self) -> Fe {
        let (z_250_0, _) = self.pow_2_250_1();
        z_250_0.square_n(2).mul(self)
    }

    /// Swap `a` and `b` when `choice` is 1, leave them when it is 0.
    pub fn swap(a: &mut Fe, b: &mut Fe, choice: u64) {
        let mask = 0u64.wrapping_sub(choice);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// `b` when `choice` is 1, `a` when it is 0.
    pub fn select(a: &Fe, b: &Fe, choice: u64) -> Fe {
        let mask = 0u64.wrapping_sub(choice);
        Fe(std::array::from_fn(|i| a.0[i] ^ (mask & (a.0[i] ^ b.0[i]))))
    }

    /// Whether the canonical value is odd (RFC 8032's "negative").
    pub fn is_odd(&self) -> u64 {
        u64::from(self.to_bytes()[0] & 1)
    }

    pub fn equals(&self, other: &Fe) -> bool {
        crate::wipe::equal(&self.to_bytes(), &other.to_bytes())
    }

    pub fn wipe(&mut self) {
        wipe_words(&mut self.0);
    }
}
