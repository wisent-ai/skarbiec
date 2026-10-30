//! Ed25519 (RFC 8032 section 5.1): signing in constant time (a fixed
//! double-and-add with selection by mask, scalar arithmetic modulo L by a
//! fixed bit-serial reduction) and verification. The curve constants are
//! derived from their definitions when first used, not written out.

use crate::field::Fe;
use crate::sha::sha512;
use crate::wipe::{wipe, wipe_words};
use std::sync::LazyLock;

/// The group order L = 2^252 + 27742317777372353535851937790883648493, in
/// little-endian 64-bit words.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

/// x^e for a public exponent `e` (little-endian bytes).
fn pow(x: &Fe, e: &[u8; 32]) -> Fe {
    let mut result = Fe::ONE;
    for i in (0..256).rev() {
        result = result.square();
        if (e[i / 8] >> (i % 8)) & 1 == 1 {
            result = result.mul(x);
        }
    }
    result
}

struct Constants {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
    base: Point,
}

static CONSTANTS: LazyLock<Constants> = LazyLock::new(|| {
    let d = Fe::from_small(121_665)
        .neg()
        .mul(&Fe::from_small(121_666).invert());
    // sqrt(-1) = 2^((p-1)/4), and (p-1)/4 = 2^253 - 5.
    let mut exponent = [0xffu8; 32];
    exponent[0] = 0xfb;
    exponent[31] = 0x1f;
    let sqrt_m1 = pow(&Fe::from_small(2), &exponent);
    // The base point has y = 4/5 and an even x (RFC 8032 section 5.1).
    let y = Fe::from_small(4).mul(&Fe::from_small(5).invert());
    let partial = Constants {
        d,
        d2: d.add(&d),
        sqrt_m1,
        base: Point::IDENTITY,
    };
    let base = decompress_with(&partial, &y.to_bytes()).expect("the base point decodes");
    Constants { base, ..partial }
});

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Addition in extended coordinates (add-2008-hwcd-3), complete on the
    /// curve, so doubling uses it too.
    fn add(&self, other: &Point) -> Point {
        let c = &*CONSTANTS;
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let cc = self.t.mul(&c.d2).mul(&other.t);
        let d = self.z.add(&self.z).mul(&other.z);
        let (e, f, g, h) = (b.sub(&a), d.sub(&cc), d.add(&cc), b.add(&a));
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    fn select(a: &Point, b: &Point, choice: u64) -> Point {
        Point {
            x: Fe::select(&a.x, &b.x, choice),
            y: Fe::select(&a.y, &b.y, choice),
            z: Fe::select(&a.z, &b.z, choice),
            t: Fe::select(&a.t, &b.t, choice),
        }
    }

    /// [scalar]self, the same additions whatever the scalar's bits.
    fn multiply(&self, scalar: &[u8; 32]) -> Point {
        let mut q = Point::IDENTITY;
        for i in (0..256).rev() {
            q = q.add(&q);
            let sum = q.add(self);
            q = Point::select(&q, &sum, u64::from((scalar[i / 8] >> (i % 8)) & 1));
        }
        q
    }

    fn compress(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi);
        let mut out = self.y.mul(&zi).to_bytes();
        out[31] |= (x.is_odd() as u8) << 7;
        out
    }

    fn wipe(&mut self) {
        self.x.wipe();
        self.y.wipe();
        self.z.wipe();
        self.t.wipe();
    }
}

/// The point an encoding names (RFC 8032 section 5.1.3), or none when it
/// names none: y at or above p, x^2 with no square root, or x = 0 with the
/// sign bit set.
fn decompress_with(c: &Constants, bytes: &[u8; 32]) -> Option<Point> {
    let sign = u64::from(bytes[31] >> 7);
    let mut y_bytes = *bytes;
    y_bytes[31] &= 0x7f;
    let y = Fe::from_bytes(&y_bytes);
    if y.to_bytes() != y_bytes {
        return None;
    }
    let yy = y.square();
    let u = yy.sub(&Fe::ONE);
    let v = c.d.mul(&yy).add(&Fe::ONE);
    let v3 = v.square().mul(&v);
    let v7 = v3.square().mul(&v);
    let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
    let vxx = v.mul(&x.square());
    if !vxx.equals(&u) {
        if vxx.equals(&u.neg()) {
            x = x.mul(&c.sqrt_m1);
        } else {
            return None;
        }
    }
    if x.equals(&Fe::ZERO) && sign == 1 {
        return None;
    }
    if x.is_odd() != sign {
        x = x.neg();
    }
    Some(Point {
        x,
        y,
        z: Fe::ONE,
        t: x.mul(&y),
    })
}

/// `wide` (little-endian, at most 512 bits) modulo L, one bit at a time:
/// the same doubling and masked subtraction for every bit.
fn reduce(wide: &[u8]) -> [u8; 32] {
    let mut r = [0u64; 5];
    for i in (0..wide.len() * 8).rev() {
        let bit = u64::from((wide[i / 8] >> (i % 8)) & 1);
        let mut carry = bit;
        for limb in r.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        // r - L, kept when it does not go below zero.
        let mut diff = [0u64; 5];
        let mut borrow = 0u64;
        for j in 0..5 {
            let l = if j < 4 { L[j] } else { 0 };
            let (d1, b1) = r[j].overflowing_sub(l);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[j] = d2;
            borrow = u64::from(b1 | b2);
        }
        let keep = borrow.wrapping_sub(1);
        for j in 0..5 {
            r[j] = (r[j] & !keep) | (diff[j] & keep);
        }
        wipe_words(&mut diff);
    }
    let mut out = [0u8; 32];
    for j in 0..4 {
        out[8 * j..8 * j + 8].copy_from_slice(&r[j].to_le_bytes());
    }
    wipe_words(&mut r);
    out
}

/// (a * b + c) modulo L, through the full 512-bit product.
fn mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let words = |x: &[u8; 32]| -> [u64; 4] {
        std::array::from_fn(|i| {
            u64::from_le_bytes(x[8 * i..8 * i + 8].try_into().expect("8 bytes"))
        })
    };
    let (aw, bw, cw) = (words(a), words(b), words(c));
    let mut product = [0u64; 9];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = u128::from(aw[i]) * u128::from(bw[j]) + u128::from(product[i + j]) + carry;
            product[i + j] = t as u64;
            carry = t >> 64;
        }
        product[i + 4] = carry as u64;
    }
    let mut carry = 0u128;
    for (i, word) in product.iter_mut().enumerate() {
        let add = if i < 4 { cw[i] } else { 0 };
        let t = u128::from(*word) + u128::from(add) + carry;
        *word = t as u64;
        carry = t >> 64;
    }
    let mut bytes = [0u8; 72];
    for (i, word) in product.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
    }
    let out = reduce(&bytes);
    wipe(&mut bytes);
    wipe_words(&mut product);
    out
}

/// The expanded secret: the clamped scalar and the nonce prefix (RFC 8032
/// section 5.1.5).
fn expand(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut h = sha512(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&h[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    wipe(&mut h);
    (scalar, prefix)
}

/// The public key of a 32-byte secret seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let (mut scalar, mut prefix) = expand(seed);
    let mut a = CONSTANTS.base.multiply(&scalar);
    let out = a.compress();
    a.wipe();
    wipe(&mut scalar);
    wipe(&mut prefix);
    out
}

fn sha512_of(parts: &[&[u8]]) -> [u8; 64] {
    use crate::sha::{Digest, Sha512};
    let mut hash = Sha512::new();
    for part in parts {
        hash.update(part);
    }
    let mut out = [0u8; 64];
    hash.finish_into(&mut out);
    out
}

/// The Ed25519 signature of `message` under `seed` (RFC 8032 5.1.6).
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let (mut scalar, mut prefix) = expand(seed);
    let base = CONSTANTS.base;
    let public = base.multiply(&scalar).compress();
    let mut nonce_wide = sha512_of(&[&prefix, message]);
    let mut nonce = reduce(&nonce_wide);
    let mut r_point = base.multiply(&nonce);
    let r = r_point.compress();
    let k = reduce(&sha512_of(&[&r, &public, message]));
    let s = mul_add(&k, &scalar, &nonce);
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r);
    signature[32..].copy_from_slice(&s);
    r_point.wipe();
    wipe(&mut scalar);
    wipe(&mut prefix);
    wipe(&mut nonce_wide);
    wipe(&mut nonce);
    signature
}

/// Whether `signature` is `public`'s signature of `message` (RFC 8032
/// 5.1.7): S below L, R and A points of the curve, and [S]B = R + [k]A.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let c = &*CONSTANTS;
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature[32..]);
    if reduce(&s) != s {
        return false;
    }
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let (Some(a), Some(r)) = (decompress_with(c, public), decompress_with(c, &r_bytes)) else {
        return false;
    };
    let k = reduce(&sha512_of(&[&r_bytes, public, message]));
    let left = c.base.multiply(&s).compress();
    let right = r.add(&a.multiply(&k)).compress();
    left == right
}
