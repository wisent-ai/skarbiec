//! X25519 (RFC 7748): the Montgomery ladder over Curve25519, with a swap by
//! mask at every step and no branch on the scalar.

use crate::field::Fe;
use crate::wipe::wipe;

/// The u-coordinate of the base point.
pub const BASE: [u8; 32] = {
    let mut base = [0u8; 32];
    base[0] = 9;
    base
};

/// X25519(scalar, u): the scalar is clamped as RFC 7748 section 5 says.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let a24 = Fe::from_small(121_665);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let bit = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= bit;
        Fe::swap(&mut x2, &mut x3, swap);
        Fe::swap(&mut z2, &mut z3, swap);
        swap = bit;
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&a24.mul(&e)));
    }
    Fe::swap(&mut x2, &mut x3, swap);
    Fe::swap(&mut z2, &mut z3, swap);
    let out = x2.mul(&z2.invert()).to_bytes();
    for value in [&mut x2, &mut z2, &mut x3, &mut z3] {
        value.wipe();
    }
    wipe(&mut k);
    out
}

/// The public key of a secret scalar: X25519(scalar, 9).
pub fn public_key(scalar: &[u8; 32]) -> [u8; 32] {
    x25519(scalar, &BASE)
}

/// The shared secret, refused when it is all zeros: the peer's key was a
/// point of small order, and a shared secret of zero is no secret
/// (RFC 7748 section 6.1).
pub fn shared_secret(scalar: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = x25519(scalar, peer);
    if crate::wipe::equal(&shared, &[0u8; 32]) {
        None
    } else {
        Some(shared)
    }
}
