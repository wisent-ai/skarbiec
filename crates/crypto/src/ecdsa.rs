//! ECDSA signature verification (FIPS 186-4 section 6.4) over the NIST
//! curves P-256 and P-384, the curves web certificates and TLS 1.3 servers
//! sign with. Only verification: every value is public.

use crate::bignum::Big;

/// A short Weierstrass curve y^2 = x^3 - 3x + b over GF(p), with its base
/// point G of prime order n.
pub struct Curve {
    pub name: &'static str,
    p: Big,
    b: Big,
    n: Big,
    gx: Big,
    gy: Big,
    /// Bytes of a coordinate and of a scalar.
    pub size: usize,
}

fn hex(text: &str) -> Big {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("a curve constant is hex"))
        .collect();
    Big::from_be_bytes(&bytes)
}

/// P-256 (FIPS 186-4 D.1.2.3).
pub fn p256() -> Curve {
    Curve {
        name: "P-256",
        p: hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
        b: hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
        n: hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        gx: hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        gy: hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        size: 32,
    }
}

/// P-384 (FIPS 186-4 D.1.2.4).
pub fn p384() -> Curve {
    Curve {
        name: "P-384",
        p: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
        b: hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
        n: hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
        gx: hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
        gy: hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
        size: 48,
    }
}

/// A point in Jacobian coordinates (X, Y, Z) for x = X/Z^2, y = Y/Z^3;
/// Z = 0 is the point at infinity.
#[derive(Clone)]
struct Point {
    x: Big,
    y: Big,
    z: Big,
}

impl Curve {
    fn infinity(&self) -> Point {
        Point {
            x: Big::from_u64(1),
            y: Big::from_u64(1),
            z: Big::zero(),
        }
    }

    /// Whether (x, y) is a point of the curve, both coordinates reduced.
    pub fn on_curve(&self, x: &Big, y: &Big) -> bool {
        if x >= &self.p || y >= &self.p {
            return false;
        }
        let p = &self.p;
        let left = y.mod_mul(y, p);
        let x3 = x.mod_mul(x, p).mod_mul(x, p);
        let three_x = x.mod_add(&x.mod_add(x, p), p);
        let right = x3.mod_sub(&three_x, p).mod_add(&self.b, p);
        left == right
    }

    fn double(&self, point: &Point) -> Point {
        if point.z.is_zero() || point.y.is_zero() {
            return self.infinity();
        }
        let p = &self.p;
        // a = -3: M = 3 (X - Z^2)(X + Z^2).
        let z2 = point.z.mod_mul(&point.z, p);
        let m = point.x.mod_sub(&z2, p).mod_mul(&point.x.mod_add(&z2, p), p);
        let m = m.mod_add(&m.mod_add(&m, p), p);
        let y2 = point.y.mod_mul(&point.y, p);
        let s = point.x.mod_mul(&y2, p);
        let s = s.mod_add(&s, p);
        let s = s.mod_add(&s, p);
        let x = m.mod_mul(&m, p).mod_sub(&s.mod_add(&s, p), p);
        let y4 = y2.mod_mul(&y2, p);
        let eight_y4 = y4.mod_add(&y4, p);
        let eight_y4 = eight_y4.mod_add(&eight_y4, p);
        let eight_y4 = eight_y4.mod_add(&eight_y4, p);
        let y = m.mod_mul(&s.mod_sub(&x, p), p).mod_sub(&eight_y4, p);
        let z = point.y.mod_mul(&point.z, p);
        let z = z.mod_add(&z, p);
        Point { x, y, z }
    }

    fn add(&self, a: &Point, b: &Point) -> Point {
        if a.z.is_zero() {
            return b.clone();
        }
        if b.z.is_zero() {
            return a.clone();
        }
        let p = &self.p;
        let z1z1 = a.z.mod_mul(&a.z, p);
        let z2z2 = b.z.mod_mul(&b.z, p);
        let u1 = a.x.mod_mul(&z2z2, p);
        let u2 = b.x.mod_mul(&z1z1, p);
        let s1 = a.y.mod_mul(&b.z, p).mod_mul(&z2z2, p);
        let s2 = b.y.mod_mul(&a.z, p).mod_mul(&z1z1, p);
        if u1 == u2 {
            return if s1 == s2 {
                self.double(a)
            } else {
                self.infinity()
            };
        }
        let h = u2.mod_sub(&u1, p);
        let r = s2.mod_sub(&s1, p);
        let h2 = h.mod_mul(&h, p);
        let h3 = h2.mod_mul(&h, p);
        let u1h2 = u1.mod_mul(&h2, p);
        let x = r
            .mod_mul(&r, p)
            .mod_sub(&h3, p)
            .mod_sub(&u1h2.mod_add(&u1h2, p), p);
        let y = r
            .mod_mul(&u1h2.mod_sub(&x, p), p)
            .mod_sub(&s1.mod_mul(&h3, p), p);
        let z = a.z.mod_mul(&b.z, p).mod_mul(&h, p);
        Point { x, y, z }
    }

    /// u1·G + u2·Q by one pass over the bits of both scalars.
    fn twin_multiply(&self, u1: &Big, u2: &Big, q: &Point) -> Point {
        let g = Point {
            x: self.gx.clone(),
            y: self.gy.clone(),
            z: Big::from_u64(1),
        };
        let both = self.add(&g, q);
        let mut acc = self.infinity();
        for index in (0..u1.bits().max(u2.bits())).rev() {
            acc = self.double(&acc);
            match (u1.bit(index), u2.bit(index)) {
                (true, true) => acc = self.add(&acc, &both),
                (true, false) => acc = self.add(&acc, &g),
                (false, true) => acc = self.add(&acc, q),
                (false, false) => {}
            }
        }
        acc
    }

    /// The affine x of a Jacobian point; `None` at infinity.
    fn affine_x(&self, point: &Point) -> Option<Big> {
        let z_inverse = point.z.mod_inverse_prime(&self.p)?;
        let z2 = z_inverse.mod_mul(&z_inverse, &self.p);
        Some(point.x.mod_mul(&z2, &self.p))
    }

    /// Verify signature (r, s) of `digest` under public key (qx, qy). The
    /// digest is cut to the curve's order length as FIPS 186-4 6.4 states.
    pub fn verify(&self, qx: &[u8], qy: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
        let (qx, qy) = (Big::from_be_bytes(qx), Big::from_be_bytes(qy));
        if !self.on_curve(&qx, &qy) {
            return false;
        }
        let (r, s) = (Big::from_be_bytes(r), Big::from_be_bytes(s));
        if r.is_zero() || s.is_zero() || r >= self.n || s >= self.n {
            return false;
        }
        let n_bits = self.n.bits();
        let mut e = Big::from_be_bytes(digest);
        if digest.len() * 8 > n_bits {
            let shift = digest.len() * 8 - n_bits;
            let mut truncated = Big::zero();
            for index in (shift..digest.len() * 8).rev() {
                truncated = truncated.add(&truncated);
                if e.bit(index) {
                    truncated = truncated.add(&Big::from_u64(1));
                }
            }
            e = truncated;
        }
        let Some(w) = s.mod_inverse_prime(&self.n) else {
            return false;
        };
        let u1 = e.rem(&self.n).mod_mul(&w, &self.n);
        let u2 = r.mod_mul(&w, &self.n);
        let q = Point {
            x: qx,
            y: qy,
            z: Big::from_u64(1),
        };
        let point = self.twin_multiply(&u1, &u2, &q);
        match self.affine_x(&point) {
            Some(x) => x.rem(&self.n) == r,
            None => false,
        }
    }
}
