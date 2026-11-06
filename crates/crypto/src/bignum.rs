//! Unsigned big integers for verifying signatures: RSA's modular
//! exponentiation and the prime-field and scalar arithmetic of ECDSA over
//! P-256 and P-384. Every value this handles is public (a key, a signature,
//! a digest), so the arithmetic is plain, not constant time; nothing secret
//! is ever computed with it.

use std::cmp::Ordering;

/// A non-negative integer, as little-endian 64-bit limbs with no high zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Big {
    limbs: Vec<u64>,
}

impl Big {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn from_u64(value: u64) -> Self {
        let mut big = Self { limbs: vec![value] };
        big.trim();
        big
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// The integer big-endian `bytes` state.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len() / 8 + 1);
        for chunk in bytes.rchunks(8) {
            let mut limb = [0u8; 8];
            limb[8 - chunk.len()..].copy_from_slice(chunk);
            limbs.push(u64::from_be_bytes(limb));
        }
        let mut big = Self { limbs };
        big.trim();
        big
    }

    /// The integer as `length` big-endian bytes; `None` when it does not fit.
    pub fn to_be_bytes(&self, length: usize) -> Option<Vec<u8>> {
        if self.bits() > length * 8 {
            return None;
        }
        let mut out = vec![0u8; length];
        for (index, limb) in self.limbs.iter().enumerate() {
            for (byte_index, byte) in limb.to_le_bytes().iter().enumerate() {
                let at = index * 8 + byte_index;
                if at < length {
                    out[length - 1 - at] = *byte;
                }
            }
        }
        Some(out)
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// The number of bits up to the highest set one.
    pub fn bits(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => self.limbs.len() * 64 - top.leading_zeros() as usize,
        }
    }

    pub fn bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / 64)
            .is_some_and(|limb| (limb >> (index % 64)) & 1 == 1)
    }

    pub fn add(&self, other: &Self) -> Self {
        let length = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(length + 1);
        let mut carry = 0u64;
        for index in 0..length {
            let a = self.limbs.get(index).copied().unwrap_or(0);
            let b = other.limbs.get(index).copied().unwrap_or(0);
            let (sum, first) = a.overflowing_add(b);
            let (sum, second) = sum.overflowing_add(carry);
            limbs.push(sum);
            carry = u64::from(first) + u64::from(second);
        }
        if carry > 0 {
            limbs.push(carry);
        }
        let mut big = Self { limbs };
        big.trim();
        big
    }

    /// `self - other`; `None` when `other` is the larger.
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self.cmp(other) == Ordering::Less {
            return None;
        }
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0u64;
        for (index, a) in self.limbs.iter().enumerate() {
            let b = other.limbs.get(index).copied().unwrap_or(0);
            let (difference, first) = a.overflowing_sub(b);
            let (difference, second) = difference.overflowing_sub(borrow);
            limbs.push(difference);
            borrow = u64::from(first) + u64::from(second);
        }
        let mut big = Self { limbs };
        big.trim();
        Some(big)
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut limbs = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, b) in other.limbs.iter().enumerate() {
                let product = u128::from(*a) * u128::from(*b) + u128::from(limbs[i + j]) + carry;
                limbs[i + j] = product as u64;
                carry = product >> 64;
            }
            let mut k = i + other.limbs.len();
            while carry > 0 {
                let sum = u128::from(limbs[k]) + carry;
                limbs[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
        }
        let mut big = Self { limbs };
        big.trim();
        big
    }

    fn shl1(&mut self) {
        let mut carry = 0u64;
        for limb in &mut self.limbs {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if carry > 0 {
            self.limbs.push(carry);
        }
    }

    /// `self mod modulus`, by shift and subtract; `modulus` is not zero.
    pub fn rem(&self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "reduction by zero");
        if self.cmp(modulus) == Ordering::Less {
            return self.clone();
        }
        let mut remainder = Self::zero();
        for index in (0..self.bits()).rev() {
            remainder.shl1();
            if self.bit(index) {
                if remainder.limbs.is_empty() {
                    remainder.limbs.push(1);
                } else {
                    remainder.limbs[0] |= 1;
                }
            }
            if remainder.cmp(modulus) != Ordering::Less {
                remainder = remainder
                    .checked_sub(modulus)
                    .expect("remainder is at least the modulus");
            }
        }
        remainder
    }

    pub fn mod_mul(&self, other: &Self, modulus: &Self) -> Self {
        self.mul(other).rem(modulus)
    }

    pub fn mod_add(&self, other: &Self, modulus: &Self) -> Self {
        self.add(other).rem(modulus)
    }

    /// `self - other mod modulus`, both already reduced.
    pub fn mod_sub(&self, other: &Self, modulus: &Self) -> Self {
        match self.checked_sub(other) {
            Some(difference) => difference,
            None => self
                .add(modulus)
                .checked_sub(other)
                .expect("a reduced value plus the modulus exceeds another"),
        }
    }

    /// `self^exponent mod modulus`, left to right.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        let base = self.rem(modulus);
        let mut result = Self::from_u64(1).rem(modulus);
        for index in (0..exponent.bits()).rev() {
            result = result.mod_mul(&result, modulus);
            if exponent.bit(index) {
                result = result.mod_mul(&base, modulus);
            }
        }
        result
    }

    /// The inverse of `self` modulo the prime `modulus` (Fermat's little
    /// theorem); `None` for zero.
    pub fn mod_inverse_prime(&self, modulus: &Self) -> Option<Self> {
        let reduced = self.rem(modulus);
        if reduced.is_zero() {
            return None;
        }
        let exponent = modulus.checked_sub(&Self::from_u64(2))?;
        Some(reduced.mod_pow(&exponent, modulus))
    }
}

impl PartialOrd for Big {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Big {
    fn cmp(&self, other: &Self) -> Ordering {
        self.limbs
            .len()
            .cmp(&other.limbs.len())
            .then_with(|| self.limbs.iter().rev().cmp(other.limbs.iter().rev()))
    }
}

#[cfg(test)]
mod tests {
    use super::Big;

    #[test]
    fn arithmetic_holds_on_known_values() {
        let p = Big::from_u64(1_000_000_007);
        let a = Big::from_u64(123_456_789);
        assert_eq!(
            a.mod_pow(&Big::from_u64(1_000_000_006), &p),
            Big::from_u64(1)
        );
        let inverse = a.mod_inverse_prime(&p).expect("non-zero");
        assert_eq!(a.mod_mul(&inverse, &p), Big::from_u64(1));
        let big = Big::from_be_bytes(&[1; 40]);
        assert_eq!(big.to_be_bytes(40).expect("fits"), vec![1; 40]);
        assert_eq!(big.mul(&big).rem(&big), Big::zero());
        assert_eq!(big.add(&big).checked_sub(&big), Some(big.clone()));
        assert!(Big::from_u64(3).checked_sub(&Big::from_u64(4)).is_none());
    }
}
