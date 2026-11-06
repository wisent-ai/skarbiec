//! RSA signature verification (RFC 8017): RSASSA-PKCS1-v1_5, which
//! certificate chains are signed with, and RSASSA-PSS, which TLS 1.3
//! servers sign the handshake with. Only verification: every value is public.

use crate::bignum::Big;
use crate::sha::{sha256, sha384, sha512, Digest, Sha256, Sha384, Sha512};

/// A hash a signature names, with what RFC 8017 needs of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Bytes of its output.
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => sha256(data).to_vec(),
            HashAlg::Sha384 => sha384(data).to_vec(),
            HashAlg::Sha512 => sha512(data).to_vec(),
        }
    }

    fn digest_parts(self, parts: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![0u8; self.output_len()];
        match self {
            HashAlg::Sha256 => {
                let mut hash = Sha256::new();
                parts.iter().for_each(|part| hash.update(part));
                hash.finish_into(&mut out);
            }
            HashAlg::Sha384 => {
                let mut hash = Sha384::new();
                parts.iter().for_each(|part| hash.update(part));
                hash.finish_into(&mut out);
            }
            HashAlg::Sha512 => {
                let mut hash = Sha512::new();
                parts.iter().for_each(|part| hash.update(part));
                hash.finish_into(&mut out);
            }
        }
        out
    }

    /// The DER DigestInfo prefix of EMSA-PKCS1-v1_5 (RFC 8017 9.2 note 1).
    fn digest_info(self) -> &'static [u8] {
        match self {
            HashAlg::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlg::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            HashAlg::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// An RSA public key.
pub struct PublicKey {
    pub n: Big,
    pub e: Big,
}

impl PublicKey {
    pub fn new(modulus: &[u8], exponent: &[u8]) -> Self {
        Self {
            n: Big::from_be_bytes(modulus),
            e: Big::from_be_bytes(exponent),
        }
    }

    /// Bytes of the modulus.
    pub fn size(&self) -> usize {
        self.n.bits().div_ceil(8)
    }

    /// RSAVP1: the encoded message a signature carries, `size` bytes, or
    /// `None` when the signature is not below the modulus.
    fn open(&self, signature: &[u8]) -> Option<Vec<u8>> {
        if signature.len() != self.size() {
            return None;
        }
        let s = Big::from_be_bytes(signature);
        if s >= self.n {
            return None;
        }
        s.mod_pow(&self.e, &self.n).to_be_bytes(self.size())
    }

    /// RSASSA-PKCS1-v1_5 verification (RFC 8017 8.2.2) of `message`.
    pub fn verify_pkcs1v15(&self, hash: HashAlg, message: &[u8], signature: &[u8]) -> bool {
        let Some(em) = self.open(signature) else {
            return false;
        };
        let info = hash.digest_info();
        let t_len = info.len() + hash.output_len();
        if em.len() < t_len + 11 {
            return false;
        }
        let mut expected = vec![0x00, 0x01];
        expected.resize(em.len() - t_len - 1, 0xff);
        expected.push(0x00);
        expected.extend_from_slice(info);
        expected.extend_from_slice(&hash.digest(message));
        expected == em
    }

    /// RSASSA-PSS verification (RFC 8017 8.1.2 and 9.1.2) of `message`,
    /// MGF1 over the same hash, with a salt of `salt_len` bytes.
    pub fn verify_pss(
        &self,
        hash: HashAlg,
        message: &[u8],
        signature: &[u8],
        salt_len: usize,
    ) -> bool {
        let Some(em_full) = self.open(signature) else {
            return false;
        };
        let em_bits = self.n.bits() - 1;
        let em_len = em_bits.div_ceil(8);
        // EM is the low em_len bytes; any byte above them must be zero.
        let (high, em) = em_full.split_at(em_full.len() - em_len);
        if high.iter().any(|byte| *byte != 0) {
            return false;
        }
        let h_len = hash.output_len();
        if em_len < h_len + salt_len + 2 || em.last() != Some(&0xbc) {
            return false;
        }
        let (masked_db, rest) = em.split_at(em_len - h_len - 1);
        let h = &rest[..h_len];
        let unused_bits = 8 * em_len - em_bits;
        if unused_bits > 0 && masked_db[0] >> (8 - unused_bits) != 0 {
            return false;
        }
        let mut db = mgf1(hash, h, masked_db.len());
        for (byte, mask) in db.iter_mut().zip(masked_db) {
            *byte ^= mask;
        }
        if unused_bits > 0 {
            db[0] &= 0xff >> unused_bits;
        }
        let padding = em_len - h_len - salt_len - 2;
        if db[..padding].iter().any(|byte| *byte != 0) || db[padding] != 0x01 {
            return false;
        }
        let salt = &db[padding + 1..];
        let m_hash = hash.digest(message);
        let expected = hash.digest_parts(&[&[0u8; 8], &m_hash, salt]);
        expected == h
    }
}

/// MGF1 (RFC 8017 B.2.1) of `seed` to `length` bytes.
fn mgf1(hash: HashAlg, seed: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + hash.output_len());
    let mut counter = 0u32;
    while out.len() < length {
        out.extend(hash.digest_parts(&[seed, &counter.to_be_bytes()]));
        counter += 1;
    }
    out.truncate(length);
    out
}
