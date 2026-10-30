//! OCB (RFC 7253) over AES, the AEAD mode of OpenPGP's AEAD encrypted data
//! packet and of gpg-agent's protected keys. Every value that depends on the
//! key or the data is computed without branching on it.

use crate::aes::Aes;
use crate::wipe::{equal, wipe};

/// Doubling in GF(2^128) (RFC 7253 section 2), in constant time.
fn double(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let carry = block[0] >> 7;
    for i in 0..15 {
        out[i] = (block[i] << 1) | (block[i + 1] >> 7);
    }
    out[15] = (block[15] << 1) ^ (0x87 & 0u8.wrapping_sub(carry));
    out
}

fn xor_into(target: &mut [u8; 16], other: &[u8; 16]) {
    for (t, o) in target.iter_mut().zip(other) {
        *t ^= o;
    }
}

/// OCB with one key and a tag of `tag_len` bytes.
pub struct Ocb<'a> {
    aes: &'a Aes,
    l_star: [u8; 16],
    l_dollar: [u8; 16],
    l: Vec<[u8; 16]>,
    tag_len: usize,
}

impl Drop for Ocb<'_> {
    fn drop(&mut self) {
        wipe(&mut self.l_star);
        wipe(&mut self.l_dollar);
        for l in &mut self.l {
            wipe(l);
        }
    }
}

/// Why OCB refused: a nonce or tag of a length it does not take, or a
/// message whose tag does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcbError {
    NonceLength(usize),
    TagLength(usize),
    TooShort,
    Forged,
}

impl std::fmt::Display for OcbError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonceLength(n) => write!(formatter, "an OCB nonce is 1 to 15 bytes, not {n}"),
            Self::TagLength(n) => write!(
                formatter,
                "an OCB tag is 16 bytes (or the 12 and 8 RFC 7253 also defines), not {n}"
            ),
            Self::TooShort => write!(formatter, "the OCB ciphertext is shorter than its tag"),
            Self::Forged => write!(
                formatter,
                "the OCB tag does not match: the data or its key is not the one sealed"
            ),
        }
    }
}

impl std::error::Error for OcbError {}

impl<'a> Ocb<'a> {
    /// OCB with a tag of `tag_len` bytes: 16, as everything Skarbiec seals
    /// and opens uses, or the 12 and 8 RFC 7253 also defines, for its
    /// vectors. Any shorter tag is refused.
    pub fn new(aes: &'a Aes, tag_len: usize) -> Result<Self, OcbError> {
        if !matches!(tag_len, 8 | 12 | 16) {
            return Err(OcbError::TagLength(tag_len));
        }
        let mut l_star = [0u8; 16];
        aes.encrypt_block(&mut l_star);
        let l_dollar = double(&l_star);
        let mut l = vec![double(&l_dollar)];
        // Enough for 2^32 blocks; a vault item is a few blocks.
        for i in 1..32 {
            let next = double(&l[i - 1]);
            l.push(next);
        }
        Ok(Self {
            aes,
            l_star,
            l_dollar,
            l,
            tag_len,
        })
    }

    /// L_{ntz(i)}: the table index is the block number's trailing zeros,
    /// which depends on the length of the data, never its content.
    fn l_at(&self, i: usize) -> &[u8; 16] {
        &self.l[i.trailing_zeros() as usize]
    }

    fn initial_offset(&self, nonce: &[u8]) -> Result<[u8; 16], OcbError> {
        if nonce.is_empty() || nonce.len() > 15 {
            return Err(OcbError::NonceLength(nonce.len()));
        }
        let mut block = [0u8; 16];
        block[0] = (((self.tag_len * 8) % 128) as u8) << 1;
        block[16 - nonce.len() - 1] |= 1;
        block[16 - nonce.len()..].copy_from_slice(nonce);
        let bottom = (block[15] & 0x3f) as usize;
        block[15] &= 0xc0;
        let mut ktop = block;
        self.aes.encrypt_block(&mut ktop);
        let mut stretch = [0u8; 24];
        stretch[..16].copy_from_slice(&ktop);
        for i in 0..8 {
            stretch[16 + i] = ktop[i] ^ ktop[i + 1];
        }
        // Offset_0 = Stretch[1+bottom..128+bottom]: a bit shift by the
        // nonce's low six bits, which are public.
        let mut offset = [0u8; 16];
        let (bytes, bits) = (bottom / 8, bottom % 8);
        for (i, byte) in offset.iter_mut().enumerate() {
            let high = stretch[i + bytes];
            let low = stretch[i + bytes + 1];
            *byte = if bits == 0 {
                high
            } else {
                (high << bits) | (low >> (8 - bits))
            };
        }
        wipe(&mut stretch);
        wipe(&mut ktop);
        Ok(offset)
    }

    fn hash(&self, associated: &[u8]) -> [u8; 16] {
        let mut sum = [0u8; 16];
        let mut offset = [0u8; 16];
        let (blocks, rest) = associated.as_chunks::<16>();
        for (i, chunk) in blocks.iter().enumerate() {
            xor_into(&mut offset, self.l_at(i + 1));
            let mut block = *chunk;
            xor_into(&mut block, &offset);
            self.aes.encrypt_block(&mut block);
            xor_into(&mut sum, &block);
        }
        if !rest.is_empty() {
            xor_into(&mut offset, &self.l_star);
            let mut block = [0u8; 16];
            block[..rest.len()].copy_from_slice(rest);
            block[rest.len()] = 0x80;
            xor_into(&mut block, &offset);
            self.aes.encrypt_block(&mut block);
            xor_into(&mut sum, &block);
        }
        sum
    }

    /// Encrypt `plaintext`, returning ciphertext followed by the tag.
    pub fn seal(
        &self,
        nonce: &[u8],
        associated: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OcbError> {
        let mut offset = self.initial_offset(nonce)?;
        let mut checksum = [0u8; 16];
        let mut out = Vec::with_capacity(plaintext.len() + self.tag_len);
        let (blocks, rest) = plaintext.as_chunks::<16>();
        for (i, chunk) in blocks.iter().enumerate() {
            xor_into(&mut offset, self.l_at(i + 1));
            let mut block = *chunk;
            xor_into(&mut checksum, &block);
            xor_into(&mut block, &offset);
            self.aes.encrypt_block(&mut block);
            xor_into(&mut block, &offset);
            out.extend_from_slice(&block);
        }
        if !rest.is_empty() {
            xor_into(&mut offset, &self.l_star);
            let mut pad = offset;
            self.aes.encrypt_block(&mut pad);
            out.extend(rest.iter().zip(pad.iter()).map(|(p, k)| p ^ k));
            let mut padded = [0u8; 16];
            padded[..rest.len()].copy_from_slice(rest);
            padded[rest.len()] = 0x80;
            xor_into(&mut checksum, &padded);
            wipe(&mut pad);
        }
        let mut tag = checksum;
        xor_into(&mut tag, &offset);
        xor_into(&mut tag, &self.l_dollar);
        self.aes.encrypt_block(&mut tag);
        xor_into(&mut tag, &self.hash(associated));
        out.extend_from_slice(&tag[..self.tag_len]);
        wipe(&mut checksum);
        wipe(&mut offset);
        Ok(out)
    }

    /// Decrypt `sealed` (ciphertext followed by the tag); the plaintext only
    /// when the tag verifies.
    pub fn open(
        &self,
        nonce: &[u8],
        associated: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, OcbError> {
        if sealed.len() < self.tag_len {
            return Err(OcbError::TooShort);
        }
        let (ciphertext, tag) = sealed.split_at(sealed.len() - self.tag_len);
        let mut offset = self.initial_offset(nonce)?;
        let mut checksum = [0u8; 16];
        let mut out = Vec::with_capacity(ciphertext.len());
        let (blocks, rest) = ciphertext.as_chunks::<16>();
        for (i, chunk) in blocks.iter().enumerate() {
            xor_into(&mut offset, self.l_at(i + 1));
            let mut block = *chunk;
            xor_into(&mut block, &offset);
            self.aes.decrypt_block(&mut block);
            xor_into(&mut block, &offset);
            xor_into(&mut checksum, &block);
            out.extend_from_slice(&block);
        }
        if !rest.is_empty() {
            xor_into(&mut offset, &self.l_star);
            let mut pad = offset;
            self.aes.encrypt_block(&mut pad);
            let start = out.len();
            out.extend(rest.iter().zip(pad.iter()).map(|(c, k)| c ^ k));
            let mut padded = [0u8; 16];
            padded[..rest.len()].copy_from_slice(&out[start..]);
            padded[rest.len()] = 0x80;
            xor_into(&mut checksum, &padded);
            wipe(&mut pad);
            wipe(&mut padded);
        }
        let mut expected = checksum;
        xor_into(&mut expected, &offset);
        xor_into(&mut expected, &self.l_dollar);
        self.aes.encrypt_block(&mut expected);
        xor_into(&mut expected, &self.hash(associated));
        let verified = equal(&expected[..self.tag_len], tag);
        wipe(&mut checksum);
        wipe(&mut offset);
        if verified {
            Ok(out)
        } else {
            wipe(&mut out);
            Err(OcbError::Forged)
        }
    }
}
