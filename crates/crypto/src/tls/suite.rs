//! The cipher suites this client offers (RFC 8446 section 9.1): the two it
//! must, TLS_AES_128_GCM_SHA256 and the ChaCha20-Poly1305 one, and
//! TLS_AES_256_GCM_SHA384.

use super::schedule::Hash;
use crate::gcm::Gcm;

/// A suite: its code point, its hash, and the AEAD key length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suite {
    pub code: u16,
    pub hash: Hash,
    pub key_len: usize,
    pub name: &'static str,
}

pub const TLS_AES_128_GCM_SHA256: Suite = Suite {
    code: 0x1301,
    hash: Hash::Sha256,
    key_len: 16,
    name: "TLS_AES_128_GCM_SHA256",
};
pub const TLS_AES_256_GCM_SHA384: Suite = Suite {
    code: 0x1302,
    hash: Hash::Sha384,
    key_len: 32,
    name: "TLS_AES_256_GCM_SHA384",
};
pub const TLS_CHACHA20_POLY1305_SHA256: Suite = Suite {
    code: 0x1303,
    hash: Hash::Sha256,
    key_len: 32,
    name: "TLS_CHACHA20_POLY1305_SHA256",
};

/// The suites offered, in the client's order of preference.
pub const OFFERED: [Suite; 3] = [
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
];

/// The suite a code point names, when this client offered it.
pub fn by_code(code: u16) -> Option<Suite> {
    OFFERED.into_iter().find(|suite| suite.code == code)
}

/// One suite's AEAD with its key.
pub enum Aead {
    Gcm(Gcm),
    ChaCha([u8; 32]),
}

impl Drop for Aead {
    fn drop(&mut self) {
        if let Aead::ChaCha(key) = self {
            crate::wipe::wipe(key);
        }
    }
}

impl Aead {
    pub fn new(suite: Suite, key: &[u8]) -> Self {
        if suite == TLS_CHACHA20_POLY1305_SHA256 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(key);
            return Aead::ChaCha(bytes);
        }
        Aead::Gcm(Gcm::new(key).expect("a suite's key length is an AES key length"))
    }

    pub fn tag_len(&self) -> usize {
        16
    }

    pub fn seal(&self, nonce: &[u8; 12], associated: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self {
            Aead::Gcm(gcm) => gcm.seal(nonce, associated, plaintext),
            Aead::ChaCha(key) => crate::chacha::seal(key, nonce, associated, plaintext),
        }
    }

    pub fn open(&self, nonce: &[u8; 12], associated: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        match self {
            Aead::Gcm(gcm) => gcm.open(nonce, associated, sealed).ok(),
            Aead::ChaCha(key) => crate::chacha::open(key, nonce, associated, sealed).ok(),
        }
    }
}
