//! The TLS 1.3 key schedule (RFC 8446 section 7): HKDF-Extract and
//! HKDF-Expand-Label over the cipher suite's hash, the secrets each stage
//! derives from the transcript, and the traffic keys and IVs records are
//! sealed with.

use crate::hmac::hmac_into;
use crate::sha::{Digest, Sha256, Sha384};
use crate::wipe::wipe;

/// The hash a cipher suite names: SHA-256 or SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    /// Bytes of its output.
    pub fn output_len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
        }
    }

    /// The hash of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; self.output_len()];
        match self {
            Hash::Sha256 => {
                let mut hash = Sha256::new();
                hash.update(data);
                hash.finish_into(&mut out);
            }
            Hash::Sha384 => {
                let mut hash = Sha384::new();
                hash.update(data);
                hash.finish_into(&mut out);
            }
        }
        out
    }

    /// HMAC of `message` under `key` with this hash.
    pub fn hmac(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; self.output_len()];
        match self {
            Hash::Sha256 => hmac_into::<Sha256>(key, message, &mut out),
            Hash::Sha384 => hmac_into::<Sha384>(key, message, &mut out),
        }
        out
    }

    /// HKDF-Extract (RFC 5869 section 2.2). An empty salt is the hash's
    /// length of zeros, as RFC 5869 and RFC 8446 7.1 state.
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let zeros = vec![0u8; self.output_len()];
        let salt = if salt.is_empty() { &zeros } else { salt };
        self.hmac(salt, ikm)
    }

    /// HKDF-Expand (RFC 5869 section 2.3) to `length` bytes, at most 255
    /// blocks of the hash, which every TLS label stays within.
    pub fn expand(self, prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        assert!(
            length <= 255 * self.output_len(),
            "HKDF-Expand beyond 255 blocks"
        );
        let mut okm = Vec::with_capacity(length);
        let mut previous: Vec<u8> = Vec::new();
        let mut counter = 1u8;
        while okm.len() < length {
            let mut input = previous.clone();
            input.extend_from_slice(info);
            input.push(counter);
            let block = self.hmac(prk, &input);
            wipe(&mut input);
            let take = (length - okm.len()).min(block.len());
            okm.extend_from_slice(&block[..take]);
            wipe(&mut previous);
            previous = block;
            counter = counter.wrapping_add(1);
        }
        wipe(&mut previous);
        okm
    }

    /// HKDF-Expand-Label (RFC 8446 section 7.1): the label is prefixed
    /// "tls13 " and bound with the context and the length asked for.
    pub fn expand_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let full = format!("tls13 {label}");
        let mut info = Vec::with_capacity(4 + full.len() + context.len());
        info.extend_from_slice(&(length as u16).to_be_bytes());
        info.push(full.len() as u8);
        info.extend_from_slice(full.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.expand(secret, &info, length)
    }

    /// Derive-Secret (RFC 8446 section 7.1): a label expanded over the hash
    /// of the transcript so far.
    pub fn derive_secret(self, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, transcript_hash, self.output_len())
    }
}

/// A sealing key and the IV its per-record nonces are made from.
pub struct TrafficKey {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

impl Drop for TrafficKey {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.iv);
    }
}

/// The key and IV a traffic secret gives (RFC 8446 section 7.3).
pub fn traffic_key(hash: Hash, secret: &[u8], key_len: usize) -> TrafficKey {
    TrafficKey {
        key: hash.expand_label(secret, "key", &[], key_len),
        iv: hash.expand_label(secret, "iv", &[], 12),
    }
}

/// The secrets of one handshake, stage by stage (RFC 8446 section 7.1,
/// without a pre-shared key).
pub struct Schedule {
    pub hash: Hash,
    pub handshake: Vec<u8>,
    pub master: Vec<u8>,
}

impl Drop for Schedule {
    fn drop(&mut self) {
        wipe(&mut self.handshake);
        wipe(&mut self.master);
    }
}

impl Schedule {
    /// From the (EC)DHE shared secret: the early secret with no PSK, the
    /// handshake secret, and the master secret.
    pub fn new(hash: Hash, shared: &[u8]) -> Self {
        let zeros = vec![0u8; hash.output_len()];
        let empty = hash.digest(&[]);
        let early = hash.extract(&[], &zeros);
        let derived = hash.derive_secret(&early, "derived", &empty);
        let handshake = hash.extract(&derived, shared);
        let derived = hash.derive_secret(&handshake, "derived", &empty);
        let master = hash.extract(&derived, &zeros);
        Self {
            hash,
            handshake,
            master,
        }
    }

    /// The client and server handshake traffic secrets, over the transcript
    /// through ServerHello.
    pub fn handshake_traffic(&self, transcript_hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (
            self.hash
                .derive_secret(&self.handshake, "c hs traffic", transcript_hash),
            self.hash
                .derive_secret(&self.handshake, "s hs traffic", transcript_hash),
        )
    }

    /// The client and server application traffic secrets, over the
    /// transcript through the server's Finished.
    pub fn application_traffic(&self, transcript_hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (
            self.hash
                .derive_secret(&self.master, "c ap traffic", transcript_hash),
            self.hash
                .derive_secret(&self.master, "s ap traffic", transcript_hash),
        )
    }

    /// The Finished verify_data a side with `base` traffic secret sends over
    /// the transcript so far (RFC 8446 section 4.4.4).
    pub fn finished(&self, base: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        let key = self
            .hash
            .expand_label(base, "finished", &[], self.hash.output_len());
        self.hash.hmac(&key, transcript_hash)
    }
}

/// The next application traffic secret (RFC 8446 section 7.2).
pub fn update_traffic_secret(hash: Hash, secret: &[u8]) -> Vec<u8> {
    hash.expand_label(secret, "traffic upd", &[], hash.output_len())
}
