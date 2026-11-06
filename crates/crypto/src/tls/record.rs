//! TLS 1.3 records (RFC 8446 section 5): the plaintext records of the first
//! flight, and the protected records sealed with the suite's AEAD, whose
//! nonce is the traffic IV with the record's sequence number folded in.

use super::schedule::TrafficKey;
use super::suite::Aead;

/// The content types a record carries.
pub const CHANGE_CIPHER_SPEC: u8 = 20;
pub const ALERT: u8 = 21;
pub const HANDSHAKE: u8 = 22;
pub const APPLICATION_DATA: u8 = 23;

/// The most plaintext one record carries (2^14), and the most ciphertext
/// with its expansion (RFC 8446 section 5.2).
pub const MAX_PLAINTEXT: usize = 1 << 14;
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

/// Why a record could not be read or sealed, said for the person reading.
#[derive(Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The header names a length past what TLS 1.3 allows.
    Overflow(usize),
    /// A protected record whose tag does not open under this key.
    BadRecordMac,
    /// A protected record that holds only padding: no content type.
    NoContentType,
    /// The sequence number would wrap, which RFC 8446 forbids.
    SequenceExhausted,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Overflow(length) => write!(
                f,
                "a TLS record states {length} bytes, past the {MAX_CIPHERTEXT} TLS 1.3 allows: the peer is not speaking TLS 1.3 or the stream is damaged"
            ),
            RecordError::BadRecordMac => f.write_str(
                "a protected TLS record does not open under the negotiated key (bad_record_mac): it was changed on the way or the handshake keys disagree",
            ),
            RecordError::NoContentType => f.write_str(
                "a protected TLS record holds only padding and no content type, which RFC 8446 forbids",
            ),
            RecordError::SequenceExhausted => f.write_str(
                "this connection has sealed 2^64 records with one key and must not seal more",
            ),
        }
    }
}

impl std::error::Error for RecordError {}

/// The header of a record: its type, the legacy version and its length.
pub fn header(content_type: u8, length: usize) -> [u8; 5] {
    let length = (length as u16).to_be_bytes();
    [content_type, 0x03, 0x03, length[0], length[1]]
}

/// One direction's protection: the AEAD with its key, the IV, and the
/// number of the next record.
pub struct Protection {
    aead: Aead,
    iv: [u8; 12],
    sequence: u64,
}

impl Protection {
    pub fn new(aead_of: impl Fn(&[u8]) -> Aead, key: &TrafficKey) -> Self {
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&key.iv);
        Self {
            aead: aead_of(&key.key),
            iv,
            sequence: 0,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        for (byte, sequence) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *byte ^= sequence;
        }
        nonce
    }

    fn advance(&mut self) -> Result<(), RecordError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(RecordError::SequenceExhausted)?;
        Ok(())
    }

    /// Seal `content` of `content_type` into one whole record, header
    /// included, with no padding.
    pub fn seal(&mut self, content_type: u8, content: &[u8]) -> Result<Vec<u8>, RecordError> {
        let mut inner = Vec::with_capacity(content.len() + 1);
        inner.extend_from_slice(content);
        inner.push(content_type);
        let sealed_len = inner.len() + self.aead.tag_len();
        let head = header(APPLICATION_DATA, sealed_len);
        let sealed = self.aead.seal(&self.nonce(), &head, &inner);
        crate::wipe::wipe(&mut inner);
        self.advance()?;
        let mut record = head.to_vec();
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// Open the body of a protected record whose header was `head`: its
    /// content type and content, the padding taken off.
    pub fn open(&mut self, head: &[u8; 5], body: &[u8]) -> Result<(u8, Vec<u8>), RecordError> {
        let mut inner = self
            .aead
            .open(&self.nonce(), head, body)
            .ok_or(RecordError::BadRecordMac)?;
        self.advance()?;
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let content_type = inner.pop().ok_or(RecordError::NoContentType)?;
        Ok((content_type, inner))
    }
}
