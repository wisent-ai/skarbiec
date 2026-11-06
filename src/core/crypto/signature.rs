// A workload's Ed25519 key and signatures, checked in this process.
//
// The key is the PEM public key (`-----BEGIN PUBLIC KEY-----`) a workload
// registers: an X.509 SubjectPublicKeyInfo naming id-Ed25519 (RFC 8410
// section 4). The answer has three outcomes, not two: a signature that does
// not verify is a denial (`Ok(false)`); a key that is not an Ed25519 public
// key is an error with its own words, never read as a bad signature.

use anyhow::{bail, Context, Result};

/// The DER SubjectPublicKeyInfo of an Ed25519 key up to its 32 key bytes:
/// SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) },
/// as RFC 8410 section 10.1 shows it.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const PEM_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_END: &str = "-----END PUBLIC KEY-----";

/// The 32-byte Ed25519 public key a PEM public key holds, or why it holds none.
pub fn ed25519_public_key(pem: &str) -> Result<[u8; 32]> {
    let start = pem
        .find(PEM_BEGIN)
        .with_context(|| format!("the public key has no {PEM_BEGIN} line; give the PEM public key (`openssl pkey -pubout`)"))?;
    let rest = &pem[start + PEM_BEGIN.len()..];
    let end = rest
        .find(PEM_END)
        .with_context(|| format!("the public key has no {PEM_END} line; it was cut short"))?;
    let body: String = rest[..end].split_whitespace().collect();
    let der = skarbiec_crypto::openpgp::armor::base64_decode(&body)
        .map_err(|error| anyhow::anyhow!("the public key's base64 does not decode: {error}"))?;
    match der.strip_prefix(&ED25519_SPKI_PREFIX[..]) {
        Some(key) if key.len() == 32 => Ok(key.try_into().context("32 key bytes")?),
        _ => bail!(
            "the public key is not an Ed25519 public key (RFC 8410 id-Ed25519, 44 bytes of DER; \
             this one is {} bytes): make the workload key with `openssl genpkey -algorithm ED25519`",
            der.len()
        ),
    }
}

/// Whether `signature` is `public_key`'s Ed25519 signature over `payload`.
///
/// `Ok(false)` is the verdict that it is not, including a signature that is
/// not 64 bytes. A key that is not an Ed25519 public key is the error,
/// naming `what`.
pub fn verify(public_key: &str, payload: &[u8], signature: &[u8], what: &str) -> Result<bool> {
    let key = ed25519_public_key(public_key).with_context(|| format!("verify {what}"))?;
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return Ok(false);
    };
    Ok(skarbiec_crypto::ed25519::verify(&key, payload, &signature))
}
