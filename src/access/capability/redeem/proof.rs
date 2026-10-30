// Proving that the process asking is the workload the grant names, and
// reading the one field it is allowed to spend.

use anyhow::{Context, Result};
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde_json::Value;

use crate::core::{crypto, vault::Vault};

// Liveness is grant::active's: a consumer entry carries no state field, only an
// expiry, and a clock that cannot say what now is denies with its cause said.
pub(in crate::access::capability) fn workload_public_key(
    vault: &Vault,
    agent: &str,
) -> Option<String> {
    let entry = vault
        .doc()
        .get("tokens")
        .and_then(|tokens| tokens.get(agent))?;
    if !crate::access::grant::active(entry) {
        return None;
    }
    entry
        .get("workload_public_key")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// One item field as the text a redemption hands out.
///
/// A field written as a string is served verbatim. A field holding a
/// structured document -- the shape a browser sign-in banks an OAuth grant
/// in -- is served as its canonical JSON text: redemption's contract is text,
/// and the serialization is that text, exactly what the consumer's own
/// credential reduction expects to peel.
///
/// `None` is only "nothing is written there": no such item, or the field is
/// absent or null. An item that exists but cannot be opened (GnuPG refused,
/// legacy envelope, trashed, not the declared shape) is an error naming the
/// item, because "no value" or a challenge left pending would hide a cause
/// that sits in the keyring.
pub(super) fn item_field(vault: &Vault, item: &str, field: &str) -> Result<Option<String>> {
    // A document without its items section is damage, refused by name, not
    // a vault that holds no such item.
    let present = vault.section("items", "id -> item")?.contains_key(item);
    if !present {
        return Ok(None);
    }
    let payload = vault
        .get_item(item)
        .with_context(|| format!("vault item {item} exists but cannot be read"))?;
    let Some(value) = payload.get("fields").and_then(|fields| fields.get(field)) else {
        return Ok(None);
    };
    match value {
        Value::String(text) => Ok(Some(text.clone())),
        Value::Null => Ok(None),
        other => serde_json::to_string(other)
            .map(Some)
            .with_context(|| format!("serialize {item}#{field} as text")),
    }
}

/// The signature's bytes, or `None` when it is not base64 or is empty: such a
/// signature is no proof, and the denial is the answer. Decoded here rather
/// than by an openssl child, and both the URL-safe and the standard alphabet
/// are read, padded or not.
fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let standard = value.replace('-', "+").replace('_', "/");
    let engine = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    match engine.decode(standard) {
        Ok(bytes) if !bytes.is_empty() => Some(bytes),
        _ => None,
    }
}

/// Whether the workload signed `payload` with the key its grant records.
/// The Ed25519 verdict is the answer; a key that is not an Ed25519 public
/// key is the error, in its own words (`crypto::signature::verify`).
pub(super) fn verify_proof(
    public_key: &str,
    payload: &[u8],
    signature_b64url: &str,
) -> Result<bool> {
    let Some(signature) = decode_base64url(signature_b64url) else {
        return Ok(false);
    };
    crypto::signature::verify(public_key, payload, &signature, "capability proof")
}
