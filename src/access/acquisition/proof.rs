// What a workload has to prove before one field is handed to it: the exact
// names, the nonce, and a signature over this exact request.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::core::vault::Vault;
use crate::core::{crypto, schema};

use super::state::state_path;
use super::AcquisitionFieldMissing;

pub(super) fn exact_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(super) fn valid_workload_id(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && !value.chars().any(char::is_control)
}

pub(super) fn valid_nonce(value: &str) -> bool {
    // https://skarbiec.wisent.com/docs/credential-model publishes the nonce as
    // exactly 43 base64url characters, one 32-byte random value unpadded.
    let expected: usize = 43;
    value.len() == expected
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// The signature's bytes, or what makes the text no signature: its length,
/// or a pair of characters that is not a hexadecimal byte.
pub(super) fn decode_signature(value: &str) -> std::result::Result<Vec<u8>, String> {
    // https://skarbiec.wisent.com/docs/credential-model publishes the
    // signature as exactly 128 lowercase hexadecimal characters.
    let expected: usize = 128;
    if value.len() != expected {
        return Err(format!("{} characters, not {expected}", value.len()));
    }
    value
        .as_bytes()
        // https://www.rfc-editor.org/rfc/rfc4648#section-8 writes each byte as two digits.
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|cause| cause.to_string())?;
            // https://www.rfc-editor.org/rfc/rfc4648#section-8 is base 16.
            u8::from_str_radix(text, 16).map_err(|cause| format!("{text:?} is not a byte: {cause}"))
        })
        .collect()
}

pub(super) fn workload_payload(
    consumer: &str,
    item: &str,
    field: &str,
    workload_id: &str,
    timestamp: u64,
    nonce: &str,
) -> Vec<u8> {
    format!(
        "SKARBIEC-WORKLOAD-ACQUISITION\0v1\0{consumer}\0{item}\0{field}\0{workload_id}\0{timestamp}\0{nonce}"
    )
    .into_bytes()
}

/// Whether the workload signed `payload` with the key its grant records.
/// OpenSSL's verdict is the denial; a verifier that cannot answer is the
/// error with OpenSSL's words, from the one verifier capability redemption
/// also asks.
pub(super) fn verify_workload_proof(
    public_key: &str,
    payload: &[u8],
    signature: &str,
) -> Result<bool> {
    // Every refusal at issue time is the one word unauthorized and names no
    // check, as the credential model publishes, so a signature that is not the
    // published hexadecimal text is denied like a signature that does not
    // verify.
    let Ok(signature) = decode_signature(signature) else {
        return Ok(false);
    };
    let scratch = state_path()
        .parent()
        .context("acquisition state has no parent")?
        .to_path_buf();
    crypto::signature::verify(
        public_key,
        payload,
        &signature,
        &scratch,
        "workload acquisition proof",
    )
}

pub(super) fn validate_target(vault: &Vault, item: &str, field: &str) -> Result<()> {
    if !exact_name(item) || !exact_name(field) {
        bail!("item and field must be exact names without wildcards or separators");
    }
    let payload = vault.get_item(item)?;
    let present = if field == "context" {
        payload.get("context").is_some()
    } else {
        schema::fields(&payload)?.contains_key(field)
    };
    if !present {
        return Err(AcquisitionFieldMissing.into());
    }
    Ok(())
}

pub(super) fn purge_expired(state: &mut Value, now: u64) -> Result<()> {
    let tokens = state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?;
    tokens.retain(|_, record| {
        record
            .get("expires_at")
            .and_then(Value::as_u64)
            .is_some_and(|expiry| expiry > now)
    });
    let proofs = state
        .get_mut("proofs")
        .and_then(Value::as_object_mut)
        .context("acquisition proofs section")?;
    proofs.retain(|_, expiry| expiry.as_u64().is_some_and(|value| value > now));
    let workloads = state
        .get_mut("workloads")
        .and_then(Value::as_object_mut)
        .context("acquisition workloads section")?;
    workloads.retain(|_, record| {
        record
            .get("expires_at")
            .and_then(Value::as_u64)
            .is_some_and(|expiry| expiry > now)
    });
    Ok(())
}
