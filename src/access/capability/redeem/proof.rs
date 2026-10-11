// Proving that the process asking is the workload the grant names, and
// reading the one field it is allowed to spend.

use anyhow::{Context, Result};
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde_json::Value;
use std::fs;
use std::process::{Command, Stdio};

use crate::access::capability::openssl_bin;
use crate::access::capability::state::{now_epoch, state_path, write_private_file};
use crate::core::{crypto, vault::Vault};

// Liveness matches grant::active: a consumer entry carries no state field, only an
// expiry. Checking for a "state" the vault never writes would deny every redemption
// while looking like a working guard.
pub(super) fn workload_public_key(vault: &Vault, agent: &str) -> Option<String> {
    let entry = vault
        .doc()
        .get("tokens")
        .and_then(|tokens| tokens.get(agent))?;
    let live = entry
        .get("expires_at")
        .and_then(Value::as_u64)
        .is_some_and(|expires_at| now_epoch().is_ok_and(|now| now < expires_at));
    if !live {
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
/// credential reduction expects to peel. Refusing the object here parked
/// every signed-in subscription behind "capability redemption denied" while
/// the vault held a working grant.
///
/// `None` is only "nothing is written there": no such item, or the field is
/// absent or null. An item that exists but cannot be opened (GnuPG refused,
/// legacy envelope, trashed, not the declared shape) is an error naming the
/// item; read as `None`, it answered "no value" - or, for a challenge,
/// "pending" forever - while the cause sat in the keyring.
pub(super) fn item_field(vault: &Vault, item: &str, field: &str) -> Result<Option<String>> {
    let present = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(item))
        .is_some();
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

/// The signature's bytes, or `None` when it is not base64. Decoded here
/// rather than by an openssl child: a missing or failing openssl used to read
/// as an invalid proof and denied a correctly signed redemption. Both the
/// URL-safe and the standard alphabet are read, padded or not, as before.
fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let standard = value.replace('-', "+").replace('_', "/");
    let engine = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    engine
        .decode(standard)
        .ok()
        .filter(|bytes| !bytes.is_empty())
}

pub(super) fn verify_proof(
    public_key: &str,
    payload: &[u8],
    signature_b64url: &str,
) -> Result<bool> {
    let Some(signature) = decode_base64url(signature_b64url) else {
        return Ok(false);
    };
    let parent = state_path()
        .parent()
        .context("capability state has no parent")?
        .to_path_buf();
    fs::create_dir_all(&parent)?;
    let stem = crypto::sha256_hex(&crypto::random_token()?)?;
    let key_path = parent.join(format!(".skarbiec-cap-key-{stem}"));
    let signature_path = parent.join(format!(".skarbiec-cap-sig-{stem}"));
    let payload_path = parent.join(format!(".skarbiec-cap-payload-{stem}"));
    let result = (|| -> Result<bool> {
        write_private_file(&key_path, public_key.as_bytes())?;
        write_private_file(&signature_path, &signature)?;
        write_private_file(&payload_path, payload)?;
        let status = Command::new(openssl_bin())
            .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
            .arg(&key_path)
            .args(["-rawin", "-sigfile"])
            .arg(&signature_path)
            .arg("-in")
            .arg(&payload_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("verify capability proof with openssl")?;
        Ok(status.success())
    })();
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&signature_path);
    let _ = fs::remove_file(&payload_path);
    result
}
