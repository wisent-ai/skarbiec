// Proving that the process asking is the workload the grant names, and
// reading the one field it is allowed to spend.

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::access::capability::state::{now_epoch, state_path, write_private_file};
use crate::access::capability::openssl_bin;
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
pub(super) fn item_field(vault: &Vault, item: &str, field: &str) -> Option<String> {
    let payload = vault.get_item(item).ok()?;
    let value = payload.get("fields").and_then(|fields| fields.get(field))?;
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Null => None,
        other => serde_json::to_string(other).ok(),
    }
}

// `len() % 4` is the base64 padding rule as the format itself states it, and the
// loop reads as "pad until the quantum is whole". `is_multiple_of` would say the
// same thing about a number without saying it about base64.
#[allow(clippy::manual_is_multiple_of)]
fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let mut normalised = value.replace('-', "+").replace('_', "/");
    while normalised.len() % 4 != 0 {
        normalised.push('=');
    }
    let mut child = Command::new(openssl_bin())
        .args(["base64", "-d", "-A"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .as_mut()?
        .write_all(normalised.as_bytes())
        .ok()?;
    let done = child.wait_with_output().ok()?;
    if !done.status.success() || done.stdout.is_empty() {
        return None;
    }
    Some(done.stdout)
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
