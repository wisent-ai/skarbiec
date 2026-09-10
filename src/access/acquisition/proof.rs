// What a workload has to prove before one field is handed to it: the exact
// names, the nonce, and an Ed25519 signature over this exact request.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::core::vault::Vault;
use crate::core::{crypto, schema};

use super::state::{private_file_mode, state_path};
use super::AcquisitionFieldMissing;

pub(super) fn exact_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(super) fn valid_workload_id(value: &str) -> bool {
    let maximum: usize = "128".parse().unwrap_or_default();
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(super) fn valid_nonce(value: &str) -> bool {
    let expected: usize = "43".parse().unwrap_or_default();
    value.len() == expected
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn decode_signature(value: &str) -> Option<Vec<u8>> {
    let expected: usize = "128".parse().ok()?;
    if value.len() != expected {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact("2".parse().ok()?)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, "16".parse().ok()?).ok()
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

pub(super) fn write_private_file(path: &Path, value: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(path)?;
    file.write_all(value)?;
    file.sync_all()?;
    Ok(())
}

/// Apple ships LibreSSL as `openssl`, but its `pkeyutl` cannot verify Ed25519
/// signatures. Prefer an installed OpenSSL 3 build and allow an explicit path.
pub(super) fn openssl_bin() -> String {
    if let Ok(configured) = std::env::var("SKARBIEC_OPENSSL") {
        if !configured.is_empty() {
            return configured;
        }
    }
    for candidate in [
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "openssl".to_string()
}

pub(super) fn verify_workload_proof(public_key: &str, payload: &[u8], signature: &str) -> Result<bool> {
    let Some(signature) = decode_signature(signature) else {
        return Ok(false);
    };
    let parent = state_path()
        .parent()
        .context("acquisition state has no parent")?
        .to_path_buf();
    fs::create_dir_all(&parent)?;
    let stem = crypto::sha256_hex(&crypto::random_token()?)?;
    let key_path = parent.join(format!(".skarbiec-proof-key-{stem}"));
    let signature_path = parent.join(format!(".skarbiec-proof-signature-{stem}"));
    let payload_path = parent.join(format!(".skarbiec-proof-payload-{stem}"));
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
            .context("verify workload proof with openssl")?;
        Ok(status.success())
    })();
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&signature_path);
    let _ = fs::remove_file(&payload_path);
    result
}

pub(super) fn proof_window_seconds() -> Result<u64> {
    "30".parse().context("workload proof window")
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
    Ok(())
}
