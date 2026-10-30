// Certificate expiry across the vault: every live `certificate` item's
// subject, issuer and end of validity, read in this process from the DER of
// the item's `certificate` field. The certificate is the public half; the
// private key and passphrase beside it never leave the process.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{clock, schema, vault::Vault, vault_path};

mod x509;

/// The kind whose items carry a certificate, and the field that holds it.
const CERTIFICATE_KIND: &str = "certificate";
const CERTIFICATE_FIELD: &str = "certificate";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "certificates" => report(flags).map(Some),
        _ => Ok(None),
    }
}

/// `skarbiec certificates [--expiring-before <iso8601>]`.
///
/// An item that will not open, holds no certificate text, or whose certificate
/// cannot be read is listed under `unreadable` with its error: a report that
/// dropped it would read as one certificate fewer to renew.
fn report(flags: &HashMap<String, String>) -> Result<Value> {
    let before = flags.get("expiring-before");
    if let Some(before) = before {
        if !clock::is_iso(before) {
            return Err(crate::cli::args::Usage(format!(
                "--expiring-before {before} is not a UTC time of the form {}",
                clock::now_iso()
            ))
            .into());
        }
    }
    let now = clock::now_iso();
    let vault = Vault::open(vault_path())?;
    let mut certificates = Vec::new();
    let mut unreadable = Vec::new();
    for entry in vault.list(false) {
        if entry.get("kind").and_then(Value::as_str) != Some(CERTIFICATE_KIND) {
            continue;
        }
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        match inspect(&vault, id) {
            Ok(facts) => {
                let not_after = facts.not_after;
                if before.is_some_and(|before| not_after.as_str() >= before.as_str()) {
                    continue;
                }
                certificates.push(json!({
                    "item": id,
                    "subject": facts.subject,
                    "issuer": facts.issuer,
                    "not_after": not_after,
                    "expired": not_after.as_str() <= now.as_str(),
                }));
            }
            Err(error) => unreadable.push(json!({"item": id, "error": format!("{error:#}")})),
        }
    }
    certificates.sort_by(|a, b| a["not_after"].as_str().cmp(&b["not_after"].as_str()));
    Ok(json!({
        "ok": true,
        "checked_at": now,
        "expiring_before": before,
        "certificates": certificates,
        "unreadable": unreadable,
    }))
}

struct CertificateFacts {
    subject: String,
    issuer: String,
    not_after: String,
}

fn inspect(vault: &Vault, id: &str) -> Result<CertificateFacts> {
    let payload = vault.get_item(id)?;
    let fields = schema::fields(&payload)?;
    let pem = fields
        .get(CERTIFICATE_FIELD)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .with_context(|| format!("{id} holds no {CERTIFICATE_FIELD} text"))?;
    let der = x509::first_pem(pem).with_context(|| format!("read the certificate of {id}"))?;
    let (subject, issuer, not_after) = x509::facts(&der)
        .with_context(|| format!("read the certificate of {id} (RFC 5280 DER)"))?;
    Ok(CertificateFacts {
        subject,
        issuer,
        not_after,
    })
}
