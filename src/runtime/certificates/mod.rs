// Certificate expiry across the vault: every live `certificate` item's
// subject, issuer and end of validity, read by OpenSSL from the item's
// `certificate` field. The certificate is the public half; the private key
// and passphrase beside it never leave the process.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::core::{clock, schema, vault::Vault, vault_path};

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
/// An item that will not open, holds no certificate text, or that OpenSSL
/// cannot read is listed under `unreadable` with its error: a report that
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
    let openssl = crate::core::crypto::signature::openssl_bin()?;
    let mut child = Command::new(&openssl)
        .args(["x509", "-noout", "-subject", "-issuer", "-enddate"])
        .args(["-nameopt", "RFC2253", "-dateopt", "iso_8601"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "start {} to read the certificate of {id}",
                openssl.display()
            )
        })?;
    child
        .stdin
        .take()
        .context("OpenSSL was started without a standard input")?
        .write_all(pem.as_bytes())
        .with_context(|| format!("hand the certificate of {id} to OpenSSL"))?;
    // Closing standard input above is what lets OpenSSL finish; the wait for
    // it is said on stderr: what runs, since when, and how it ended.
    let output = stado_wait::blocking(
        stado_wait::Kind::Process,
        "OpenSSL reading one vault certificate",
        openssl.display(),
        || child.wait_with_output(),
    )
    .with_context(|| format!("wait for OpenSSL reading the certificate of {id}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        bail!(
            "{} could not read the certificate of {id} ({}): {}",
            openssl.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let line = |prefix: &str| -> Result<String> {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .map(|value| value.trim().to_string())
            .with_context(|| {
                format!("OpenSSL printed no {prefix} line for the certificate of {id}")
            })
    };
    // `-dateopt iso_8601` prints `YYYY-MM-DD HH:MM:SSZ`; the vault's stamps
    // join date and time with `T`, and only that form compares as text.
    let printed = line("notAfter=")?;
    let not_after = printed
        .split_once(' ')
        .map(|(date, time)| format!("{date}T{time}"))
        .filter(|joined| clock::is_iso(joined));
    let Some(not_after) = not_after else {
        bail!(
            "{} printed the end of validity of {id} as {printed:?}, not an ISO 8601 UTC time; \
             SKARBIEC_OPENSSL names an OpenSSL that supports -dateopt iso_8601",
            openssl.display()
        );
    };
    Ok(CertificateFacts {
        subject: line("subject=")?,
        issuer: line("issuer=")?,
        not_after,
    })
}
