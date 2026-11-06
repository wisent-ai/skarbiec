// `skarbiec audit epoch`: a journal whose chain is broken starts a new chain
// from a checkpoint the vault owner signs, naming the old tail and why.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;

use super::journal::{
    acquire_append_lock, audit_path, digest_input, now_iso, open_for_append, rotate_if_due,
    sha256_hex, tail_hash,
};
use super::reports::chain_report;

/// Start a new chain after a broken one. An intact journal is refused, and
/// the checkpoint records where the old chain broke and how many faults the
/// report found, or `null` where the report named none.
pub(super) fn start_epoch(flags: &HashMap<String, String>) -> Result<Value> {
    let reason = flags
        .get("reason")
        .map(String::as_str)
        .filter(|reason| !reason.trim().is_empty())
        .context("--reason is required")?;
    let report = chain_report(&HashMap::new())?;
    if report.intact {
        anyhow::bail!("audit journal is intact; refusing to create an unnecessary epoch");
    }
    let path = audit_path();
    let _lock = acquire_append_lock(&path)?;
    // The epoch line is chained as any other is: a segment due to close
    // closes first, so the line lands in the segment it belongs to.
    rotate_if_due(&path)?;
    let previous_tail = tail_hash()?;
    let vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
    let owner = vault
        .doc()
        .get("owner")
        .and_then(Value::as_str)
        .context("vault owner is missing")?;
    let signer = vault
        .doc()
        .get("recipients")
        .and_then(Value::as_object)
        .and_then(|recipients| recipients.get(owner))
        .and_then(|recipient| recipient.get("fingerprint"))
        .and_then(Value::as_str)
        .context("vault owner fingerprint is missing")?;
    let at = now_iso();
    let checkpoint = serde_json::to_string(&json!({
        "at": at,
        "reason": reason,
        "previous_tail": previous_tail,
        "broken_at": report.broken_at,
        "faults": report.faults.len(),
    }))?;
    let signed_checkpoint = crate::core::crypto::clearsign(signer, &checkpoint)?;
    let extra = json!({
        "reason": reason,
        "previous_tail": previous_tail,
        "signer": signer,
        "checkpoint": checkpoint,
        "signed_checkpoint": signed_checkpoint,
    });
    let prev = String::new();
    let hash = sha256_hex(&digest_input(&prev, &at, "audit-epoch-start", &extra));
    let entry = json!({
        "at": at,
        "op": "audit-epoch-start",
        "extra": extra,
        "prev": prev,
        "hash": hash,
    });
    let mut file = open_for_append(&path)?;
    writeln!(file, "{entry}")?;
    file.sync_data()?;
    Ok(json!({
        "started": true,
        "signer": signer,
        "previous_tail": previous_tail,
        "hash": hash,
    }))
}
