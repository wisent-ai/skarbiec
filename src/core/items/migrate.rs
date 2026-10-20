// Moving a vault forward: the one upgrade pass that brings the configured
// vault to the current schema.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::core::vault::Vault;
use crate::core::{migrate, vault_path};

/// `skarbiec upgrade [--apply] [--snapshot <path>]`: bring the configured
/// vault to the current schema in one idempotent pass — the v2 envelope for
/// its items and grants, an `item_uid` on every item, and a payload
/// fingerprint on every active item, and owner control of every item a former
/// owner still controls. Each step is skipped for what already has it, so a
/// second run changes nothing and reports zero. Without `--apply` it reports
/// what the pass would change and writes nothing.
///
/// The envelope migration rewrites the file, so it is preceded by a
/// mode-0600 snapshot — `--snapshot` names it, otherwise a timestamped path
/// beside the vault — and refused when that path exists. The identifier and
/// fingerprint steps touch the cleartext envelope only: no payload is
/// re-encrypted and no item gains a revision.
pub fn upgrade(flags: &std::collections::HashMap<String, String>) -> Result<Value> {
    let apply = crate::cli::args::flag_set(flags, "apply");
    let source = vault_path();
    let mut vault = Vault::open(source.clone())?;
    let version = vault
        .doc()
        .get("version")
        .and_then(Value::as_str)
        .with_context(|| format!("vault {} records no schema version", source.display()))?
        .to_string();
    let legacy_envelope = version != CURRENT_VERSION;
    let mut envelope = json!({
        "from": version,
        "to": CURRENT_VERSION,
        "needed": legacy_envelope,
    });
    if legacy_envelope && apply {
        let snapshot = snapshot_vault(flags, &source)?;
        let report = migrate::migrate(&mut vault)?;
        envelope = json!({
            "from": version,
            "to": CURRENT_VERSION,
            "needed": true,
            "snapshot": snapshot.display().to_string(),
            "items": report.items,
            "revisions": report.revisions,
            "grants": report.grants,
        });
    }
    let item_uids = if apply {
        let (stamped, total) = vault.backfill_item_uids()?;
        if !stamped.is_empty() {
            crate::runtime::audit::append_sync(
                "item-uids-backfilled",
                &json!({"stamped": stamped.len(), "items": total}),
            )?;
        }
        json!({"items": total, "stamped": stamped.len(), "ids": stamped})
    } else {
        let items = vault
            .doc()
            .get("items")
            .and_then(Value::as_object)
            .with_context(|| format!("vault {} holds no items object", source.display()))?;
        let missing: Vec<&String> = items
            .iter()
            .filter(|(_, entry)| crate::core::vault::entry_item_uid(entry).is_none())
            .map(|(id, _)| id)
            .collect();
        json!({"items": items.len(), "missing": missing.len(), "ids": missing})
    };
    let fingerprints = vault.stamp_fingerprints(apply)?;
    // Control held by a former owner: a vault rotated before rotate-owner
    // moved control with the ownership still has items nobody may write.
    let moved = vault.transfer_former_owner_control()?;
    if apply && !moved.is_empty() {
        vault.save()?;
        crate::runtime::audit::append_sync(
            "former-owner-control-transferred",
            &json!({"items": moved.len()}),
        )?;
    }
    let control = json!({"former_owner_items": moved.len(), "ids": moved});
    Ok(json!({
        "ok": true,
        "applied": apply,
        "vault": source.display().to_string(),
        "envelope": envelope,
        "item_uids": item_uids,
        "fingerprints": fingerprints,
        "control": control,
    }))
}

/// The schema version the upgrade pass brings a vault to.
const CURRENT_VERSION: &str = "v2";

/// Copy the vault file, byte for byte, to a new owner-only path before the
/// envelope migration rewrites it: the path `--snapshot` names, or
/// `<vault>.pre-v2.<stamp>` beside the vault.
fn snapshot_vault(
    flags: &std::collections::HashMap<String, String>,
    source: &Path,
) -> Result<PathBuf> {
    let snapshot = match flags.get("snapshot") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(format!(
            "{}.pre-v2.{}",
            source.display(),
            crate::core::clock::now_stamp()
        )),
    };
    if snapshot.exists() {
        bail!(
            "upgrade snapshot already exists: {}; name another with --snapshot",
            snapshot.display()
        );
    }
    let mut input = File::open(source)
        .with_context(|| format!("open vault snapshot source {}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(crate::core::vault::private_file_mode()?)
        .open(&snapshot)
        .with_context(|| format!("create upgrade snapshot {}", snapshot.display()))?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(snapshot)
}
