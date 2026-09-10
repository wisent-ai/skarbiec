// Moving a vault forward: the v2 envelope migration with its snapshot, and
// the item-by-item copy between two vault files.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::vault::Vault;
use crate::core::{migrate, vault_path};

pub fn migrate_v2(flags: &std::collections::HashMap<String, String>) -> Result<Value> {
    let source = vault_path();
    let snapshot = flags.get("snapshot").map_or_else(
        || -> Result<PathBuf> {
            let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            Ok(PathBuf::from(format!(
                "{}.pre-v2.{epoch}",
                source.display()
            )))
        },
        |path| Ok(PathBuf::from(path)),
    )?;
    if snapshot.exists() {
        bail!("migration snapshot already exists: {}", snapshot.display());
    }
    let mut input = File::open(&source)
        .with_context(|| format!("open vault snapshot source {}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(u32::from_str_radix("600", "8".parse()?)?)
        .open(&snapshot)
        .with_context(|| format!("create migration snapshot {}", snapshot.display()))?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    let mut vault = Vault::open(source)?;
    let report = migrate::migrate(&mut vault)?;
    Ok(json!({
        "ok": true,
        "snapshot": snapshot.display().to_string(),
        "items": report.items,
        "revisions": report.revisions,
        "grants": report.grants,
    }))
}

/// Copy every live item from one vault file into another.
///
/// This is the supported way to merge a private vault — for example one held
/// by a private Weles instance — into the fleet vault, replacing ad-hoc
/// scripting. Each source item is decrypted locally and re-encrypted to the
/// target vault's own recipients: the target owner and its recovery key, never
/// the source's recipient list, whose uids mean nothing in the target. The
/// item keeps its id, kind, schema, context, fields and tags; the target
/// writer stamps `management` as owner-controlled by the target owner, the
/// same as any other owner write.
///
/// An id already present in the target is skipped unless `--force`; even with
/// `--force` an item owned by the credential lifecycle or managed by Weles is
/// refused, and the target writer itself refuses to displace an item whose
/// recorded controller is not the owner. The report names id, kind and sorted
/// field names only — never a field value. The first unreadable or unwritable
/// item stops the run with the id in the error.
pub fn migrate_vault(flags: &std::collections::HashMap<String, String>) -> Result<Value> {
    let from = flags
        .get("from")
        .context("usage: migrate --from <vault-file> --to <vault-file> [--force]")?;
    let to = flags
        .get("to")
        .context("usage: migrate --from <vault-file> --to <vault-file> [--force]")?;
    if from == to {
        bail!("--from and --to must be different vault files");
    }
    let force = flags.get("force").map(|v| v == "true").unwrap_or(false);
    let source =
        Vault::open(PathBuf::from(from)).with_context(|| format!("open source vault {from}"))?;
    let mut target =
        Vault::open(PathBuf::from(to)).with_context(|| format!("open target vault {to}"))?;
    let mut migrated = Vec::new();
    let mut skipped = Vec::new();
    for entry in source.list(false) {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .context("source vault lists an item without an id")?;
        let exists_in_target = target
            .doc()
            .get("items")
            .and_then(Value::as_object)
            .is_some_and(|items| items.contains_key(id));
        if exists_in_target && !force {
            skipped.push(id.to_string());
            continue;
        }
        if crate::credential::lifecycle_owned_item(&source, id)
            || crate::credential::lifecycle_owned_item(&target, id)
        {
            bail!("{id} is managed by the credential lifecycle and cannot be migrated");
        }
        if crate::core::inbox::managed_by_weles(&target, id) {
            bail!(
                "{id} is managed by Weles in the target vault; migrate cannot overwrite an externally managed credential"
            );
        }
        let payload = source
            .get_item(id)
            .with_context(|| format!("read source item {id}"))?;
        let item_kind = entry
            .get("kind")
            .and_then(Value::as_str)
            .or_else(|| payload.get("kind").and_then(Value::as_str))
            .with_context(|| format!("source item {id} has no kind"))?;
        let tags: Vec<String> = entry
            .get("tags")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        // The same item on the far side of a copy, so it keeps the same
        // identity. `set_migrated_item` adopts this only when the target has
        // no item under the id yet; an existing target item keeps its own.
        let source_item_uid = source
            .doc()
            .get("items")
            .and_then(|items| items.get(id))
            .and_then(crate::core::vault::entry_item_uid)
            .map(str::to_string);
        target
            .set_migrated_item(
                id,
                item_kind,
                &payload,
                &[],
                &tags,
                source_item_uid.as_deref(),
            )
            .with_context(|| format!("write item {id} into target vault"))?;
        let mut field_names: Vec<String> = payload
            .get("fields")
            .and_then(Value::as_object)
            .map(|fields| fields.keys().cloned().collect())
            .unwrap_or_default();
        field_names.sort();
        migrated.push(json!({"id": id, "kind": item_kind, "fields": field_names}));
    }
    Ok(json!({
        "ok": true,
        "from": from,
        "to": to,
        "force": force,
        "migrated": migrated,
        "skipped": skipped,
    }))
}
