// Moving a vault forward: the one upgrade pass that brings the configured
// vault to the current schema, and the item-by-item copy between two vault
// files.

use crate::cli::args::OrUsage;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
        .unwrap_or("v1")
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
        let items = vault.doc().get("items").and_then(Value::as_object);
        let total = items.map(serde_json::Map::len).unwrap_or_default();
        let missing: Vec<&String> = items
            .map(|items| {
                items
                    .iter()
                    .filter(|(_, entry)| crate::core::vault::entry_item_uid(entry).is_none())
                    .map(|(id, _)| id)
                    .collect()
            })
            .unwrap_or_default();
        json!({"items": total, "missing": missing.len(), "ids": missing})
    };
    let fingerprints = vault.stamp_fingerprints(apply)?;
    // Control held by a former owner: a vault rotated before rotate-owner
    // moved control with the ownership still has items nobody may write.
    let moved = vault.transfer_former_owner_control();
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

/// Copy the vault file, byte for byte, to a new mode-0600 path before the
/// envelope migration rewrites it.
fn snapshot_vault(
    flags: &std::collections::HashMap<String, String>,
    source: &Path,
) -> Result<PathBuf> {
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
        .mode(0o600)
        .open(&snapshot)
        .with_context(|| format!("create upgrade snapshot {}", snapshot.display()))?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(snapshot)
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
        .or_usage("usage: migrate --from <vault-file> --to <vault-file> [--force]")?;
    let to = flags
        .get("to")
        .or_usage("usage: migrate --from <vault-file> --to <vault-file> [--force]")?;
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
