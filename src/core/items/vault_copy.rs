// Copying live items from one vault file into another: the supported merge
// of a private vault into another, and the reconciliation of a second file
// of one owner into the vault that is declared.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::cli::args::{flag_set, OrUsage, Usage};
use crate::core::vault::{entry_item_uid, Vault};

const USAGE: &str = "usage: migrate --from <vault-file> --to <vault-file> [--force | --reconcile]";

/// What reconciling one id both vaults hold does with it.
enum Verdict {
    /// The source's current revision was written later: it replaces the
    /// target's.
    Newer,
    /// The target already holds this value, or a later one.
    Kept(String),
    /// Which copy is current cannot be told; nothing is written for it.
    Unreconciled(String),
}

/// The items object of `vault`, named by `path`, without which no id can be
/// told present or absent.
fn items_of<'a>(vault: &'a Vault, path: &str) -> Result<&'a Map<String, Value>> {
    vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .with_context(|| format!("vault {path} holds no items object"))
}

/// When the current revision of `entry` was written, as the vault recorded
/// it.
fn written<'a>(entry: &'a Value, id: &str, side: &str) -> Result<&'a str> {
    entry
        .get("current")
        .and_then(|current| current.get("created_at"))
        .and_then(Value::as_str)
        .with_context(|| {
            format!("{id} in the {side} vault records no write time for its current revision")
        })
}

/// Whether the source's copy of `id` replaces the target's. Both must be the
/// same item (one item_uid); then the copy whose current revision was
/// written later wins. The write times are the vault's own UTC stamps in one
/// fixed-width form (`core::clock::now_iso`), which orders as text; stamps
/// of different shape, or of the same second with different values, cannot
/// be ordered and leave the id unreconciled.
fn verdict(
    source: &Vault,
    target: &Vault,
    id: &str,
    paths: (&str, &str),
    payload: &Value,
) -> Result<Verdict> {
    let source_entry = items_of(source, paths.0)?
        .get(id)
        .with_context(|| format!("source vault lists {id} but holds no entry for it"))?;
    let target_entry = items_of(target, paths.1)?
        .get(id)
        .with_context(|| format!("target vault holds no entry for {id}"))?;
    let (Some(source_uid), Some(target_uid)) =
        (entry_item_uid(source_entry), entry_item_uid(target_entry))
    else {
        return Ok(Verdict::Unreconciled(format!(
            "{id} carries no item_uid in one of the vaults; run `skarbiec upgrade --apply` on both"
        )));
    };
    if source_uid != target_uid {
        return Ok(Verdict::Unreconciled(format!(
            "{id} is item {source_uid} in the source and item {target_uid} in the target: two \
             different items share the id"
        )));
    }
    let current = target
        .get_item(id)
        .with_context(|| format!("read target item {id}"))?;
    if current == *payload {
        return Ok(Verdict::Kept("the target holds the same value".to_owned()));
    }
    let source_written = written(source_entry, id, "source")?;
    let target_written = written(target_entry, id, "target")?;
    if source_written.len() != target_written.len()
        || !source_written.ends_with('Z')
        || !target_written.ends_with('Z')
    {
        return Ok(Verdict::Unreconciled(format!(
            "{id} was written at {source_written} in the source and {target_written} in the \
             target, stamps of different form that cannot be ordered"
        )));
    }
    if source_written == target_written {
        return Ok(Verdict::Unreconciled(format!(
            "{id} holds different values written in the same second ({source_written}) in both \
             vaults"
        )));
    }
    if source_written < target_written {
        return Ok(Verdict::Kept(format!(
            "the target's value ({target_written}) is later than the source's ({source_written})"
        )));
    }
    Ok(Verdict::Newer)
}

/// Set the reconciled copy aside as `<path>.reconciled.<stamp>`, so a host
/// holds one file of its owner. The new name is linked first, which refuses
/// a name that exists, and only then is the old one removed.
fn retire(copy: &Path) -> Result<PathBuf> {
    let retired = PathBuf::from(format!(
        "{}.reconciled.{}",
        copy.display(),
        crate::core::clock::now_stamp()
    ));
    std::fs::hard_link(copy, &retired).with_context(|| {
        format!(
            "set the reconciled copy {} aside as {}",
            copy.display(),
            retired.display()
        )
    })?;
    std::fs::remove_file(copy).with_context(|| {
        format!(
            "remove {} after linking it as {}",
            copy.display(),
            retired.display()
        )
    })?;
    Ok(retired)
}

/// `skarbiec migrate --from <vault-file> --to <vault-file> [--force |
/// --reconcile]`: copy every live item from one vault file into another.
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
/// An id already present in the target is skipped unless `--force` replaces
/// it or `--reconcile` replaces it only when the source's value is later
/// ([`verdict`]). `--reconcile` is for two files of one owner: it refuses
/// vaults of different owners, and once every source item is in the target
/// it sets the source file aside ([`retire`]). Even with `--force` an item
/// owned by the credential lifecycle or managed by Weles is refused, and the
/// target writer itself refuses to displace an item whose recorded
/// controller is not the owner. The report names id, kind and sorted field
/// names only — never a field value. The first unreadable or unwritable item
/// stops the run with the id in the error.
pub fn migrate_vault(flags: &HashMap<String, String>) -> Result<Value> {
    let from = flags.get("from").or_usage(USAGE)?;
    let to = flags.get("to").or_usage(USAGE)?;
    if from == to {
        bail!("--from and --to must be different vault files");
    }
    let force = flag_set(flags, "force");
    let reconcile = flag_set(flags, "reconcile");
    if force && reconcile {
        return Err(Usage(format!(
            "--force replaces every id both vaults hold and --reconcile only an older one; name \
             one. {USAGE}"
        ))
        .into());
    }
    let source =
        Vault::open(PathBuf::from(from)).with_context(|| format!("open source vault {from}"))?;
    let mut target =
        Vault::open(PathBuf::from(to)).with_context(|| format!("open target vault {to}"))?;
    if reconcile && source.owner_uid() != target.owner_uid() {
        bail!(
            "--reconcile joins two files of one owner; {from} is owned by {} and {to} by {}",
            source.owner_uid(),
            target.owner_uid()
        );
    }
    let mut migrated = Vec::new();
    let mut skipped = Vec::new();
    let mut kept = Vec::new();
    let mut unreconciled = Vec::new();
    for entry in source.list(false) {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .context("source vault lists an item without an id")?;
        let present = items_of(&target, to)?.contains_key(id);
        if present && !force && !reconcile {
            skipped.push(id.to_string());
            continue;
        }
        let payload = source
            .get_item(id)
            .with_context(|| format!("read source item {id}"))?;
        if present && reconcile {
            match verdict(&source, &target, id, (from, to), &payload)? {
                Verdict::Newer => {}
                Verdict::Kept(why) => {
                    kept.push(json!({"id": id, "why": why}));
                    continue;
                }
                Verdict::Unreconciled(why) => {
                    unreconciled.push(json!({"id": id, "why": why}));
                    continue;
                }
            }
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
        let item_kind = match entry.get("kind").and_then(Value::as_str) {
            Some(kind) => kind,
            None => payload
                .get("kind")
                .and_then(Value::as_str)
                .with_context(|| format!("source item {id} has no kind"))?,
        };
        let tags = crate::core::vault::entry_texts(id, &entry, "tags")?;
        // The same item on the far side of a copy, so it keeps the same
        // identity. `set_migrated_item` adopts this only when the target has
        // no item under the id yet; an existing target item keeps its own.
        let source_item_uid = items_of(&source, from)?
            .get(id)
            .and_then(entry_item_uid)
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
            .with_context(|| format!("source item {id} holds no fields object"))?
            .keys()
            .cloned()
            .collect();
        field_names.sort();
        migrated.push(json!({"id": id, "kind": item_kind, "fields": field_names}));
    }
    let retired = match reconcile && unreconciled.is_empty() {
        true => Some(retire(Path::new(from))?.display().to_string()),
        false => None,
    };
    Ok(json!({
        "ok": true,
        "from": from,
        "to": to,
        "force": force,
        "reconcile": reconcile,
        "migrated": migrated,
        "skipped": skipped,
        "kept": kept,
        "unreconciled": unreconciled,
        "retired": retired,
    }))
}
