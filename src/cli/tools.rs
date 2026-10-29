// The commands that do not read one item: the tag inventory, emptying the
// trash, exporting a runtime view of the vault, and reporting which build
// this is. `generate` lives in its own module.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::{schema, vault_path};

use super::args::{emit, flag_set, OrUsage};

/// `skarbiec tags [--all]`: the registered tag namespaces and every tag the
/// live items (with --all, trashed ones too) carry, with the items carrying
/// each and whether a namespace covers it. It decrypts nothing.
pub(crate) fn cmd_tags(flags: &HashMap<String, String>) -> Result<Value> {
    let items = Vault::open(vault_path())?.list(flag_set(flags, "all"));
    Ok(schema::tag_inventory(&items))
}

/// `purge --trashed-before <iso8601> [--yes]`: empty the trash of every item
/// moved there before that moment, with every saved version of each. Without
/// `--yes` it names what it would remove and removes nothing, so the list is
/// read before it is acted on. The moment an item went to trash is its last
/// write, `updated_at`.
pub(crate) fn cmd_purge_trash(
    flags: &HashMap<String, String>,
    positionals: &[String],
    before: &str,
) -> Result<Value> {
    if !positionals.is_empty() {
        return Err(super::args::Usage(
            "purge takes either one item id or --trashed-before, not both".to_string(),
        )
        .into());
    }
    if !crate::core::clock::is_iso(before) {
        return Err(super::args::Usage(format!(
            "--trashed-before {before} is not a UTC time of the form {}; nothing was removed",
            crate::core::clock::now_iso()
        ))
        .into());
    }
    let mut vault = Vault::open(vault_path())?;
    let due: Vec<String> = vault
        .list(true)
        .iter()
        .filter(|item| item.get("deleted") == Some(&Value::Bool(true)))
        .filter(|item| {
            item.get("updated_at")
                .and_then(Value::as_str)
                .is_some_and(|at| at < before)
        })
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    if !flag_set(flags, "yes") {
        return Ok(json!({"ok": true, "confirmed": false, "would_purge": due, "purged": []}));
    }
    // Every item is checked before any is removed, so a refusal leaves the
    // whole trash as it was rather than half emptied.
    for id in &due {
        super::items::ensure_owner_mutation_allowed(&vault, id, "remove")?;
    }
    for id in &due {
        vault.purge_item(id)?;
        if super::items::forget_purged(&mut vault, id)? {
            vault.save()?;
        }
    }
    crate::runtime::audit::append(
        "purge-trash",
        &json!({"trashed_before": before, "items": due}),
    )?;
    Ok(json!({"ok": true, "confirmed": true, "would_purge": [], "purged": due}))
}

// Bridge for consumers that read a JSON-array file (via an env-configured path):
// decrypt the live items and write the array to an owner-only file. The vault
// stays the source of truth; this materializes a runtime view for a consumer
// that cannot yet call resolve per item. The flags `list` takes narrow it the
// same way, so a consumer's file holds only the items it is for; `--all` is
// refused because a trashed item does not open.
pub(crate) fn cmd_export(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    emit(&export_value(flags, positionals)?)
}

/// [`cmd_export`]'s answer, which `POST /v1/operator/items/export` also
/// serves with an absolute path the desktop chose.
pub(crate) fn export_value(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let out = positionals
        .first()
        .or_else(|| flags.get("out"))
        .or_usage("usage: export <out-file> [--browser-csv | --bitwarden-csv | --canonical] [--encrypt-to <uid>] [--kind <kind>] [--tag <tag>] [--updated-before <iso8601>] [--match <text>] [--shared-with <uid>] [--pinned]")?;
    if flag_set(flags, "all") {
        return Err(super::args::Usage(
            "export writes live items only; a trashed item does not open, so --all is refused"
                .to_string(),
        )
        .into());
    }
    if flag_set(flags, "trashed") {
        return Err(super::args::Usage(
            "export writes live items only; a trashed item does not open, so --trashed is refused"
                .to_string(),
        )
        .into());
    }
    let chosen = super::list::cmd_list(flags)?;
    let vault = Vault::open(vault_path())?;
    // `--canonical` rows carry the id and tags beside each payload, the shape
    // `import` reads back; recipients stay behind, as another vault's
    // registered uids are its own.
    let mut rows: Vec<(String, Value)> = Vec::new();
    let mut canonical_rows = Vec::new();
    for entry in chosen.as_array().into_iter().flatten() {
        if let Some(id) = entry.get("id").and_then(Value::as_str) {
            let payload = vault.get_item(id)?;
            let mut row = serde_json::Map::from_iter([
                ("id".to_string(), json!(id)),
                ("payload".to_string(), payload.clone()),
            ]);
            if let Some(tags) = entry.get("tags").filter(|tags| tags.is_array()) {
                row.insert("tags".to_string(), tags.clone());
            }
            canonical_rows.push(Value::Object(row));
            rows.push((id.to_string(), payload));
        }
    }
    let exported = rows.len();
    // `--browser-csv` writes the logins in the CSV a browser imports,
    // `--bitwarden-csv` the logins and notes in the CSV Bitwarden imports;
    // otherwise the canonical payloads as one JSON array.
    let browser_csv = flag_set(flags, "browser-csv");
    let bitwarden_csv = flag_set(flags, "bitwarden-csv");
    let canonical = flag_set(flags, "canonical");
    // Any two of the shapes named together is a contradiction.
    if (browser_csv && bitwarden_csv) || (browser_csv && canonical) || (bitwarden_csv && canonical)
    {
        return Err(super::args::Usage(
            "--browser-csv, --bitwarden-csv and --canonical are shapes of the file; name one"
                .to_string(),
        )
        .into());
    }
    let document = if browser_csv {
        super::list::browser_csv::logins(&rows)?
    } else if bitwarden_csv {
        super::list::bitwarden_csv::items(&rows)?
    } else if canonical {
        serde_json::to_string(&Value::Array(canonical_rows))?
    } else {
        serde_json::to_string(&Value::Array(
            rows.into_iter().map(|(_, payload)| payload).collect(),
        ))?
    };
    // `--encrypt-to <uid>` seals the file to one registered recipient's key,
    // so what lands on disk opens only for them; without it the file is
    // plaintext, written owner-only from the first byte (atomic_write).
    let encrypt_to = flags.get("encrypt-to");
    let document = match encrypt_to {
        Some(uid) => {
            let Some(fingerprint) = vault.recipient_fpr(uid) else {
                return Err(super::args::Usage(format!(
                    "--encrypt-to {uid} is not a registered recipient; `skarbiec recipient list` names them"
                ))
                .into());
            };
            crate::core::crypto::encrypt_to(&[fingerprint], &document)?
        }
        None => document,
    };
    let target = std::env::current_dir()
        .context("the working directory cannot be read to place the export")?
        .join(out);
    crate::core::vault::atomic_write(&target, document.as_bytes())
        .with_context(|| format!("write export {}", target.display()))?;
    Ok(
        json!({"ok": true, "exported": exported, "out": out, "browser_csv": browser_csv, "bitwarden_csv": bitwarden_csv, "canonical": canonical, "encrypted_to": encrypt_to}),
    )
}

/// Report what this binary is, so a supervisor never has to identify a build by
/// counting the commands it answers — which is what the July incident actually
/// resorted to, twice, on a broker that had been replaced by hand.
///
/// `release` is the versioned coordinate the artifact was published at, and
/// `commit` is the source revision it was built from. Both are baked in at build
/// time by the publishing pipeline. A source build has neither and says so rather
/// than guessing, because an unpublished binary claiming a release coordinate is
/// worse than one admitting it has no provenance.
///
/// The coordinate alone would only identify bytes. Publishing refuses a tree with
/// uncommitted changes, so a released coordinate resolves to a revision anyone can
/// check out and rebuild — which is the difference between an artifact that is a
/// source of truth and one that is merely unique.
pub(crate) fn cmd_version() -> Result<Value> {
    let release = option_env!("SKARBIEC_RELEASE_URI");
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "release": release,
        "commit": option_env!("SKARBIEC_RELEASE_COMMIT"),
        // `release` is the word a supervisor compares against, not a synonym it
        // has to learn: a host software report classifies each file it finds as
        // `release` or `unmanaged`, and this field is how a Skarbiec binary
        // answers that question about itself. The earlier value, `published`,
        // described the same state in a second vocabulary, which left the
        // reporting side matching on a string no other surface used.
        "provenance": match release {
            Some(_) => "release",
            None => "source build",
        },
    }))
}
