// Writing one parsed export into the vault: one generation-checked save, and
// an explicit answer for every row that already existed.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use crate::core::schema;
use crate::core::vault::{ItemWrite, Vault};

use super::{Conflict, ImportDocument};

pub(super) fn apply(mut document: ImportDocument, conflict: Conflict) -> Result<Value> {
    let mut vault = Vault::open(crate::core::vault_path())?;
    let mut source_ids = HashMap::new();
    if let Some(items) = vault.doc().get("items").and_then(Value::as_object) {
        for (id, entry) in items {
            if let Some(source) = entry.get("import_source").and_then(Value::as_str) {
                if source_ids
                    .insert(source.to_string(), id.to_string())
                    .is_some()
                {
                    bail!(
                        "vault contains duplicate import source identities; no items were written"
                    );
                }
            }
        }
    }
    let mut seen = HashSet::with_capacity(document.rows.len());
    let mut selected = Vec::new();
    let mut results = Vec::with_capacity(document.rows.len());
    let (mut imported, mut updated, mut unchanged, mut conflicts) = (0, 0, 0, 0);
    for (index, row) in document.rows.iter_mut().enumerate() {
        if let Some(source) = &row.source_key {
            if let Some(id) = source_ids.get(source) {
                row.id = id.clone();
            }
        }
        if !seen.insert(row.id.clone()) {
            bail!(
                "duplicate source item in import: {}; no items were written",
                row.id
            );
        }
        let kind = row
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .context("import payload has no kind")?;
        schema::validate_payload(&row.payload, kind)?;
        if row.tags.iter().any(|tag| tag == "managed:weles") {
            bail!("{} uses the reserved managed:weles tag", row.id);
        }
        for uid in &row.recipients {
            if vault.recipient_fpr(uid).is_none() {
                bail!("{} names an unknown recipient: {uid}", row.id);
            }
        }
        let existing = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(&row.id));
        if let (Some(source), Some(existing)) = (&row.source_key, existing) {
            if existing.get("import_source").and_then(Value::as_str) != Some(source) {
                bail!(
                    "{} is occupied by another source; no items were written",
                    row.id
                );
            }
            row.recipients = vault.item_recipient_uids(&row.id);
            row.tags = existing
                .get("tags")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
        }
        let tags: Vec<Value> = row.tags.iter().cloned().map(Value::String).collect();
        let carried = existing
            .and_then(|item| item.get("tags"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        schema::ensure_registered_tags(carried, &tags)?;
        let status = if let Some(existing) = existing {
            vault.ensure_owner_controlled(&row.id)?;
            if crate::credential::lifecycle_owned_item(&vault, &row.id)
                || crate::core::inbox::managed_by_weles(&vault, &row.id)
            {
                bail!(
                    "{} is managed by a credential lifecycle and cannot be imported",
                    row.id
                );
            }
            let active = existing.get("state").and_then(Value::as_str) == Some("active");
            let same = active
                && vault.get_item(&row.id)? == row.payload
                && carried == tags.as_slice()
                && vault.item_recipient_uids(&row.id) == row.recipients;
            if same {
                unchanged += 1;
                "unchanged"
            } else if conflict == Conflict::Keep {
                conflicts += 1;
                "kept_existing"
            } else if conflict == Conflict::Error {
                bail!(
                    "{} conflicts with an existing item; no items were written",
                    row.id
                );
            } else {
                updated += 1;
                selected.push(index);
                "updated"
            }
        } else {
            imported += 1;
            selected.push(index);
            "imported"
        };
        results.push(json!({
            "id": row.id, "title": row.title, "kind": kind, "status": status,
            "warning": row.payload.get("context").and_then(|context| context.get("import_warning")),
        }));
    }
    let writes: Vec<ItemWrite<'_>> = selected
        .iter()
        .map(|index| {
            let row = &document.rows[*index];
            ItemWrite {
                id: &row.id,
                kind: row.payload["kind"].as_str().expect("validated kind"),
                payload: &row.payload,
                recipients: &row.recipients,
                tags: &row.tags,
                import_source: row.source_key.as_deref(),
            }
        })
        .collect();
    vault.set_items_atomic(&writes)?;
    Ok(json!({
        "ok": true, "format": document.format, "total": results.len(),
        "vault": vault.path,
        "imported": imported, "updated": updated, "unchanged": unchanged,
        "conflicts": conflicts, "items": results,
    }))
}
