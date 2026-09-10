// Reading a vault written before the v2 item envelope and writing what it
// becomes: every item, every revision and every grant, then reading the
// result back before the migration is called done.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

use super::vault::Vault;

mod grants;
mod items;
mod patterns;
mod validate;

use grants::migrate_grants;
use items::{canonical_item_id, migrate_item};
use validate::validate_v2;

#[derive(Debug)]
pub struct MigrationReport {
    pub items: usize,
    pub revisions: usize,
    pub grants: usize,
}

pub fn migrate(vault: &mut Vault) -> Result<MigrationReport> {
    let source_items = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .cloned()
        .context("vault items section is not an object")?;

    let mut canonical_items = Map::new();
    let mut item_fields = BTreeMap::new();
    let mut revisions = usize::MIN;
    for (id, entry) in &source_items {
        let (canonical, fields, count) =
            migrate_item(vault, id, entry).with_context(|| format!("migrate item {id}"))?;
        let canonical_id = canonical_item_id(id);
        if canonical_items.contains_key(&canonical_id) {
            bail!("migration produces duplicate canonical item id: {canonical_id}");
        }
        canonical_items.insert(canonical_id.clone(), canonical);
        item_fields.insert(canonical_id, fields);
        revisions += count;
    }
    let mut tokens = vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .cloned()
        .context("vault tokens section is not an object")?;
    let grants = migrate_grants(&mut tokens, &item_fields)?;
    let document = vault
        .doc_mut()
        .as_object_mut()
        .context("vault document is not an object")?;
    document.insert("version".to_string(), json!("v2"));
    document.insert("items".to_string(), Value::Object(canonical_items));
    document.insert("tokens".to_string(), Value::Object(tokens));
    validate_v2(vault)?;
    vault.save()?;
    Ok(MigrationReport {
        items: source_items.len(),
        revisions,
        grants,
    })
}
