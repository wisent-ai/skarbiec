// Canonical item construction and secret generation for the Skarbiec vault.
//
// Every newly written item uses `skarbiec.item.v2`: one validated kind, a
// logical fields object, and encrypted context. Generation uses OS entropy.
// No numeric literals: lengths/counts arrive as usize from argv, character
// classes are string literals (digits inside them are stripped by the scanner).

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::core::{schema, vault::Vault, vault_path};

mod generate;
mod migrate;

pub use generate::{generate_passphrase, generate_password};
pub use migrate::{migrate_v2, migrate_vault};

// Canonical item construction: k=v fields become one validated payload;
// profile-based bundle items use `set-json` instead.
pub fn build_item(item_kind: &str, fields: &[String]) -> Result<Value> {
    let mut map = Map::new();
    for field in fields {
        let (key, value) = field
            .split_once('=')
            .with_context(|| format!("field must be key=value: {field}"))?;
        map.insert(key.to_string(), Value::String(value.to_string()));
    }
    schema::payload(item_kind, map, Map::new())
}


/// Composite one-shot status: the operator picture in a single JSON,
/// composed from the same reads the individual status commands do.
pub fn status_json() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let doc = vault.doc();
    let count = |key: &str| {
        doc.get(key)
            .and_then(Value::as_object)
            .map(|m| m.len())
            .unwrap_or_default()
    };
    let fpr = vault.recovery_fpr().to_string();
    let held = !fpr.is_empty() && crate::core::crypto::secret_key_present(&fpr);
    Ok(json!({
        "vault": vault_path().display().to_string(),
        "item_count": count("items"),
        "recipient_count": count("recipients"),
        "token_count": count("tokens"),
        "bond_count": count("bond"),
        "recovery_fpr": fpr,
        "recovery_present_locally": held,
    }))
}
