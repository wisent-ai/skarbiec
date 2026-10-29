// Canonical item construction and secret generation for the Skarbiec vault.
//
// Every newly written item uses `skarbiec.item.v2`: one validated kind, a
// logical fields object, and encrypted context. Generation uses OS entropy.
// No numeric literals: lengths/counts arrive as usize from argv, character
// classes are string literals (digits inside them are stripped by the scanner).

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::core::{schema, vault::Vault, vault_path};

mod domains;
mod generate;
mod migrate;
mod vault_copy;

pub use domains::{
    display_name, domain_matches, item_domains, notes, plain_http_addresses, site_host, DISPLAY_NAME, NOTES,
    PASSWORD_RULES,
};
pub use generate::{generate_passphrase, generate_password};
pub use migrate::upgrade;
pub use vault_copy::migrate_vault;

// Canonical item construction: k=v fields become one validated payload;
// profile-based bundle items use `set` instead.
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
///
/// A host Stado declares as a client of the vault owner (it names
/// `secrets.skarbiec.url`, or publishes the canonical forward, and no vault
/// file) holds no vault, so its status is where it reads the fleet vault, not
/// a missing file or the leftover copy: `holds_vault: false` with the route,
/// what declares it, and whether a copy lies at the default path. A vault
/// file that is absent on any other host is still the error `Vault::open`
/// gives.
pub fn status_json() -> Result<Value> {
    let path = vault_path();
    if let Some(owner) = crate::core::unchosen_copy_route(&path).map_err(anyhow::Error::msg)? {
        return Ok(json!({
            "vault": path.display().to_string(),
            "holds_vault": false,
            "copy_present": crate::core::is_present(&path, "vault copy")?,
            "owner_route": owner.route,
            "owner_route_declared_by": owner.declared_by,
        }));
    }
    let vault = Vault::open(path)?;
    let doc = vault.doc();
    // A section the vault has never written (no tokens, no bond) holds no
    // entries; one present but not an object is damage, said by name.
    let count = |key: &str| -> Result<usize> {
        doc.get(key)
            .into_iter()
            .map(|section| {
                section
                    .as_object()
                    .map(serde_json::Map::len)
                    .with_context(|| format!("the vault's {key} section is not an object"))
            })
            .sum()
    };
    let fpr = vault.recovery_fpr().to_string();
    let held = !fpr.is_empty() && crate::core::crypto::secret_key_present(&fpr)?;
    // What the items are, read from the envelopes: how many of each kind are
    // live, which live ones record no kind (`upgrade` stamps them), how many
    // sit in the trash, and how many live ones someone besides the owner and
    // recovery can open. Nothing is decrypted.
    let mut kinds = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut kindless = Vec::new();
    let mut trashed = Vec::new();
    let mut shared = Vec::new();
    for item in vault.list(true) {
        let Some(id) = item.get("id").and_then(Value::as_str) else {
            continue;
        };
        if item.get("deleted") == Some(&Value::Bool(true)) {
            trashed.push(id.to_string());
            continue;
        }
        match item.get("kind").and_then(Value::as_str) {
            Some(kind) => kinds.entry(kind.to_string()).or_default().push(id.to_string()),
            None => kindless.push(id.to_string()),
        }
        if !vault.item_recipient_uids(id)?.is_empty() {
            shared.push(id.to_string());
        }
    }
    let by_kind: std::collections::BTreeMap<String, usize> =
        kinds.into_iter().map(|(kind, ids)| (kind, ids.len())).collect();
    Ok(json!({
        "vault": vault_path().display().to_string(),
        "item_count": count("items")?,
        "live_by_kind": by_kind,
        "live_without_kind": kindless,
        "trashed_count": trashed.len(),
        "shared_count": shared.len(),
        "recipient_count": count("recipients")?,
        "token_count": count("tokens")?,
        "bond_count": count("bond")?,
        "recovery_fpr": fpr,
        "recovery_present_locally": held,
    }))
}
