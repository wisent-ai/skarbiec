// Whether two items hold the same thing, answered from the cleartext envelope.
//
// The vault on this fleet holds 66 `login` items, and counting them by name
// showed 29 of them describing 12 platforms: `anticaptcha` beside
// `platform-admin-anticaptcha`, `oxylabs` beside `platform-admin-oxylabs`
// beside `weles-oxylabs-dashboard-login`, and four rows for one Google admin
// identity. Nothing in the item model could say whether two rows held the same
// credential, so nothing refused the second one, nothing reported the pairs,
// and every per-row diagnosis counted one account several times.
//
// A fingerprint decides it without opening anything: the canonical payload,
// hashed with a per-vault salt. Salted, because an unsalted digest of a short
// payload is a guessing oracle against the vault file, and the vault file is
// what leaves the host in a backup or a ciphertext sync. Per-vault, because
// duplicates are a question inside one vault, and a fingerprint means nothing
// outside the vault that minted the salt.

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use crate::core::crypto;

pub(in crate::core::vault) mod stamp;

/// Where the salt lives in the vault document.
pub(in crate::core::vault) const SALT_KEY: &str = "fingerprint_salt";
/// Where a fingerprint lives in an item's cleartext envelope.
pub(in crate::core::vault) const FINGERPRINT_KEY: &str = "payload_fingerprint";

/// The fingerprint of one canonical payload under one vault's salt.
///
/// The field map is re-sorted first: the question is whether two items hold
/// the same content, not whether it was written in the same order.
pub(in crate::core::vault) fn fingerprint(salt: &str, payload: &Value) -> Result<String> {
    let canonical =
        serde_json::to_string(&sorted(payload)).context("serialize canonical payload")?;
    crypto::sha256_hex(&format!("{salt}\u{0}{canonical}"))
}

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut names: Vec<&String> = fields.keys().collect();
            names.sort();
            let mut out = Map::with_capacity(fields.len());
            for name in names {
                out.insert(name.clone(), sorted(&fields[name]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// The active item, other than `id`, whose payload fingerprint is this one.
pub(in crate::core::vault) fn holder_of<'a>(
    items: &'a Map<String, Value>,
    print: &str,
    id: &str,
) -> Option<&'a str> {
    items.iter().find_map(|(other, entry)| {
        if other == id {
            return None;
        }
        if entry.get("state").and_then(Value::as_str) != Some("active") {
            return None;
        }
        (entry.get(FINGERPRINT_KEY).and_then(Value::as_str) == Some(print))
            .then_some(other.as_str())
    })
}

/// Every group of active items that hold the same payload, each group sorted
/// by id and the groups by their first member, so a report is stable.
///
/// An item written before fingerprints existed carries none and is absent
/// here: the report says what it knows, and the next write of that item
/// stamps it.
pub(in crate::core::vault) fn groups(items: &Map<String, Value>) -> Vec<(String, Vec<String>)> {
    let mut by_fingerprint: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (id, entry) in items {
        if entry.get("state").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let Some(print) = entry.get(FINGERPRINT_KEY).and_then(Value::as_str) else {
            continue;
        };
        by_fingerprint
            .entry(print.to_string())
            .or_default()
            .push(id.clone());
    }
    let single = std::iter::once(()).count();
    let mut found: Vec<(String, Vec<String>)> = by_fingerprint
        .into_iter()
        .filter(|(_, ids)| ids.len() > single)
        .map(|(print, mut ids)| {
            ids.sort();
            (print, ids)
        })
        .collect();
    found.sort_by(|left, right| left.1[0].cmp(&right.1[0]));
    found
}
