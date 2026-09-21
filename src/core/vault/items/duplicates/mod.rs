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

#[cfg(test)]
mod tests {
    use super::{fingerprint, groups, holder_of, FINGERPRINT_KEY};
    use serde_json::json;

    fn login(username: &str, password: &str) -> serde_json::Value {
        json!({
            "schema": "skarbiec.item.v2",
            "kind": "login",
            "fields": {"username": username, "password": password},
            "context": {},
        })
    }

    #[test]
    fn the_same_content_in_another_field_order_is_one_fingerprint() {
        let one = json!({"kind": "login", "fields": {"username": "a", "password": "b"}});
        let other = json!({"fields": {"password": "b", "username": "a"}, "kind": "login"});
        assert_eq!(
            fingerprint("salt", &one).expect("hash"),
            fingerprint("salt", &other).expect("hash")
        );
    }

    #[test]
    fn a_different_value_is_a_different_fingerprint() {
        assert_ne!(
            fingerprint("salt", &login("a", "b")).expect("hash"),
            fingerprint("salt", &login("a", "c")).expect("hash")
        );
    }

    /// A fingerprint is meaningless outside the vault that minted the salt, so
    /// a stolen vault file cannot be matched against this one.
    #[test]
    fn another_vaults_salt_gives_another_fingerprint() {
        assert_ne!(
            fingerprint("salt-one", &login("a", "b")).expect("hash"),
            fingerprint("salt-two", &login("a", "b")).expect("hash")
        );
    }

    #[test]
    fn the_holder_of_a_fingerprint_is_another_active_item() {
        let items = serde_json::from_value(json!({
            "anticaptcha": {"state": "active", FINGERPRINT_KEY: "aa"},
            "platform-admin-anticaptcha": {"state": "active", FINGERPRINT_KEY: "aa"},
            "retired": {"state": "deleted", FINGERPRINT_KEY: "aa"},
        }))
        .expect("items");
        assert_eq!(
            holder_of(&items, "aa", "platform-admin-anticaptcha"),
            Some("anticaptcha")
        );
        assert_eq!(holder_of(&items, "bb", "anticaptcha"), None);
    }

    /// A deleted row is not a duplicate of a live one, and a row written
    /// before fingerprints existed is reported by nothing rather than guessed.
    #[test]
    fn groups_name_only_live_fingerprinted_pairs() {
        let items = serde_json::from_value(json!({
            "oxylabs": {"state": "active", FINGERPRINT_KEY: "oo"},
            "platform-admin-oxylabs": {"state": "active", FINGERPRINT_KEY: "oo"},
            "weles-oxylabs-dashboard-login": {"state": "active", FINGERPRINT_KEY: "zz"},
            "written-before-fingerprints": {"state": "active"},
            "trashed": {"state": "deleted", FINGERPRINT_KEY: "oo"},
        }))
        .expect("items");
        let found = groups(&items);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].1,
            vec!["oxylabs".to_string(), "platform-admin-oxylabs".to_string(),]
        );
    }
}
