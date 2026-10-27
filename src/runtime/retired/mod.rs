// `health --saved-versions`: values in use now that were retired before. A
// password one item replaced — after a breach, a departure, a rotation —
// is no safer for being typed into another item, and one an item changed
// away from and then back to undid the rotation. Every saved version of
// every live item is opened and its field compared, by digest in memory,
// with the values the live items hold now; only item ids and the stamp of
// the version leave, never a value or a digest.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::core::{crypto, schema, vault::Vault};

/// Each live item holding a value one saved version once held and gave up,
/// and each saved version that could not be opened. `holders` maps the
/// digest of every value held now to the items holding it.
pub(crate) fn reused(vault: &Vault, field: &str, holders: &BTreeMap<String, Vec<String>>) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut current: HashMap<&str, &str> = HashMap::new();
    for (digest, ids) in holders {
        for id in ids {
            current.insert(id.as_str(), digest.as_str());
        }
    }
    let mut found = BTreeSet::new();
    let mut unreadable = Vec::new();
    for entry in vault.list(false) {
        let Some(id) = entry.get("id").and_then(Value::as_str) else { continue };
        if entry.get("state").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let versions = vault.versions(id)?;
        let saved: Vec<&str> = versions["versions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|version| version["current"] != json!(true))
            .filter_map(|version| version["at"].as_str())
            .collect();
        // The digest each saved version held, oldest first; None where the
        // version did not hold the field as text.
        let mut held: Vec<(&str, Option<String>)> = Vec::new();
        for at in saved {
            match digest_at(vault, id, at, field) {
                Ok(digest) => held.push((at, digest)),
                Err(error) => unreadable.push(json!({"item": id, "at": at, "error": format!("{error:#}")})),
            }
        }
        for (index, (at, digest)) in held.iter().enumerate() {
            let Some(digest) = digest else { continue };
            let kept_now = current.get(id) == Some(&digest.as_str());
            // Given up: the item holds something else now, or a later
            // version held something else before the value came back.
            let changed_later = held.iter().skip(index).any(|(_, later)| later.as_ref().is_some_and(|later| later != digest));
            if kept_now && !changed_later {
                continue;
            }
            for holder in holders.get(digest).into_iter().flatten().filter(|holder| holder.as_str() != id) {
                found.insert((holder.clone(), id.to_string(), at.to_string()));
            }
            if kept_now {
                found.insert((id.to_string(), id.to_string(), at.to_string()));
            }
        }
    }
    let found = found
        .into_iter()
        .map(|(item, retired_in, at)| json!({"item": item, "field": field, "retired_in": retired_in, "at": at}))
        .collect();
    Ok((found, unreadable))
}

fn digest_at(vault: &Vault, id: &str, at: &str, field: &str) -> Result<Option<String>> {
    let payload = vault.version_payload(id, at)?;
    let fields = schema::fields(&payload).with_context(|| format!("read the fields of {id} at {at}"))?;
    match fields.get(field).and_then(Value::as_str).filter(|text| !text.is_empty()) {
        Some(text) => Ok(Some(crypto::sha256_hex(text)?)),
        None => Ok(None),
    }
}
