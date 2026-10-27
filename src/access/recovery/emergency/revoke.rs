// Revoking an activated emergency grant: the grantee comes off exactly the
// items the activation added them to, every current and historical version,
// and the grant record goes. Items the grantee was given another way stay
// theirs, because the activation recorded which shares were its own.

use anyhow::{bail, Result};
use serde_json::{json, Value};

use super::{ensure_section, grant_of, load, status_of, ACTIVATED};
use crate::cli::args::OrUsage;

/// The items an activation recorded under `key`; none when it recorded no
/// such list.
fn recorded_items(grant: &Value, key: &str) -> Option<Vec<String>> {
    grant.get(key).and_then(Value::as_array).map(|ids| {
        ids.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

pub(super) fn revoke(positionals: &[String]) -> Result<Value> {
    let grantee = positionals
        .first()
        .or_usage("usage: emergency revoke <grantee>")?;
    let mut vault = load()?;
    let grant = grant_of(&vault, grantee, "revoke")?;
    let status = status_of(&grant);
    if status != ACTIVATED {
        bail!(
            "the emergency grant for {grantee} is {status}, so it has shared nothing to revoke; `skarbiec emergency cancel {grantee}` withdraws a grant that is still waiting"
        );
    }
    // An activation by a release that did not record its items cannot be
    // undone item by item without guessing which shares were its own, so
    // the refusal names what the grantee reads and the two exact commands.
    let Some(added_to) = recorded_items(&grant, "added_to") else {
        let readable: Vec<String> = vault
            .list(true)
            .iter()
            .filter(|item| {
                item.get("recipients")
                    .and_then(Value::as_array)
                    .is_some_and(|uids| uids.iter().any(|uid| uid.as_str() == Some(grantee)))
            })
            .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
            .collect();
        let reads = if readable.is_empty() {
            "no item".to_string()
        } else {
            readable.join(", ")
        };
        bail!(
            "the emergency grant for {grantee} was activated by a release that did not record which items it shared, so nothing was revoked; {grantee} reads: {reads}; `skarbiec revoke <item-id> {grantee}` takes back one item and `skarbiec recipient remove {grantee} --yes` takes back every item"
        );
    };
    let report = vault.withdraw_recipient(grantee, &added_to)?;
    ensure_section(vault.doc_mut(), "emergency")?.remove(grantee);
    vault.save()?;
    crate::runtime::audit::append(
        "emergency-revoke",
        &json!({
            "grantee": grantee,
            "items": report["rewrapped"].as_array().map(Vec::len),
            "historical_versions": report["historical_versions"],
        }),
    )?;
    // Re-encryption stops future reads; a value the grantee already read
    // stays read, so every item the activation let them open is named for
    // rotation.
    Ok(json!({
        "ok": true,
        "grantee": grantee,
        "revoked_items": report["rewrapped"],
        "historical_versions": report["historical_versions"],
        "already_gone": report["absent"],
        "no_longer_reader": report["not_reader"],
        "exposed": recorded_items(&grant, "shared_items"),
    }))
}
