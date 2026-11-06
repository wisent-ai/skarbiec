// Sharing and revoking by tag: every item that carries one tag, for one
// recipient. The way a team member is given the set of credentials their role
// uses without one `share` per item, and taken off that set again, without
// missing the one nobody remembered.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{vault::Vault, vault_path};

/// The ids of the items carrying `tag`, live ones only or trashed ones too.
fn tagged_ids(vault: &Vault, tag: &str, include_trashed: bool) -> Vec<String> {
    vault
        .list(include_trashed)
        .iter()
        .filter(|item| {
            item.get("tags")
                .and_then(Value::as_array)
                .is_some_and(|tags| tags.iter().any(|held| held.as_str() == Some(tag)))
        })
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// `share --tag <tag> <uid> [--until <iso8601>]`.
///
/// Every item the recipient cannot read yet is opened first; one that will
/// not open stops the run before anything is written, naming it, so a share
/// never half-completes. Items the recipient already reads are reported and
/// not rewritten. With --until every item shared now ends at that moment,
/// as a single share --until does, and maintain revokes them all then.
pub(super) fn share_tagged(tag: &str, uid: &str, flags: &HashMap<String, String>) -> Result<Value> {
    // A bad --until is refused before any item is written.
    super::timed::checked(flags)?;
    let mut vault = Vault::open(vault_path())?;
    if vault.recipient_fpr(uid).is_none() {
        return Ok(json!({"status": "blocked", "reason": "unknown_recipient", "uid": uid}));
    }
    let tagged = tagged_ids(&vault, tag, false);
    if tagged.is_empty() {
        anyhow::bail!("no live item carries the tag {tag}, so nothing was shared; `skarbiec tags` lists the tags the vault carries");
    }
    let mut already = Vec::new();
    let mut pending = Vec::new();
    for id in &tagged {
        let mut recipients = vault.item_recipient_uids(id)?;
        if recipients.iter().any(|reader| reader == uid) {
            already.push(id.clone());
            continue;
        }
        let payload = vault.get_item(id).with_context(|| {
            format!("{id} carries {tag} but will not open, so nothing was shared")
        })?;
        let (kind, tags) = super::item_meta(&vault, id)?;
        recipients.push(uid.to_string());
        pending.push((id.clone(), kind, payload, recipients, tags));
    }
    let mut shared = Vec::new();
    let mut until = None;
    for (id, kind, payload, recipients, tags) in pending {
        vault.set_item(&id, &kind, &payload, &recipients, &tags)?;
        until = super::timed::apply(&mut vault, &id, uid, flags)?;
        shared.push(id);
    }
    if !shared.is_empty() {
        crate::runtime::audit::append(
            "share",
            &json!({"tag": tag, "uid": uid, "items": shared, "until": until}),
        )?;
    }
    Ok(
        json!({"ok": true, "tag": tag, "uid": uid, "shared": shared, "already_shared": already, "until": until}),
    )
}

/// `revoke --tag <tag> <uid>`: the inverse of `share --tag`. Every item
/// carrying the tag that lists the uid, trashed ones included, is rewrapped
/// without them, current value and every saved version, in one save, as
/// `revoke` does for one item. Items they could not read are reported, not
/// touched.
pub(super) fn revoke_tagged(tag: &str, uid: &str) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    let tagged = tagged_ids(&vault, tag, true);
    if tagged.is_empty() {
        anyhow::bail!("no item carries the tag {tag}, so nothing was revoked; `skarbiec tags --all` lists the tags the vault carries");
    }
    let mut readable = Vec::new();
    let mut not_reader = Vec::new();
    for id in tagged {
        if vault
            .item_recipient_uids(&id)?
            .iter()
            .any(|reader| reader == uid)
        {
            readable.push(id);
        } else {
            not_reader.push(id);
        }
    }
    if readable.is_empty() {
        return Ok(
            json!({"ok": true, "tag": tag, "uid": uid, "revoked": readable, "not_a_reader": not_reader}),
        );
    }
    let report = vault.withdraw_recipient(uid, &readable)?;
    vault.save()?;
    crate::runtime::audit::append(
        "revoke",
        &json!({
            "tag": tag,
            "uid": uid,
            "items": readable,
            "historical_versions": report["historical_versions"],
        }),
    )?;
    Ok(json!({
        "ok": true,
        "tag": tag,
        "uid": uid,
        "revoked": readable,
        "historical_versions": report["historical_versions"],
        "not_a_reader": not_reader,
    }))
}
