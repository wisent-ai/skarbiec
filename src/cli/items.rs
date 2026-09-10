// The owner's own item commands: writing one, reading one, renaming it, and
// the guards that keep a managed item out of a direct owner write.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;

use crate::core::vault::Vault;
use crate::core::{items, schema, vault_path};

use super::args::emit;

pub(super) fn ensure_owner_mutation_allowed(
    vault: &Vault,
    id: &str,
    operation: &str,
) -> Result<()> {
    vault.ensure_owner_controlled(id).with_context(|| {
        format!("use the item's controlling lifecycle instead of direct owner {operation}")
    })
}

fn ensure_owner_set_allowed(vault: &Vault, id: &str) -> Result<()> {
    let item_exists = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .is_some_and(|items| items.contains_key(id));
    if !item_exists {
        return Ok(());
    }
    ensure_owner_mutation_allowed(vault, id, "rotate")
}

fn ensure_no_reserved_tags(tags: &[String]) -> Result<()> {
    if tags.iter().any(|tag| tag == "managed:weles") {
        bail!("managed:weles is reserved for authenticated Weles writes");
    }
    Ok(())
}

/// Resolve one metadata list: what the caller asked for, or what the item
/// already carries when the caller said nothing about it.
///
/// An absent flag used to become an empty list, and the vault wrote that empty
/// list over whatever was there. Brama's credential refresh calls `set-json`
/// with neither `--tags` nor `--recipients`, so every OAuth rotation stripped a
/// subscription's `brama:subscription` and `brama:agent:` tags and narrowed its
/// recipients to the owner alone. The item kept serving traffic while vanishing
/// from every consumer that enumerates by tag — the gateway's own listing and
/// its desktop console both do — which is how a subscription at revision 258
/// came to be invisible everywhere it should have appeared. An absent flag now
/// means "leave this as it is"; `--tags=` still clears.
fn requested_or_existing(
    flags: &HashMap<String, String>,
    vault: &Vault,
    id: &str,
    key: &str,
) -> Vec<String> {
    if let Some(value) = flags.get(key) {
        return value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect();
    }
    vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .and_then(|items| items.get(id))
        .and_then(|item| item.get(key))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn cmd_set(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: set <id> [--type <canonical-kind>] k=v ...")?;
    let item_kind = flags.get("type").map(String::as_str).unwrap_or("login");
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_set_allowed(&vault, id)?;
    let fields: Vec<String> = positionals
        .iter()
        .skip(std::iter::once(()).count())
        .cloned()
        .collect();
    let payload = items::build_item(item_kind, &fields)?;
    let recipients = requested_or_existing(flags, &vault, id, "recipients");
    let tags = requested_or_existing(flags, &vault, id, "tags");
    ensure_no_reserved_tags(&tags)?;
    let writer = vault.owner_uid().to_string();
    vault.set_item_written_by(id, item_kind, &payload, &recipients, &tags, &writer)?;
    emit(&json!({"ok": true, "id": id, "kind": item_kind}))
}

pub(crate) fn cmd_set_json(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: set-json <id> [--type <canonical-kind>]")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_set_allowed(&vault, id)?;
    let mut encoded = String::new();
    std::io::stdin().read_to_string(&mut encoded)?;
    let payload: Value =
        serde_json::from_str(&encoded).context("stdin must be one canonical JSON payload")?;
    let payload_kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .context("set-json payload requires kind")?;
    let item_kind = flags
        .get("type")
        .map(String::as_str)
        .unwrap_or(payload_kind);
    schema::validate_payload(&payload, item_kind)?;
    let recipients = requested_or_existing(flags, &vault, id, "recipients");
    let tags = requested_or_existing(flags, &vault, id, "tags");
    ensure_no_reserved_tags(&tags)?;
    let writer = vault.owner_uid().to_string();
    vault.set_item_written_by(id, item_kind, &payload, &recipients, &tags, &writer)?;
    emit(&json!({"ok": true, "id": id, "kind": item_kind}))
}

/// Replace one item's tags, leaving its payload untouched.
///
/// Consumers enumerate by tag: Brama's gateway and its desktop console both
/// treat an item as a subscription only when it carries `brama:subscription`
/// and `brama:agent:<agent>`, so an item that lost those tags is invisible to
/// every reader while still serving traffic. Until now the only way to restore
/// them was `set-json`, which rewrites the payload and re-encrypts it to the
/// current recipient list — a write that can narrow access to a live
/// credential, and one that needs the secret in hand to perform at all.
pub(crate) fn cmd_retag(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals
        .first()
        .context("usage: retag <id> --tags tag[,tag...]")?;
    let tags: Vec<String> = flags
        .get("tags")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    ensure_no_reserved_tags(&tags)?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "retag")?;
    vault.set_item_tags(id, &tags)?;
    emit(&json!({"ok": true, "id": id, "tags": tags}))
}

/// Change one item's id, keeping everything that is not the id.
///
/// There was no way to do this. The improvisation -- `get`, `set-json` under
/// the new id, `delete` the old -- is a copy wearing a rename's clothes: the
/// result starts at revision 1 with an empty history and a fresh `created_at`,
/// its tags are gone because a new id has no previous entry to preserve them
/// from, and it needs the plaintext in hand. Measured on a scratch vault, an
/// item at revision 3 with two historical versions came out at revision 1 with
/// none.
///
/// Owner-controlled items only, the same bar `retag` and `delete` apply. An
/// item the credential lifecycle or Weles controls is refused, because its
/// controller holds references keyed by the id and this command cannot update
/// them.
///
/// The references this does break -- capability routes, consumer grants,
/// acquisition bearers in flight -- break loudly, which is the accepted
/// tradeoff. What changes is that they are now traceable: the uid travels with
/// the item, so `route verify` reports a renamed item as renamed and names
/// where it went, instead of reporting it as missing and leaving an operator
/// unable to tell a rename from a purge.
pub(crate) fn cmd_rename(positionals: &[String]) -> Result<()> {
    let from = positionals.first().context("usage: rename <id> <new-id>")?;
    let to = positionals
        .get("1".parse::<usize>()?)
        .context("usage: rename <id> <new-id>")?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, from, "rename")?;
    let item_uid = vault.rename_item(from, to)?;
    crate::runtime::audit::append_sync(
        "item-renamed",
        &json!({"from": from, "to": to, "item_uid": item_uid}),
    )?;
    emit(&json!({"ok": true, "from": from, "to": to, "item_uid": item_uid}))
}

/// Stamp a permanent `item_uid` onto every item that predates the field.
///
/// Lazy minting means the field arrives on its own as items are written, but
/// an operator wanting a complete picture should not have to touch hundreds of
/// items by hand to get one. Idempotent: an item that already has one is
/// skipped before anything is generated, so a second run stamps nothing.
///
/// Envelope only. No payload is read, decrypted or re-encrypted, and
/// `revision`, `updated_at` and `current` are untouched -- acquiring an
/// identifier is not a change to the credential, and a diff of a backfilled
/// vault shows one added field per item and nothing else.
pub(crate) fn cmd_backfill_item_uids() -> Result<()> {
    let mut vault = Vault::open(vault_path())?;
    let (stamped, total) = vault.backfill_item_uids()?;
    if !stamped.is_empty() {
        crate::runtime::audit::append_sync(
            "item-uids-backfilled",
            &json!({"stamped": stamped.len(), "items": total}),
        )?;
    }
    emit(&json!({
        "ok": true,
        "items": total,
        "stamped": stamped.len(),
        "already_present": total.saturating_sub(stamped.len()),
        "ids": stamped,
    }))
}
