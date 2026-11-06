// The owner's own item commands: writing one, reading one, renaming it, and
// the guards that keep a managed item out of a direct owner write.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;

use crate::bonds::{Mode, Role};
use crate::core::vault::Vault;
use crate::core::{schema, vault_path};

use super::args::{emit, flag_set, OrUsage};

pub(crate) const SET_JSON_USAGE: &str =
    "usage: set <id> [--type <canonical-kind>] [--if-absent | --if-unchanged]  (the canonical JSON payload on stdin)";

pub(crate) fn ensure_owner_mutation_allowed(
    vault: &Vault,
    id: &str,
    operation: &str,
) -> Result<()> {
    ensure_not_replica(vault, operation)?;
    vault.ensure_owner_controlled(id).with_context(|| {
        format!("use the item's controlling lifecycle instead of direct owner {operation}")
    })
}

/// A vault that replicates another is replaced by the next pull from its
/// source, so a write here is lost within one pull interval: a tag written
/// with `retag` on a replica vanishes and the item reads as undeclared. The
/// write is refused and names the source to write on.
pub(crate) fn ensure_not_replica(vault: &Vault, operation: &str) -> Result<()> {
    let Some(bonds) = vault.doc().get("bond").and_then(Value::as_object) else {
        return Ok(());
    };
    for (name, bond) in bonds {
        let text = |key: &str| bond.get(key).and_then(Value::as_str);
        let replica = text("mode").and_then(Mode::parse) == Some(Mode::Replica)
            && text("role").and_then(Role::parse) == Some(Role::Replica);
        if replica {
            let source = match bond
                .get("channel")
                .and_then(|channel| channel.get("address"))
                .and_then(Value::as_str)
            {
                Some(address) => address.to_string(),
                None => "a source whose address the bond does not record".to_string(),
            };
            bail!(
                "this vault replicates bond {name} from {source}; a direct {operation} here is \
                 replaced by the next pull. Write it on the source vault."
            );
        }
    }
    Ok(())
}

fn ensure_owner_set_allowed(vault: &Vault, id: &str) -> Result<()> {
    ensure_not_replica(vault, "set")?;
    if !vault.section("items", "id -> item")?.contains_key(id) {
        return Ok(());
    }
    ensure_owner_mutation_allowed(vault, id, "rotate")
}

pub(crate) fn ensure_no_reserved_tags(tags: &[String]) -> Result<()> {
    if tags.iter().any(|tag| tag == "managed:weles") {
        bail!("managed:weles is reserved for authenticated Weles writes");
    }
    Ok(())
}

/// Resolve one metadata list: what the caller asked for, or what the item
/// already carries when the caller said nothing about it.
///
/// An absent flag used to become an empty list, and the vault wrote that empty
/// list over whatever was there. Brama's credential refresh calls `set`
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
) -> Result<Vec<String>> {
    if let Some(value) = flags.get(key) {
        return Ok(value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect());
    }
    match vault.section("items", "id -> item")?.get(id) {
        Some(item) => crate::core::vault::entry_texts(id, item, key),
        None => Ok(Vec::new()),
    }
}

/// `--if-absent` creates the item only when no live item has that id; an
/// existing one is left untouched and reported as `created: false`. The check
/// and the write share one opened vault, and `save` refuses when another
/// writer changed the vault since it was opened, so two concurrent creators
/// cannot both write: one wins, the other is refused and its caller reads the
/// winner's value.
pub(crate) fn cmd_set_json(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let id = positionals.first().or_usage(SET_JSON_USAGE)?;
    // The payload is read first, so a caller writing it is never cut off by
    // an early answer.
    let mut encoded = String::new();
    std::io::stdin().read_to_string(&mut encoded)?;
    emit(&set_json_value(flags, id, &encoded)?)
}

pub(crate) fn set_json_value(
    flags: &HashMap<String, String>,
    id: &str,
    encoded: &str,
) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    if flag_set(flags, "if-absent") && flag_set(flags, "if-unchanged") {
        bail!("set accepts only one of --if-absent or --if-unchanged");
    }
    if flag_set(flags, "if-absent")
        && vault
            .list(false)
            .iter()
            .any(|entry| entry.get("id").and_then(Value::as_str) == Some(id))
    {
        return Ok(json!({"ok": true, "id": id, "created": false}));
    }
    ensure_owner_set_allowed(&vault, id)?;
    let mut payload: Value =
        serde_json::from_str(encoded).context("stdin must be one canonical JSON payload")?;
    if flag_set(flags, "if-unchanged") {
        let expected = payload
            .get("expected")
            .context("set --if-unchanged requires expected and payload on stdin")?;
        let current = vault
            .get_item(id)
            .with_context(|| format!("set --if-unchanged cannot read existing item {id}"))?;
        if &current != expected {
            bail!("item_payload_changed: set {id} refused because its payload changed since the caller read it; nothing was written");
        }
        payload = payload
            .get_mut("payload")
            .context("set --if-unchanged requires expected and payload on stdin")?
            .take();
    }
    let payload_kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .context("set payload requires kind")?;
    // `--type` names the item kind when it differs from the kind the payload
    // states; without it the payload's own kind is the item's.
    let item_kind = match flags.get("type") {
        Some(kind) => kind.as_str(),
        None => payload_kind,
    };
    schema::validate_payload(&payload, item_kind)?;
    let recipients = requested_or_existing(flags, &vault, id, "recipients")?;
    let tags = requested_or_existing(flags, &vault, id, "tags")?;
    ensure_no_reserved_tags(&tags)?;
    let writer = vault.owner_uid().to_string();
    vault.set_item_written_by(id, item_kind, &payload, &recipients, &tags, &writer)?;
    Ok(json!({"ok": true, "id": id, "kind": item_kind, "created": true}))
}

/// Create `id` from `encoded` with `flags`, as `set --if-absent` does,
/// refusing when an item with that id exists — one written between a
/// caller's own check and this write too — so a command that makes an item
/// never reports, journals or binds one it did not make. `by` names the
/// command in the refusal.
pub(crate) fn create_value(
    flags: &HashMap<String, String>,
    id: &str,
    encoded: &str,
    by: &str,
) -> Result<Value> {
    let mut write = flags.clone();
    write.insert("if-absent".to_string(), "true".to_string());
    let written = set_json_value(&write, id, encoded)?;
    if written["created"] != json!(true) {
        bail!("{id} already exists; {by} creates an item and never replaces one, and nothing was written");
    }
    Ok(written)
}

/// Forget what other vault sections kept about a purged item — its recorded
/// expiry, its pin and its rotation policy — none of which anything could
/// act on again; the caller saves. True when any was kept. Every purge path
/// goes through here, so a section added later is forgotten everywhere.
pub(crate) fn forget_purged(vault: &mut Vault, id: &str) -> Result<bool> {
    let expiry = crate::runtime::expiry::forget(vault, id);
    let pin = crate::runtime::pins::forget(vault, id)?;
    let rotation = crate::credential::forget_rotation(vault, id);
    Ok(expiry || pin || rotation)
}

/// Replace one item's tags, leaving its payload untouched.
///
/// Consumers enumerate by tag: Brama's gateway and its desktop console both
/// treat an item as a subscription only when it carries `brama:subscription`
/// and `brama:agent:<agent>`, so an item that lost those tags is invisible to
/// every reader while still serving traffic. Until now the only way to restore
/// them was `set`, which rewrites the payload and re-encrypts it to the
/// current recipient list — a write that can narrow access to a live
/// credential, and one that needs the secret in hand to perform at all.
pub(crate) fn cmd_retag(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    emit(&retag_value(flags, positionals)?)
}

/// [`cmd_retag`]'s answer, which the vault owner also serves to a machine
/// whose `retag` it forwards.
pub(crate) fn retag_value(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    // `retag --rename <old> --to <new>` renames a tag on every item at once.
    if flags.contains_key("rename") {
        return super::retag::rename_tag(flags);
    }
    // `retag --add|--remove <tag> <id>...` puts one tag on or off several items.
    if let Some(tag) = flags.get("add") {
        return super::retag::members::change_tag(
            super::retag::members::Change::Add,
            tag,
            positionals,
        );
    }
    if let Some(tag) = flags.get("remove") {
        return super::retag::members::change_tag(
            super::retag::members::Change::Remove,
            tag,
            positionals,
        );
    }
    let id = positionals
        .first()
        .or_usage("usage: retag <id> --tags tag[,tag...] | retag --rename <tag> --to <tag> | retag --add|--remove <tag> <id>...")?;
    // The list replaces every tag the item carries, so it must be stated:
    // `--tags ""` clears them, and a call that leaves the flag out is refused
    // rather than read as that.
    let tags: Vec<String> = flags
        .get("tags")
        .or_usage("usage: retag <id> --tags tag[,tag...] (--tags \"\" removes every tag)")?
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect();
    ensure_no_reserved_tags(&tags)?;
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, id, "retag")?;
    vault.set_item_tags(id, &tags)?;
    Ok(json!({"ok": true, "id": id, "tags": tags}))
}
