// `recipient rekey <uid> --import <public-key-file> --yes`: a person's key
// expired, was revoked or was lost, and they made a new one. Their entry
// takes the new fingerprint and every live item they can read is written
// again to it, so they keep reading what they read without being removed and
// shared everything anew. Saved versions stay encrypted to the old key; the
// owner's key is changed with owner rotate, which rewraps those too.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{flag_set, OrUsage};
use crate::core::{crypto, vault::Vault, vault_path};

const USAGE: &str = "usage: recipient rekey <uid> --import <public-key-file> --yes";

pub(super) fn run(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let uid = positionals.first().or_usage(USAGE)?;
    let file = flags.get("import").or_usage(USAGE)?;
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_not_replica(&vault, "recipient rekey")?;
    let old = vault
        .recipient_fpr(uid)
        .with_context(|| format!("unknown recipient: {uid}; `skarbiec recipient list` names them"))?;
    if uid == vault.owner_uid() {
        bail!("{uid} owns this vault; `skarbiec owner rotate` moves the owner to a new key and rewraps every saved version too");
    }
    let armored = std::fs::read_to_string(file).with_context(|| format!("read {file}"))?;
    let new = crypto::fingerprint_of_armored(&armored)?;
    if new == old {
        bail!("{file} holds the key {uid} already has ({old}); nothing to change");
    }
    let readable: Vec<String> = vault
        .list(false)
        .iter()
        .filter(|item| {
            item.get("recipients")
                .and_then(Value::as_array)
                .is_some_and(|readers| readers.iter().any(|reader| reader.as_str() == Some(uid.as_str())))
        })
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    if !flag_set(flags, "yes") {
        return Ok(json!({"ok": true, "confirmed": false, "uid": uid, "from": old, "to": new, "would_rewrite": readable}));
    }
    crypto::import_key(&armored)?;
    let entry = vault
        .doc_mut()
        .get_mut("recipients")
        .and_then(|recipients| recipients.get_mut(uid.as_str()))
        .and_then(Value::as_object_mut)
        .with_context(|| format!("the vault's entry for {uid} is not an object"))?;
    entry.insert("fingerprint".to_string(), json!(new));
    entry.insert("rekeyed_at".to_string(), json!(crate::core::clock::now_iso()));
    vault.save()?;
    let mut rewritten = Vec::new();
    let mut not_rewritten = Vec::new();
    for id in &readable {
        match rewrite(&mut vault, id) {
            Ok(()) => rewritten.push(id.clone()),
            Err(error) => not_rewritten.push(json!({"item": id, "error": format!("{error:#}")})),
        }
    }
    crate::runtime::audit::append(
        "recipient-rekeyed",
        &json!({"uid": uid, "from": old, "to": new, "items": rewritten}),
    )?;
    Ok(json!({
        "ok": not_rewritten.is_empty(),
        "confirmed": true,
        "uid": uid,
        "from": old,
        "to": new,
        "rewritten": rewritten,
        "not_rewritten": not_rewritten,
    }))
}

/// Write one item's current value again, so it is encrypted to every
/// reader's current key; kind, tags and readers stay as they are.
fn rewrite(vault: &mut Vault, id: &str) -> Result<()> {
    let payload = vault.get_item(id)?;
    let entry = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .with_context(|| format!("no item: {id}"))?;
    let kind = entry
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{id} records no kind; run `skarbiec upgrade --apply` first"))?
        .to_string();
    let tags = crate::core::vault::entry_texts(id, entry, "tags")?;
    let recipients = vault.item_recipient_uids(id)?;
    vault.set_item(id, &kind, &payload, &recipients, &tags)
}
