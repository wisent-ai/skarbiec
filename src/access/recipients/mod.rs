// Per-user recipients and cryptographic sharing. Adding a user gives them a gpg
// key; sharing an item re-encrypts it to include their key; revoking re-encrypts
// to the remaining recipients (plus the always-present owner + recovery keys);
// removing a user does that for every item they can read, all at once.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::OrUsage;
use crate::core::{crypto, vault::Vault, vault_path};

mod donate;
mod reach;
mod rekey;
mod tagged;
mod timed;

pub use timed::{expire as expire_timed_shares, follow_rename as carry_share_ends};

// Canonical item kind + tags as stored, so re-encryption preserves them.
fn item_meta(vault: &Vault, id: &str) -> Result<(String, Vec<String>)> {
    let item = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .with_context(|| format!("no item: {id}"))?;
    let item_kind = item
        .get("kind")
        .and_then(Value::as_str)
        .context("canonical item has no kind")?
        .to_string();
    let tags = crate::core::vault::entry_texts(id, item, "tags")?;
    Ok((item_kind, tags))
}

/// `recipient add|remove|list|export` is a group: the object is the command
/// and the verb its first positional; the operator routes call the leaves by
/// their whole name ("recipient add").
pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == "recipient" {
        return group(flags, positionals).map(Some);
    }
    leaf(command, flags, positionals)
}

fn group(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let Some((verb, positionals)) = positionals.split_first() else {
        return Err(crate::cli::args::Usage("recipient needs a subcommand; `skarbiec recipient help` lists them".to_string()).into());
    };
    if verb == "help" {
        return Ok(json!({
            "commands": [
                "recipient add <uid> [--import <public-key-file>] [--role <member-role>]",
                "recipient remove <uid> --yes",
                "recipient list",
                "recipient export <uid>",
                "recipient items <uid>",
                "recipient rekey <uid> --import <public-key-file> --yes",
            ],
            "usage": "recipient add registers a recipient identity without sharing any existing item; recipient remove takes one person out of every item, every historical revision and the registry, and changes nothing without --yes; recipient list prints the registered recipients; recipient export prints one recipient's public key; recipient items lists every item one recipient can open, live and trashed, without decrypting anything; recipient rekey gives one person a new key and writes every live item they read again to it, listing them first without --yes.",
        }));
    }
    if verb == "rekey" {
        return rekey::run(flags, positionals);
    }
    leaf(&format!("recipient {verb}"), flags, positionals)?.ok_or_else(|| {
        crate::cli::args::Usage(format!(
            "unknown recipient command: {verb}; `skarbiec recipient help` lists them"
        ))
        .into()
    })
}

fn leaf(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "shares" => timed::dispatch(positionals).map(Some),
        "recipient add" => {
            let mut args = positionals.iter();
            let uid = args.next().or_usage(
                "usage: recipient add <uid> [--import <public-key-file>] [--role <member-role>]",
            )?;
            // A recipient added without --role is a member: `share` then
            // grants it items one by one.
            let role = match flags.get("role") {
                Some(role) => role.as_str(),
                None => "member",
            };
            // `recipient add` registers a recipient and stops there: it does NOT
            // re-encrypt the items already in the vault. For a member that is
            // correct — `share` grants per item on purpose. For an owner it is
            // a trap, and it fired: an owner added this way holds a key that
            // opens nothing, while the vault still answers every read from the
            // previous owner's key. If that key then goes missing, every item
            // is unreadable and the audit log shows only a successful
            // `recipient add` (audited as `add-user`, the journal's own name).
            //
            // `owner rotate` is the operation that means what this looked like:
            // it rewraps every current and historical ciphertext onto the new
            // fingerprint and keeps the recovery recipient. Refuse here rather
            // than half-do it.
            if role == "owner" {
                anyhow::bail!(
                    "recipient add cannot install an owner: it would register the key without \
                     re-encrypting the {} item(s) already stored, leaving an owner that \
                     cannot read them. Use `owner rotate <uid>`, which rewraps every \
                     version onto the new key and preserves the recovery recipient.",
                    Vault::open(vault_path())?.list(true).len()
                );
            }
            let fpr = match flags.get("import") {
                Some(file) => {
                    let armored =
                        std::fs::read_to_string(file).with_context(|| format!("read {file}"))?;
                    crypto::import_key(&armored)?;
                    crypto::fingerprint_for(uid)?
                        .with_context(|| format!("imported key has no uid match for {uid}"))?
                }
                None => match crypto::fingerprint_for(uid)? {
                    Some(existing) => existing,
                    None => crypto::generate_key(uid)?,
                },
            };
            let mut vault = Vault::open(vault_path())?;
            vault.register_recipient(uid, &fpr, role)?;
            crate::runtime::audit::append("add-user", &json!({"uid": uid, "role": role}))?;
            Ok(Some(
                json!({"ok": true, "uid": uid, "fingerprint": fpr, "role": role}),
            ))
        }
        "share" => {
            if let Some(tag) = flags.get("tag") {
                let uid = positionals.first().or_usage("usage: share --tag <tag> <uid>")?;
                return tagged::share_tagged(tag, uid, flags).map(Some);
            }
            let mut args = positionals.iter();
            let id = args.next().or_usage("usage: share <item-id> <uid> | share --tag <tag> <uid>")?;
            let uid = args.next().or_usage("usage: share <item-id> <uid> | share --tag <tag> <uid>")?;
            let mut vault = Vault::open(vault_path())?;
            if vault.recipient_fpr(uid).is_none() {
                return Ok(Some(
                    json!({"status": "blocked", "reason": "unknown_recipient", "uid": uid}),
                ));
            }
            let (item_kind, tags) = item_meta(&vault, id)?;
            let until = timed::apply(&mut vault, id, uid, flags)?;
            let mut recipients = vault.item_recipient_uids(id)?;
            // Sharing with someone who already reads the item changes
            // nothing, so nothing is written: a second share used to add a
            // revision and an audit entry for a value that never changed.
            if recipients.iter().any(|r| r == uid) {
                return Ok(Some(
                    json!({"ok": true, "item": id, "recipients": recipients, "already_shared": true, "until": until}),
                ));
            }
            let payload = vault.get_item(id)?;
            recipients.push(uid.clone());
            vault.set_item(id, &item_kind, &payload, &recipients, &tags)?;
            crate::runtime::audit::append("share", &json!({"item": id, "uid": uid}))?;
            Ok(Some(
                json!({"ok": true, "item": id, "recipients": recipients, "already_shared": false, "until": until}),
            ))
        }
        // Revoking rewraps every saved version without the uid, not only the
        // current one: a new current revision left every earlier ciphertext
        // readable by the person it was meant to shut out, and `restore --at`
        // handed that value straight back. The revision does not move,
        // because the value did not change.
        "revoke" => {
            if let Some(tag) = flags.get("tag") {
                let uid = positionals.first().or_usage("usage: revoke --tag <tag> <uid>")?;
                return tagged::revoke_tagged(tag, uid).map(Some);
            }
            let mut args = positionals.iter();
            let id = args.next().or_usage("usage: revoke <item-id> <uid> | revoke --tag <tag> <uid>")?;
            let uid = args.next().or_usage("usage: revoke <item-id> <uid> | revoke --tag <tag> <uid>")?;
            let mut vault = Vault::open(vault_path())?;
            item_meta(&vault, id)?;
            let readers = vault.item_recipient_uids(id)?;
            if !readers.iter().any(|reader| reader == uid) {
                anyhow::bail!(
                    "{uid} is not a recipient of {id}, so there is nothing to revoke; its recipients are: {}",
                    if readers.is_empty() {
                        "only the owner and recovery keys".to_string()
                    } else {
                        readers.join(", ")
                    }
                );
            }
            let report = vault.withdraw_recipient(uid, std::slice::from_ref(id))?;
            timed::forget(&mut vault, id, uid);
            vault.save()?;
            crate::runtime::audit::append(
                "revoke",
                &json!({"item": id, "uid": uid, "historical_versions": report["historical_versions"]}),
            )?;
            Ok(Some(json!({
                "ok": true,
                "item": id,
                "recipients": vault.item_recipient_uids(id)?,
                "historical_versions": report["historical_versions"],
            })))
        }
        // A person leaving loses every item at once, not one `revoke` at a
        // time. The rewrap stops future reads; values they already read are
        // named, and the ones with a rotation policy are marked due now so the
        // next `rotation run` replaces them at the provider. Every item and
        // every saved version is rewritten without them and nothing restores
        // that, so the CLI needs --yes; the desktop's Remove from vault sheet
        // sends it.
        "recipient remove" => {
            let uid = positionals
                .first()
                .or_usage("usage: recipient remove <uid> --yes")?;
            let mut vault = Vault::open(vault_path())?;
            crate::cli::items::ensure_not_replica(&vault, "recipient remove")?;
            if vault.recipient_fpr(uid).is_some() && !crate::cli::args::flag_set(flags, "yes") {
                anyhow::bail!(
                    "recipient remove would rewrite every item and every saved version without {uid}; nothing was changed. \
                     Rerun with --yes to remove {uid}, or revoke single items with `skarbiec revoke <item-id> {uid}`"
                );
            }
            let mut report = vault.remove_recipient(uid)?;
            drop(vault);
            let exposed: Vec<String> = report
                .get("exposed")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.get("item").and_then(Value::as_str))
                .map(str::to_string)
                .collect();
            let marked =
                crate::credential::mark_due(&exposed, &format!("recipient {uid} was removed"))?;
            let manual: Vec<&String> = exposed.iter().filter(|id| !marked.contains(*id)).collect();
            report["rotation_marked_due"] = json!(marked);
            report["rotate_manually"] = json!(manual);
            crate::runtime::audit::append("remove-user", &report)?;
            Ok(Some(report))
        }
        "recipient list" => {
            let vault = Vault::open(vault_path())?;
            // A vault without a recipients section lists none.
            Ok(Some(match vault.doc().get("recipients") {
                Some(users) => users.clone(),
                None => json!({}),
            }))
        }
        "recipient items" => {
            let uid = positionals.first().or_usage("usage: recipient items <uid>")?;
            reach::items_of(uid).map(Some)
        }
        "recipient export" => {
            let uid = positionals
                .first()
                .or_usage("usage: recipient export <uid>")?;
            let vault = Vault::open(vault_path())?;
            let fpr = vault
                .recipient_fpr(uid)
                .with_context(|| format!("unknown recipient: {uid}"))?;
            Ok(Some(
                json!({"uid": uid, "public_key": crypto::export_public_key(&fpr)?}),
            ))
        }
        // The bond configuration group (bond add/edit/list/remove) lives
        // in crate::bonds with the other bond operations.
        "donate" => donate::donate(flags, positionals).map(Some),
        _ => Ok(None),
    }
}
