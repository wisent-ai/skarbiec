// Per-user recipients and cryptographic sharing. Adding a user gives them a gpg
// key; sharing an item re-encrypts it to include their key; revoking re-encrypts
// to the remaining recipients (plus the always-present owner + recovery keys).

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{crypto, vault::Vault, vault_path};

// Item type + tags as stored, so a re-encrypt preserves them.
fn item_meta(vault: &Vault, id: &str) -> Result<(String, Vec<String>)> {
    let item = vault
        .doc()
        .get("items")
        .and_then(|m| m.get(id))
        .with_context(|| format!("no item: {id}"))?;
    let item_type = item
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("login")
        .to_string();
    let tags = item
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok((item_type, tags))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "add-user" => {
            let mut args = positionals.iter();
            let uid = args
                .next()
                .context("usage: add-user <uid> [--import <pubkey-file>] [--role r]")?;
            let role = flags.get("role").map(String::as_str).unwrap_or("member");
            // `add-user` registers a recipient and stops there: it does NOT
            // re-encrypt the items already in the vault. For a member that is
            // correct — `share` grants per item on purpose. For an owner it is
            // a trap, and it fired: an owner added this way holds a key that
            // opens nothing, while the vault still answers every read from the
            // previous owner's key. If that key then goes missing, every item
            // is unreadable and the audit log shows only a successful
            // `add-user`.
            //
            // `rotate-owner` is the operation that means what this looked like:
            // it rewraps every current and historical ciphertext onto the new
            // fingerprint and keeps the recovery recipient. Refuse here rather
            // than half-do it.
            if role == "owner" {
                anyhow::bail!(
                    "add-user cannot install an owner: it would register the key without \
                     re-encrypting the {} item(s) already stored, leaving an owner that \
                     cannot read them. Use `rotate-owner <uid>`, which rewraps every \
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
        "rotate-owner" => {
            let mut args = positionals.iter();
            let uid = args.next().context("usage: rotate-owner <new-owner-uid>")?;
            // Deliberately no key generation. `add-user` generating a key for
            // an unknown uid is what turned one command into an outage: a key
            // minted here would be a key no ciphertext was ever encrypted to.
            // The new owner's key must already be in the keyring, imported or
            // generated on purpose beforehand.
            let fpr = crypto::fingerprint_for(uid)?.with_context(|| {
                format!(
                    "no key in the keyring for {uid}: import or generate it first \
                     (add-user {uid} --import <pubkey-file>), then rotate"
                )
            })?;
            let mut vault = Vault::open(vault_path())?;
            let report = vault.rotate_owner(uid, &fpr)?;
            crate::runtime::audit::append("rotate-owner", &report)?;
            Ok(Some(report))
        }
        "share" => {
            let mut args = positionals.iter();
            let id = args.next().context("usage: share <item-id> <uid>")?;
            let uid = args.next().context("usage: share <item-id> <uid>")?;
            let mut vault = Vault::open(vault_path())?;
            if vault.recipient_fpr(uid).is_none() {
                return Ok(Some(
                    json!({"status": "blocked", "reason": "unknown_recipient", "uid": uid}),
                ));
            }
            let (item_type, tags) = item_meta(&vault, id)?;
            let secret = vault.get_item(id)?;
            let mut recipients = vault.item_recipient_uids(id);
            if !recipients.iter().any(|r| r == uid) {
                recipients.push(uid.clone());
            }
            vault.set_item(id, &item_type, &secret, &recipients, &tags)?;
            crate::runtime::audit::append("share", &json!({"item": id, "uid": uid}))?;
            Ok(Some(
                json!({"ok": true, "item": id, "recipients": recipients}),
            ))
        }
        "revoke" => {
            let mut args = positionals.iter();
            let id = args.next().context("usage: revoke <item-id> <uid>")?;
            let uid = args.next().context("usage: revoke <item-id> <uid>")?;
            let mut vault = Vault::open(vault_path())?;
            let (item_type, tags) = item_meta(&vault, id)?;
            let secret = vault.get_item(id)?;
            let recipients: Vec<String> = vault
                .item_recipient_uids(id)
                .into_iter()
                .filter(|r| r != uid)
                .collect();
            vault.set_item(id, &item_type, &secret, &recipients, &tags)?;
            crate::runtime::audit::append("revoke", &json!({"item": id, "uid": uid}))?;
            Ok(Some(
                json!({"ok": true, "item": id, "recipients": recipients}),
            ))
        }
        "users" => {
            let vault = Vault::open(vault_path())?;
            let users = vault
                .doc()
                .get("recipients")
                .cloned()
                .unwrap_or_else(|| json!({}));
            Ok(Some(users))
        }
        "export-key" => {
            let uid = positionals.first().context("usage: export-key <uid>")?;
            let vault = Vault::open(vault_path())?;
            let fpr = vault
                .recipient_fpr(uid)
                .with_context(|| format!("unknown recipient: {uid}"))?;
            Ok(Some(
                json!({"uid": uid, "public_key": crypto::export_public_key(&fpr)?}),
            ))
        }
        // The bond configuration commands (bond-add/bond-list/bond-remove) live
        // in crate::bonds with the other bond operations.
        // p2p outbound write: seal one item's fields JSON to the remote
        // vault's owner key (fetched from its serve and imported here), then
        // POST it as a donation. The remote side queues it in the inbox.
        "donate" => {
            let item_id = positionals.first().context(
                "usage: donate <item-id> --to <base-url> --consumer <name> --token <token>",
            )?;
            let to = flags.get("to").context("--to required")?;
            let consumer = flags.get("consumer").context("--consumer required")?;
            let token = flags.get("token").context("--token required")?;
            let vault = Vault::open(vault_path())?;
            let fields = vault.get_item(item_id)?;
            let item_type = vault
                .doc()
                .get("items")
                .and_then(|items| items.get(item_id))
                .and_then(|item| item.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("secret")
                .to_string();
            let (_status, owner) =
                crate::net::bond::serve_request(to, "GET", "/v1/owner-pubkey", consumer, token, None)?;
            let armored = owner
                .get("armored")
                .and_then(Value::as_str)
                .context("remote did not return an owner public key")?;
            let fingerprint = owner
                .get("fingerprint")
                .and_then(Value::as_str)
                .context("remote owner key has no fingerprint")?;
            crypto::import_key(armored).context("import remote owner public key")?;
            let armor =
                crypto::encrypt_to(&[fingerprint.to_string()], &serde_json::to_string(&fields)?)?;
            let from = flags.get("from").unwrap_or(consumer);
            let (_status, response) = crate::net::bond::serve_request(
                to,
                "POST",
                "/v1/donations",
                consumer,
                token,
                Some(&json!({
                    "consumer": consumer,
                    "from": from,
                    "item_id": item_id,
                    "type": item_type,
                    "armor": armor,
                })),
            )?;
            crate::runtime::audit::append(
                "donate",
                &json!({"to": to, "item": item_id, "consumer": consumer}),
            )?;
            Ok(Some(response))
        }
        _ => Ok(None),
    }
}
