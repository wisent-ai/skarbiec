// Bond serve channel (docs/design/bond.md): the replica-mode pull client and
// the serve handlers it talks to. `pull` fetches the whole ciphertext document
// from a serve and atomically replaces the local vault with it; `GET /v1/vault`
// is the serving side of that channel, gated by a `sync:pull` grant;
// `POST /v1/enroll` lets a replica register its key and be re-sealed into
// listed items. These live in their own module so each source file stays
// within the repository's per-file line budget.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::core::{crypto, inbox, vault_path};
use crate::net::http;

fn now_iso() -> String {
    crate::core::clock::now_iso()
}

pub(crate) use super::serve::serve_request;

/// `GET /v1/vault` — replica-mode pull of the whole ciphertext document.
/// Requires a `sync:pull` grant; items are served exactly as stored
/// ciphertext and are never decrypted here.
pub(crate) fn handle_vault_pull(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
) -> Result<()> {
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    if consumer.is_empty()
        || !grant::token_allows_vault_action(&vault, &consumer, &bearer, "sync", "pull")?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "sync:pull grant required"}),
        );
    }
    crate::runtime::audit::append("http-vault-pull", &json!({"consumer": consumer}))?;
    http::write_response(stream, "HTTP/1.1 200 OK", vault.doc())
}

/// `POST /v1/enroll` — a replica sends its armored public key and a list of
/// item ids; the source registers the key as a member recipient and re-seals
/// each listed item to include it. Requires an exact `enroll:<uid>` grant.
/// After the next pull, the replica can open exactly those items with its own key.
pub(crate) fn handle_enroll(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let bad = "HTTP/1.1 400 Bad Request";
    let Some(parsed) = http::request_json(stream, body)? else {
        return Ok(());
    };
    let Some(uid) = parsed
        .get("uid")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty())
    else {
        return http::write_response(stream, bad, &json!({"error": "uid required"}));
    };
    let Some(armored) = parsed
        .get("armored")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty())
    else {
        return http::write_response(stream, bad, &json!({"error": "armored required"}));
    };
    // The items to share with the enrolled key. An absent list shares none; a
    // list with an entry that is not an item id is refused, since dropping it
    // left that item unshared and unnamed among the skipped ones.
    let items: Vec<String> = match parsed.get("items") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(listed)) => match listed
            .iter()
            .map(|entry| entry.as_str().map(str::to_string))
            .collect::<Option<Vec<String>>>()
        {
            Some(items) => items,
            None => {
                return http::write_response(
                    stream,
                    bad,
                    &json!({"error": format!("items must list item ids as text: {}", Value::Array(listed.clone()))}),
                )
            }
        },
        Some(other) => {
            return http::write_response(
                stream,
                bad,
                &json!({"error": format!("items must be a list of item ids, not {other}")}),
            )
        }
    };
    let (consumer, bearer) = http::presented_identity(headers);
    let mut vault = http::load()?;
    if consumer.is_empty()
        || !grant::token_allows_vault_action(&vault, &consumer, &bearer, "enroll", uid)?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("enroll:{uid} grant required")}),
        );
    }
    crypto::import_key(armored).context("import enrolled public key")?;
    let fingerprint =
        crypto::fingerprint_for(uid)?.context("enrolled key has no uid match in the keyring")?;
    vault.register_recipient(uid, &fingerprint, "member")?;
    let mut shared = Vec::new();
    let mut skipped = Vec::new();
    for id in &items {
        let known = vault
            .doc()
            .get("items")
            .and_then(Value::as_object)
            .is_some_and(|all| all.contains_key(id));
        if !known {
            skipped.push(id.clone());
            continue;
        }
        let payload = vault.get_item(id)?;
        let item_kind = vault
            .doc()
            .get("items")
            .and_then(|all| all.get(id))
            .and_then(|item| item.get("kind"))
            .and_then(Value::as_str)
            .context("canonical item has no kind")?
            .to_string();
        let tags = match vault.doc().get("items").and_then(|all| all.get(id)) {
            Some(item) => crate::core::vault::entry_texts(id, item, "tags")?,
            None => Vec::new(),
        };
        let mut recipients = vault.item_recipient_uids(id)?;
        if !recipients.iter().any(|r| r == uid) {
            recipients.push(uid.to_string());
        }
        // Re-encryption preserves the active revision's provenance.
        let writer = inbox::written_by(&vault, id);
        if let Some(writer) = writer.as_deref() {
            vault.set_item_written_by(id, &item_kind, &payload, &recipients, &tags, writer)?;
        } else {
            vault.set_item(id, &item_kind, &payload, &recipients, &tags)?;
        }
        shared.push(id.clone());
    }
    crate::runtime::audit::append(
        "http-enroll",
        &json!({"consumer": consumer, "uid": uid, "shared": shared, "skipped": skipped}),
    )?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({"ok": true, "uid": uid, "fingerprint": fingerprint, "shared": shared, "skipped": skipped}),
    )
}

// Replica mode: fetch the whole ciphertext document from a serve channel and
// atomically replace the local vault with it. A replica must never shrink:
// replacing the local vault with a smaller one destroys local-only items, so
// the pull refuses unless forced. The staged file sits next to the live vault
// so the rename is atomic and no reader sees a partial write. Local bond
// configs are the replica's own relationships — they are carried across the
// replace and stamped with the pull time so bond status can report it.
pub(crate) fn cmd_pull(flags: &HashMap<String, String>) -> Result<Value> {
    let usage = "usage: pull --from <base-url> --token-file <path> [--bond name] [--consumer name, replica when not given] [--force]";
    let from = flags.get("from").context(usage)?;
    let token = crate::credential::bearer_from_file(flags, "pull")?;
    let consumer = match flags.get("consumer") {
        Some(named) => named.as_str(),
        None => "replica",
    };
    let (status, pulled) = serve_request(from, "GET", "/v1/vault", consumer, &token, None)?;
    let (Some(remote_items), Some(_)) = (
        pulled.get("items").and_then(Value::as_object),
        pulled.get("version"),
    ) else {
        bail!("remote did not return a vault document (status: {status}, body: {pulled})");
    };
    let remote_count = remote_items.len();
    let live = vault_path();
    let local: Option<Value> = match crate::core::read_present(&live, "vault")? {
        Some(text) => Some(
            serde_json::from_str(&text)
                .with_context(|| format!("parse vault {}", live.display()))?,
        ),
        None => None,
    };
    // A host with no vault yet has nothing a smaller vault could destroy.
    let local_count = local
        .as_ref()
        .map(|local| {
            let items = local.get("items").and_then(Value::as_object);
            items
                .map(serde_json::Map::len)
                .with_context(|| format!("vault {} holds no items map", live.display()))
        })
        .transpose()?;
    if let Some(local_count) = local_count.filter(|local| remote_count < *local) {
        if !flags.contains_key("force") {
            bail!("pull: refusing to replace the local vault ({local_count} items) with the remote's {remote_count}; re-run with --force to accept the loss");
        }
    }
    let mut doc = pulled;
    if let Some(bonds) = local.as_ref().and_then(|local| local.get("bond")).cloned() {
        doc["bond"] = bonds;
    }
    let stamp = now_iso();
    let wanted = flags.get("bond");
    let address = from.trim_end_matches('/');
    if let Some(bonds) = doc.get_mut("bond").and_then(Value::as_object_mut) {
        for (name, entry) in bonds.iter_mut() {
            let addressed = entry
                .get("channel")
                .and_then(|c| c.get("address"))
                .and_then(Value::as_str)
                .is_some_and(|a| a.trim_end_matches('/') == address);
            if addressed || wanted.is_some_and(|w| w == name) {
                entry["last_pull_at"] = json!(stamp);
                entry["last_items_after"] = json!(remote_count);
            }
        }
    }
    crate::core::vault::atomic_write(&live, serde_json::to_string_pretty(&doc)?.as_bytes())
        .with_context(|| format!("install pulled vault at {}", live.display()))?;
    crate::runtime::audit::append(
        "pull",
        &json!({"from": from, "items_before": local_count, "items_after": remote_count}),
    )?;
    Ok(json!({"ok": true, "items_before": local_count, "items_after": remote_count}))
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "pull" => cmd_pull(flags).map(Some),
        _ => Ok(None),
    }
}
