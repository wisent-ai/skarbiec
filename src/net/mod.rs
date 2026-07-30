// Network layer: git-backed multi-device sync of the encrypted vault, and a
// local HTTP API the separate client products integrate against. Some serve
// endpoint handlers — item read/write and the p2p donation path (owner
// pubkey + donations) — live here rather than in net::http so every file
// stays within the repository's per-file line budget; net::http keeps the
// listener, the route table, and the shared helpers they call. Routing and
// behavior are unchanged by the split.

pub mod http;
pub mod mcp;
pub mod sync;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::tokens;
use crate::core::crypto;

pub(crate) fn handle_items_read(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let Some(id) = http::request_id(&parsed) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "id required"}),
        );
    };
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    if consumer.is_empty()
        || !tokens::token_allows_action(&vault, &consumer, &bearer, "read", id)?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer not authorized to read item"}),
        );
    }
    let known = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .is_some_and(|items| items.contains_key(id));
    if !known {
        return http::write_response(
            stream,
            "HTTP/1.1 404 Not Found",
            &json!({"error": "item not found"}),
        );
    }
    // `?` here returned no HTTP response at all: the error travelled to the
    // accept loop, which logged it and dropped the connection, so a caller
    // saw a transport failure rather than a status. An item that is stored
    // but unopenable is an outage on our side, and it must say so — never
    // 404, which is the answer reserved for "this was never here".
    let value = match vault.get_item(id) {
        Ok(value) => value,
        Err(error) => {
            let detail = error.to_string();
            eprintln!("item decryption failed: {id}: {detail}");
            crate::runtime::audit::append(
                "http-item-read-undecryptable",
                &json!({"item": id, "consumer": consumer}),
            )?;
            return http::write_response(
                stream,
                "HTTP/1.1 503 Service Unavailable",
                &json!({
                    "error": "item is stored but could not be decrypted",
                    "error_code": "infra_down",
                    "detail": http::bounded_detail(&detail),
                }),
            );
        }
    };
    crate::runtime::audit::append(
        "http-item-read",
        &json!({"item": id, "consumer": consumer}),
    )?;
    http::write_response(stream, "HTTP/1.1 200 OK", &json!({"id": id, "value": value}))
}

pub(crate) fn handle_items_put(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let Some(id) = http::request_id(&parsed) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "id required"}),
        );
    };
    let Some(value) = parsed.get("value") else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "value required"}),
        );
    };
    let (consumer, bearer) = http::presented_identity(headers);
    let mut vault = http::load()?;
    if consumer.is_empty()
        || !tokens::token_allows_action(&vault, &consumer, &bearer, "write", id)?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer not authorized to write item"}),
        );
    }
    let existing = vault.doc().get("items").and_then(|items| items.get(id));
    let item_type = parsed
        .get("type")
        .and_then(Value::as_str)
        .or_else(|| {
            existing
                .and_then(|item| item.get("type"))
                .and_then(Value::as_str)
        })
        .unwrap_or("secret")
        .to_string();
    let recipients = vault.item_recipient_uids(id);
    let tags: Vec<String> = existing
        .and_then(|item| item.get("tags"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    vault.set_item(id, &item_type, value, &recipients, &tags)?;
    crate::runtime::audit::append(
        "http-item-write",
        &json!({"item": id, "consumer": consumer}),
    )?;
    http::write_response(stream, "HTTP/1.1 200 OK", &json!({"ok": true, "id": id}))
}

// === bond serve endpoints: the p2p donation path (docs/design/bond.md) ===

/// `GET /v1/owner-pubkey` — the vault owner's armored public key. A donor
/// needs it to seal a donation to this vault; the public half is not secret,
/// so no grant is required.
pub(crate) fn handle_owner_pubkey(stream: &mut TcpStream) -> Result<()> {
    let vault = http::load()?;
    let owner = vault.owner_uid().to_string();
    let fingerprint = vault
        .recipient_fpr(&owner)
        .context("owner has no registered fingerprint")?;
    let armored = crypto::export_public_key(&fingerprint)?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({"ok": true, "owner": owner, "fingerprint": fingerprint, "armored": armored}),
    )
}

/// `POST /v1/donations` — the p2p inbound write. The body names a consumer,
/// an item id, and the item's fields JSON encrypted to this vault's owner
/// key; a `donate` grant is required. v1 merge rule: a new id is appended,
/// an existing id is rejected with status "exists" — never overwritten.
pub(crate) fn handle_donation(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let bad = "HTTP/1.1 400 Bad Request";
    let parsed = http::request_json(body);
    let Some(item_id) = parsed
        .get("item_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return http::write_response(stream, bad, &json!({"error": "item_id required"}));
    };
    let Some(armor) = parsed
        .get("armor")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    else {
        return http::write_response(stream, bad, &json!({"error": "armor required"}));
    };
    let (header_consumer, bearer) = http::presented_identity(headers);
    let consumer = parsed
        .get("consumer")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or(header_consumer);
    let mut vault = http::load()?;
    if consumer.is_empty()
        || !tokens::token_allows_vault_action(&vault, &consumer, &bearer, "donate", "")?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "donate grant required"}),
        );
    }
    let exists = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .is_some_and(|items| items.contains_key(item_id));
    if exists {
        crate::runtime::audit::append(
            "http-donation-exists",
            &json!({"item": item_id, "consumer": consumer}),
        )?;
        return http::write_response(
            stream,
            "HTTP/1.1 200 OK",
            &json!({"ok": false, "status": "exists", "id": item_id}),
        );
    }
    let plain = match crypto::decrypt(armor) {
        Ok(plain) => plain,
        Err(error) => {
            return http::write_response(
                stream,
                bad,
                &json!({"ok": false, "error": "donation armor could not be decrypted", "detail": http::bounded_detail(&error.to_string())}),
            );
        }
    };
    let fields: Value = match serde_json::from_str::<Value>(&plain) {
        Ok(value) if value.is_object() => value,
        _ => {
            return http::write_response(
                stream,
                bad,
                &json!({"ok": false, "error": "donation payload is not a JSON object"}),
            );
        }
    };
    let item_type = parsed
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("secret");
    vault.set_item(item_id, item_type, &fields, &[], &[])?;
    crate::runtime::audit::append(
        "http-donation-stored",
        &json!({"item": item_id, "consumer": consumer}),
    )?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({"ok": true, "status": "created", "id": item_id}),
    )
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if let Some(v) = sync::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = http::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    Ok(None)
}
