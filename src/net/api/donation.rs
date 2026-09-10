// The p2p donation path: a donor seals an item to this vault and it waits in
// the inbox until the owner accepts it (docs/design/bond.md).

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::core::inbox;
use crate::net::http;

/// `POST /v1/donations` — p2p v2: enqueue into the donation inbox instead of
/// merging; the owner merges with donation-accept (docs/design/bond.md).
/// Requires an exact `donate:<item_id>` grant. Provenance rule: an existing id
/// admits the donation only when its `written_by` matches the donor's `from` claim.
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
    let vault = http::load()?;
    if consumer.is_empty()
        || !grant::token_allows_vault_action(&vault, &consumer, &bearer, "donate", item_id)?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("donate:{item_id} grant required")}),
        );
    }
    let from = parsed
        .get("from")
        .and_then(Value::as_str)
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| consumer.clone());
    let rule = inbox::admission(&vault, item_id, &from);
    if rule != "append" && rule != "overwrite" {
        crate::runtime::audit::append(
            "http-donation-refused",
            &json!({"item": item_id, "consumer": consumer, "from": from, "status": rule}),
        )?;
        return http::write_response(
            stream,
            "HTTP/1.1 200 OK",
            &json!({"ok": false, "status": rule, "id": item_id}),
        );
    }
    let item_kind = parsed
        .get("kind")
        .and_then(Value::as_str)
        .context("donation requires canonical item kind")?;
    let donation_id = inbox::enqueue(item_id, &consumer, &from, item_kind, armor)?;
    crate::runtime::audit::append(
        "http-donation-queued",
        &json!({"donation": donation_id, "item": item_id, "consumer": consumer, "from": from}),
    )?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({"ok": true, "status": "pending", "donation_id": donation_id, "id": item_id}),
    )
}
