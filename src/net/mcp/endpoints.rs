// The HTTP half of the MCP surface: what an agent's grant lets it list, and
// the acquisition it may ask for over the loopback API.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::net::http;
use wisent_errors::Code;

// === serve endpoint handlers relocated from net::http ===
// Routed by net::http's listener; they live in this module only because
// net::http and net::mod are at the per-file line budget. Behavior unchanged.

pub(crate) fn handle_acquisitions_issue(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let Some(parsed) = http::request_json(stream, body)? else {
        return Ok(());
    };
    let (Some(item), Some(field), Some(workload_id), Some(timestamp), Some(nonce), Some(signature)) = (
        http::request_id(&parsed),
        http::request_field(&parsed),
        parsed.get("workload_id").and_then(Value::as_str),
        parsed.get("workload_timestamp").and_then(Value::as_u64),
        parsed.get("workload_nonce").and_then(Value::as_str),
        parsed.get("workload_signature").and_then(Value::as_str),
    ) else {
        let e = &json!({"error": "exact id, field, and workload proof required"});
        return http::write_response(stream, "HTTP/1.1 400 Bad Request", e);
    };
    let consumer = match http::presented_consumer(headers) {
        Ok(consumer) => consumer,
        Err(reason) => {
            return http::write_response(
                stream,
                "HTTP/1.1 401 Unauthorized",
                &json!({"error": reason}),
            )
        }
    };
    let issued = match crate::access::acquisition::issue(
        &consumer,
        item,
        field,
        workload_id,
        timestamp,
        nonce,
        signature,
    ) {
        Ok(value) => value,
        Err(error)
            if error
                .downcast_ref::<crate::access::acquisition::AcquisitionFieldMissing>()
                .is_some() =>
        {
            eprintln!("acquisition field absent for {consumer} on {item}#{field}: {error:#}");
            let e = &json!({"error": "acquisition field does not exist on item"});
            return http::write_response(stream, "HTTP/1.1 404 Not Found", e);
        }
        Err(error) => {
            eprintln!("acquisition issue failed for {consumer} on {item}#{field}: {error:#}");
            let e = &json!({"error": Code::InfraDown.as_str()});
            return http::write_response(stream, "HTTP/1.1 503 Service Unavailable", e);
        }
    };
    let Some(issued) = issued else {
        let e = &json!({"error": "unauthorized"});
        return http::write_response(stream, "HTTP/1.1 401 Unauthorized", e);
    };
    let entry = json!({
        "consumer": consumer,
        "item": item,
        "field": field,
        "workload_id": workload_id,
        "expires_at": issued.expires_at,
    });
    crate::runtime::audit::append_sync("http-acquisition-issued", &entry)?;
    let out = json!({
        "consumer": consumer,
        "item": item,
        "field": field,
        "expires_at": issued.expires_at,
        "token": issued.token,
    });
    http::write_response(stream, "HTTP/1.1 200 OK", &out)
}

/// Why an item-index request sees nothing: it presented no identity (named),
/// or its identity holds no valid consumer grant.
pub(crate) enum ItemsRefusal {
    Unidentified(String),
    NoGrant,
}

/// The items one caller is allowed to see, or why it may see none.
///
/// This is the authorization for every route that hands back the item index,
/// held in one place so the legacy `GET /list` and `GET /audit` aliases cannot
/// drift away from the gate `POST /v1/items/list` applies. A request that
/// presents no identity is refused before the vault is read.
pub(crate) fn authorized_items(
    headers: &HashMap<String, String>,
) -> Result<std::result::Result<Vec<Value>, ItemsRefusal>> {
    let (consumer, bearer) = match http::presented_identity(headers) {
        Ok(identity) => identity,
        Err(reason) => return Ok(Err(ItemsRefusal::Unidentified(reason))),
    };
    let vault = http::load()?;
    // Hash the bearer once: hashing shells out to `shasum`, so per-item
    // hashing turned this filter into one subprocess spawn per vault item.
    let hash = grant::presented_hash(&bearer)?;
    if !grant::token_valid_hash(&vault, &consumer, &hash) {
        return Ok(Err(ItemsRefusal::NoGrant));
    }
    // A grant may cover an item by its id or by a role it plays
    // (`read:role:<role>#<field>`): the item carrying `stado:role:<role>` is
    // listed for that consumer too, so a reader granted roles sees the items
    // it may read without naming any of them.
    Ok(Ok(vault
        .list(false)
        .into_iter()
        .filter(|item| {
            let allows = |coordinate: &str| {
                grant::token_allows_any_item_hash(&vault, &consumer, &hash, "read", coordinate)
            };
            let by_id = item.get("id").and_then(Value::as_str).is_some_and(allows);
            by_id
                || item
                    .get("tags")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter_map(|tag| tag.strip_prefix("stado:role:"))
                    .any(|role| allows(&format!("role:{role}")))
        })
        .collect()))
}

/// The refusal every item-index route answers with, so an operator who loses
/// access to one of them reads the same reason from all of them.
pub(crate) fn refuse_items(stream: &mut TcpStream, refusal: ItemsRefusal) -> Result<()> {
    match refusal {
        ItemsRefusal::Unidentified(reason) => http::write_response(
            stream,
            "HTTP/1.1 401 Unauthorized",
            &json!({"error": reason}),
        ),
        ItemsRefusal::NoGrant => http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer grant required"}),
        ),
    }
}

pub(crate) fn handle_items_list(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
) -> Result<()> {
    match authorized_items(headers)? {
        Ok(visible) => http::write_response(stream, "HTTP/1.1 200 OK", &json!(visible)),
        Err(refusal) => refuse_items(stream, refusal),
    }
}
