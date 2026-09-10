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
    let parsed = http::request_json(body);
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
    let (consumer, _) = http::presented_identity(headers);
    let issued = if consumer.is_empty() {
        None
    } else {
        match crate::access::acquisition::issue(
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

/// The items one caller is allowed to see, or `None` when the caller presented
/// no usable consumer grant.
///
/// This is the authorization for every route that hands back the item index,
/// held in one place so the legacy `GET /list` and `GET /audit` aliases cannot
/// drift away from the gate `POST /v1/items/list` applies.
pub(crate) fn authorized_items(headers: &HashMap<String, String>) -> Result<Option<Vec<Value>>> {
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    // Hash the bearer once: hashing shells out to `shasum`, so per-item
    // hashing turned this filter into one subprocess spawn per vault item.
    let hash = grant::presented_hash(&bearer)?;
    if consumer.is_empty() || !grant::token_valid_hash(&vault, &consumer, &hash) {
        return Ok(None);
    }
    Ok(Some(
        vault
            .list(false)
            .into_iter()
            .filter(|item| {
                item.get("id").and_then(Value::as_str).is_some_and(|id| {
                    grant::token_allows_any_item_hash(&vault, &consumer, &hash, "read", id)
                })
            })
            .collect(),
    ))
}

/// The refusal every item-index route answers with, so an operator who loses
/// access to one of them reads the same reason from all of them.
pub(crate) fn refuse_without_grant(stream: &mut TcpStream) -> Result<()> {
    let e = &json!({"error": "consumer grant required"});
    http::write_response(stream, "HTTP/1.1 403 Forbidden", e)
}

pub(crate) fn handle_items_list(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
) -> Result<()> {
    let Some(visible) = authorized_items(headers)? else {
        return refuse_without_grant(stream);
    };
    http::write_response(stream, "HTTP/1.1 200 OK", &json!(visible))
}
