// Reading one field of one item over the local API: an exact grant, then the
// value, and nothing else about the vault.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;
use wisent_errors::Code;

use crate::access::grant;
use crate::core::schema;
use crate::net::http;

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
    let Some(field) = http::request_field(&parsed) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "field required"}),
        );
    };
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    if consumer.is_empty()
        || !grant::token_allows_field_action(&vault, &consumer, &bearer, "read", id, field)?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer not authorized to read item field"}),
        );
    }
    // An adopt candidate the provider has not confirmed is readable only by
    // the adopt verification path, never by an ordinary read grant.
    if field != "context"
        && matches!(
            crate::credential::managed_read(&vault, id, field, &consumer)?,
            crate::credential::ManagedRead::Refused
        )
    {
        return http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({"error": "credential adoption is in flight; the staged candidate is not readable"}),
        );
    }
    let stored = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .and_then(|items| items.get(id));
    let Some(stored) = stored else {
        return http::write_response(
            stream,
            "HTTP/1.1 404 Not Found",
            &json!({"error": "item not found"}),
        );
    };
    // A state the operator must change is not an outage, and every one of
    // these used to leave here as `503 infra_down`, which the Stado contract
    // reads as retryable: callers retried a trashed item forever and the
    // sentence blamed unreachable infrastructure. `410 Gone` is the one status
    // that already classifies as `not_found` for that client -- and
    // `wisent-errors` is where what that code means (its severity, and that it
    // is never retryable) is decided, for this vault and for its callers
    // alike. Unlike `404`, `410` is not silently read as an absent optional
    // value.
    if stored.get("state").and_then(Value::as_str) == Some("trashed") {
        return http::write_response(
            stream,
            "HTTP/1.1 410 Gone",
            &json!({
                "error": "item is in trash",
                "error_code": Code::NotFound.as_str(),
                "detail": format!("restore it first: skarbiec restore {id}"),
            }),
        );
    }
    if stored.get("format").and_then(Value::as_u64) != Some(crate::core::vault::current_envelope())
    {
        return http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({
                "error": "item uses the legacy envelope",
                "error_code": Code::Config.as_str(),
                "detail": format!("run migrate-v2 before reading {id}"),
            }),
        );
    }
    let payload = match vault.get_item(id) {
        Ok(payload) => payload,
        Err(error) => {
            let detail = error.to_string();
            eprintln!("item decryption failed: {id}: {detail}");
            crate::runtime::audit::append(
                "http-item-read-undecryptable",
                &json!({"item": id, "field": field, "consumer": consumer}),
            )?;
            return http::write_response(
                stream,
                "HTTP/1.1 503 Service Unavailable",
                &json!({
                    "error": "item is stored but could not be decrypted",
                    "error_code": Code::InfraDown.as_str(),
                    "detail": http::bounded_detail(&detail),
                }),
            );
        }
    };
    let value = if field == "context" {
        payload
            .get("context")
            .cloned()
            .context("canonical item has no context")?
    } else {
        schema::field(&payload, field)?.clone()
    };
    crate::runtime::audit::append(
        "http-item-read",
        &json!({"item": id, "field": field, "consumer": consumer}),
    )?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({"id": id, "field": field, "value": value}),
    )
}
