// Writing one field of one item over the local API: an exact grant, the
// staging or rotation mode the caller asked for, and the revision it produced.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;


use crate::access::grant;
use crate::core::{inbox, schema};
use crate::net::http;

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
    let Some(field) = http::request_field(&parsed) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "field required"}),
        );
    };
    let Some(operation_id) = parsed.get("operation_id").and_then(Value::as_str) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "operation_id required"}),
        );
    };
    let mode = parsed.get("mode").and_then(Value::as_str).unwrap_or("");
    let (consumer, bearer) = http::presented_identity(headers);
    let mut vault = http::load()?;
    if crate::credential::lifecycle_owned_item(&vault, id) {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "credential operation records and sealed directory contracts cannot be changed through item APIs"}),
        );
    }
    if mode != "acquire"
        && (!inbox::managed_by_weles(&vault, id)
            || inbox::written_by(&vault, id).as_deref() != Some(consumer.as_str()))
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "item is not controlled by this exact Weles writer"}),
        );
    }
    let revision = match mode {
        "acquire" => {
            if parsed.get("provider_verified").and_then(Value::as_bool) != Some(true) {
                return http::write_response(
                    stream,
                    "HTTP/1.1 409 Conflict",
                    &json!({"error": "provider verification required before acquire"}),
                );
            }
            if consumer.is_empty()
                || !grant::token_allows_field_action(
                    &vault, &consumer, &bearer, "stage", id, field,
                )?
            {
                return http::write_response(
                    stream,
                    "HTTP/1.1 403 Forbidden",
                    &json!({"error": "consumer not authorized to acquire item field"}),
                );
            }
            if vault.get_item(id).is_ok() {
                return http::write_response(
                    stream,
                    "HTTP/1.1 409 Conflict",
                    &json!({"error": "managed item already exists; use stage"}),
                );
            }
            let payload = parsed
                .get("value")
                .cloned()
                .context("canonical payload required for acquire")?;
            let kind = payload
                .get("kind")
                .and_then(Value::as_str)
                .context("canonical payload kind required for acquire")?;
            schema::field(&payload, field)
                .context("acquired payload does not contain authorized field")?;
            crate::credential::authorize_managed_write(
                &vault,
                id,
                field,
                &consumer,
                operation_id,
                &["acquire"],
                u64::MIN,
                parsed.get("capture_origin").and_then(Value::as_str),
            )?;
            vault.set_managed_item(
                id,
                kind,
                &payload,
                &[],
                &["managed:weles".to_string()],
                crate::core::vault::ManagedWrite {
                    controller: "weles",
                    writer: &consumer,
                    operation_id: Some(operation_id),
                },
            )?;
            "1".parse()?
        }
        "stage" => {
            if consumer.is_empty()
                || !grant::token_allows_field_action(
                    &vault, &consumer, &bearer, "stage", id, field,
                )?
            {
                return http::write_response(
                    stream,
                    "HTTP/1.1 403 Forbidden",
                    &json!({"error": "consumer not authorized to stage item field"}),
                );
            }
            let Some(value) = parsed.get("value").cloned() else {
                return http::write_response(
                    stream,
                    "HTTP/1.1 400 Bad Request",
                    &json!({"error": "value required for stage"}),
                );
            };
            let base_revision = parsed
                .get("base_revision")
                .and_then(Value::as_u64)
                .or_else(|| {
                    vault
                        .get_item(&format!("operation:credential/{id}"))
                        .ok()
                        .and_then(|payload| schema::field(&payload, "value").ok().cloned())
                        .and_then(|request| {
                            request.get("baseline_revision").and_then(Value::as_u64)
                        })
                });
            let Some(base_revision) = base_revision else {
                return http::write_response(
                    stream,
                    "HTTP/1.1 400 Bad Request",
                    &json!({"error": "base_revision unavailable for stage"}),
                );
            };
            crate::credential::authorize_managed_write(
                &vault,
                id,
                field,
                &consumer,
                operation_id,
                &["rotate", "reset", "verify"],
                base_revision,
                parsed.get("capture_origin").and_then(Value::as_str),
            )?;
            vault.stage_managed_field(
                id,
                field,
                value,
                base_revision,
                crate::core::vault::ManagedWrite {
                    controller: "weles",
                    writer: &consumer,
                    operation_id: Some(operation_id),
                },
            )?
        }
        _ => {
            return http::write_response(
                stream,
                "HTTP/1.1 400 Bad Request",
                &json!({"error": "mode must be acquire or stage"}),
            );
        }
    };
    crate::runtime::audit::append(
        "http-item-field-write",
        &json!({
            "item": id,
            "field": field,
            "mode": mode,
            "operation_id": operation_id,
            "revision": revision,
            "consumer": consumer,
        }),
    )?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({
            "ok": true,
            "id": id,
            "field": field,
            "mode": mode,
            "operation_id": operation_id,
            "revision": revision,
        }),
    )
}
