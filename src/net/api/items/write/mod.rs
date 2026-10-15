// Writing one field of one item over the local API: an exact grant, the
// staging or rotation mode the caller asked for, and the revision it produced.

mod acquire;

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::core::inbox;
use crate::credential::Operation;
use crate::net::http;

pub(crate) fn handle_items_put(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let Some(parsed) = http::request_json(stream, body)? else {
        return Ok(());
    };
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
    let Some(mode) = parsed.get("mode").and_then(Value::as_str) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "mode required: acquire, stage or rotate"}),
        );
    };
    let (consumer, bearer) = http::presented_identity(headers);
    let mut vault = http::load()?;
    // Grants name the requested coordinate; records and writes use its resolved
    // item. An unreadable acquisition refuses resolution before any mutation.
    let requested = id;
    let resolved;
    let id = match requested.strip_prefix("role:") {
        None => requested,
        Some(role) => {
            let item = match mode {
                "acquire" => crate::credential::pending_role_acquisition(&vault, role),
                "stage" => crate::access::acquisition::role::item_for(&vault, requested).map(Some),
                _ => Ok(None),
            };
            let item = match item {
                Ok(Some(item)) => item,
                Ok(None) => {
                    return http::write_response(
                        stream,
                        "HTTP/1.1 409 Conflict",
                        &json!({"error": format!(
                            "role {role} resolves to no item for {mode}: stage needs the one live item tagged stado:role:{role}, acquire needs an acquisition started with credential acquire role:{role}, and rotate names an item"
                        )}),
                    );
                }
                Err(error) => {
                    return http::write_response(
                        stream,
                        "HTTP/1.1 409 Conflict",
                        &json!({"error": format!("resolve {requested} for {mode}: {error:#}")}),
                    );
                }
            };
            resolved = item;
            resolved.as_str()
        }
    };
    if crate::credential::lifecycle_owned_item(&vault, id) {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "credential operation records and sealed directory contracts cannot be changed through item APIs"}),
        );
    }
    if mode == "rotate" {
        return super::rotate::handle(
            stream,
            vault,
            super::rotate::Rotation {
                id,
                field,
                operation_id,
                consumer: &consumer,
                bearer: &bearer,
                value: parsed.get("value"),
            },
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
            let acquisition = acquire::Acquisition {
                requested,
                id,
                field,
                operation_id,
                consumer: &consumer,
                bearer: &bearer,
                parsed: &parsed,
            };
            match acquire::acquire(stream, &mut vault, acquisition)? {
                Some(revision) => revision,
                None => return Ok(()),
            }
        }
        "stage" => {
            if consumer.is_empty()
                || !grant::token_allows_field_action(
                    &vault,
                    &consumer,
                    &bearer,
                    crate::access::actions::Action::Stage.as_str(),
                    requested,
                    field,
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
            let base_revision = match parsed.get("base_revision").and_then(Value::as_u64) {
                Some(revision) => Some(revision),
                None => match crate::credential::recorded_request(&vault, id) {
                    Ok(request) => request.and_then(|request| {
                        request.get("baseline_revision").and_then(Value::as_u64)
                    }),
                    Err(error) => {
                        return http::write_response(
                            stream,
                            "HTTP/1.1 409 Conflict",
                            &json!({"error": format!("{error:#}")}),
                        );
                    }
                },
            };
            let Some(base_revision) = base_revision else {
                return http::write_response(
                    stream,
                    "HTTP/1.1 400 Bad Request",
                    &json!({"error": "base_revision unavailable for stage"}),
                );
            };
            if let Err(error) = crate::credential::authorize_managed_write(
                &vault,
                id,
                field,
                &consumer,
                operation_id,
                Operation::stages_revision,
                base_revision,
                parsed.get("capture_origin").and_then(Value::as_str),
            ) {
                return http::write_response(
                    stream,
                    "HTTP/1.1 409 Conflict",
                    &json!({"error": format!("{error:#}")}),
                );
            }
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
                &json!({"error": "mode must be acquire, stage or rotate"}),
            );
        }
    };
    crate::runtime::audit::append(
        "http-item-field-write",
        &json!({
            "item": id,
            "requested": requested,
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
            "id": requested,
            "item": id,
            "field": field,
            "mode": mode,
            "operation_id": operation_id,
            "revision": revision,
        }),
    )
}
