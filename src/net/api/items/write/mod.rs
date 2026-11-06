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

/// The managed write a caller asks for, declared once: the refusal of an
/// unknown mode, the dispatch and the answer all read it, so a mode nobody
/// handles is refused as such before any item is looked at.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Acquire,
    Stage,
    Rotate,
}

const MODES: &[Mode] = &[Mode::Acquire, Mode::Stage, Mode::Rotate];

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Acquire => "acquire",
            Mode::Stage => "stage",
            Mode::Rotate => "rotate",
        }
    }

    fn parse(name: &str) -> Option<Mode> {
        MODES.iter().copied().find(|mode| mode.as_str() == name)
    }

    fn names() -> String {
        MODES
            .iter()
            .map(|mode| mode.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

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
    let Some(asked) = parsed.get("mode").and_then(Value::as_str) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": format!("mode required: one of {}", Mode::names())}),
        );
    };
    let Some(mode) = Mode::parse(asked) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": format!("mode {asked} is not a managed write; send one of {}", Mode::names())}),
        );
    };
    let (consumer, bearer) = match http::presented_identity(headers) {
        Ok(identity) => identity,
        Err(reason) => return http::unidentified(stream, &reason),
    };
    let mut vault = http::load()?;
    // Grants name the requested coordinate; records and writes use its resolved
    // item. An unreadable acquisition refuses resolution before any mutation.
    let requested = id;
    let resolved;
    let id = match requested.strip_prefix("role:") {
        None => requested,
        Some(role) => {
            let item = match mode {
                Mode::Acquire => crate::credential::pending_role_acquisition(&vault, role),
                Mode::Stage => {
                    crate::access::acquisition::role::item_for(&vault, requested).map(Some)
                }
                Mode::Rotate => Ok(None),
            };
            let item = match item {
                Ok(Some(item)) => item,
                Ok(None) => {
                    return http::write_response(
                        stream,
                        "HTTP/1.1 409 Conflict",
                        &json!({"error": format!(
                            "role {role} resolves to no item for {mode}: stage needs the one live item tagged stado:role:{role}, acquire needs an acquisition started with credential acquire role:{role}, and rotate names an item", mode = mode.as_str()
                        )}),
                    );
                }
                Err(error) => {
                    return http::write_response(
                        stream,
                        "HTTP/1.1 409 Conflict",
                        &json!({"error": format!("resolve {requested} for {mode}: {error:#}", mode = mode.as_str())}),
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
    if mode == Mode::Stage
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
        Mode::Rotate => {
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
        Mode::Acquire => {
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
        Mode::Stage => {
            if !grant::token_allows_field_action(
                &vault,
                &consumer,
                &bearer,
                crate::access::actions::Action::Stage.as_str(),
                requested,
                field,
            )? {
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
                Some(base_revision),
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
    };
    crate::runtime::audit::append(
        "http-item-field-write",
        &json!({
            "item": id,
            "requested": requested,
            "field": field,
            "mode": mode.as_str(),
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
            "mode": mode.as_str(),
            "operation_id": operation_id,
            "revision": revision,
        }),
    )
}
