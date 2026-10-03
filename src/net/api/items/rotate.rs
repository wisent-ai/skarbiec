// Replacing one field of an owner-controlled item over the local API, under a
// consumer's exact `rotate` grant. A product that refreshes its own token (a
// calendar refresh token, a rotated API key) writes that one field back
// without owner authority: every other field, the kind, the recipients and the
// tags are kept, and the consumer is recorded as the revision's writer.
//
// Items a lifecycle or Weles controls are refused; their controller stages
// changes through `acquire`/`stage`. A replica vault is refused because the
// next pull from its source would replace the write.

use anyhow::Result;
use serde_json::{json, Value};
use std::net::TcpStream;

use crate::access::grant;
use crate::core::schema;
use crate::core::vault::Vault;
use crate::net::http;

pub(super) struct Rotation<'a> {
    pub(super) id: &'a str,
    pub(super) field: &'a str,
    pub(super) operation_id: &'a str,
    pub(super) consumer: &'a str,
    pub(super) bearer: &'a str,
    pub(super) value: Option<&'a Value>,
}

fn refuse(stream: &mut TcpStream, status: &str, error: String) -> Result<()> {
    http::write_response(stream, status, &json!({"error": error}))
}

/// `vault` is the one `handle_items_put` loaded and already checked for a
/// lifecycle-owned item, so a credential operation record or a sealed
/// directory contract never reaches this path.
pub(super) fn handle(
    stream: &mut TcpStream,
    mut vault: Vault,
    rotation: Rotation<'_>,
) -> Result<()> {
    let Rotation {
        id,
        field,
        operation_id,
        consumer,
        bearer,
        value,
    } = rotation;
    if consumer.is_empty()
        || !grant::token_allows_field_action(&vault, consumer, bearer, "rotate", id, field)?
    {
        return refuse(
            stream,
            "HTTP/1.1 403 Forbidden",
            format!("consumer {consumer:?} holds no rotate grant for {id}#{field}"),
        );
    }
    let Some(value) = value else {
        return refuse(
            stream,
            "HTTP/1.1 400 Bad Request",
            "value required for rotate".to_string(),
        );
    };
    if field == "context" {
        return refuse(
            stream,
            "HTTP/1.1 400 Bad Request",
            "rotate replaces one secret field; context is not one".to_string(),
        );
    }
    if let Err(error) = crate::cli::items::ensure_not_replica(&vault, "rotate") {
        return refuse(stream, "HTTP/1.1 409 Conflict", error.to_string());
    }
    let Some(stored) = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .and_then(|items| items.get(id))
        .cloned()
    else {
        return refuse(
            stream,
            "HTTP/1.1 404 Not Found",
            format!("no item {id}: rotate replaces a field of an existing item"),
        );
    };
    if stored.get("state").and_then(Value::as_str) == Some("trashed") {
        return refuse(
            stream,
            "HTTP/1.1 410 Gone",
            format!("{id} is trashed; restore it before rotating {field}"),
        );
    }
    if let Err(error) = vault.ensure_owner_controlled(id) {
        return refuse(
            stream,
            "HTTP/1.1 409 Conflict",
            format!("{error}; its controlling lifecycle stages field changes instead"),
        );
    }
    let mut payload = vault.get_item(id)?;
    let Some(kind) = payload
        .get("kind")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return refuse(
            stream,
            "HTTP/1.1 409 Conflict",
            format!("{id} has no canonical kind"),
        );
    };
    if !schema::allows_field(&payload, field) {
        return refuse(
            stream,
            "HTTP/1.1 400 Bad Request",
            format!("kind {kind} does not allow field {field}"),
        );
    }
    let Some(fields) = payload.get_mut("fields").and_then(Value::as_object_mut) else {
        return refuse(
            stream,
            "HTTP/1.1 409 Conflict",
            format!("{id} has no fields object"),
        );
    };
    fields.insert(field.to_string(), value.clone());
    if let Err(error) = schema::validate_payload(&payload, &kind) {
        return refuse(stream, "HTTP/1.1 400 Bad Request", error.to_string());
    }
    let listed = |key: &str| -> Vec<String> {
        stored
            .get(key)
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    vault.set_item_written_by(
        id,
        &kind,
        &payload,
        &listed("recipients"),
        &listed("tags"),
        consumer,
    )?;
    let revision = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .and_then(|item| item.get("revision"))
        .and_then(Value::as_u64);
    crate::runtime::audit::append(
        "http-item-field-write",
        &json!({
            "item": id,
            "field": field,
            "mode": "rotate",
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
            "mode": "rotate",
            "operation_id": operation_id,
            "revision": revision,
        }),
    )
}
