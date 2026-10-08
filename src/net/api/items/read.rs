// Reading one field of one item over the local API: an exact grant, then the
// value, and nothing else about the vault. `locate` is the part every
// single-field read shares (the grant, the role, the item's state); the
// revision route answers from it without decrypting anything.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;
use wisent_errors::Code;

use crate::access::grant;
use crate::core::schema;
use crate::core::vault::Vault;
use crate::net::http;

/// One single-field read the grant allows, resolved to the live item that
/// answers it.
pub(super) struct Located {
    pub(super) vault: Vault,
    /// The coordinate the caller asked for: an item id or `role:<role>`.
    pub(super) requested: String,
    /// The item that answers it now.
    pub(super) item: String,
    /// The item's identity, which a rename keeps and a purge and recreate
    /// does not; `None` for an item `skarbiec upgrade` has not stamped yet.
    pub(super) item_uid: Option<String>,
    /// The revision of the item's current value.
    pub(super) revision: u64,
    pub(super) field: String,
    pub(super) consumer: String,
}

/// Check the request's grant for `read` of its item field and find the item
/// that answers it. `None` means the refusal was already written.
pub(super) fn locate(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<Option<Located>> {
    let parsed = http::request_json(body);
    let Some(id) = http::request_id(&parsed) else {
        http::write_response(stream, "HTTP/1.1 400 Bad Request", &json!({"error": "id required"}))?;
        return Ok(None);
    };
    let Some(field) = http::request_field(&parsed) else {
        http::write_response(stream, "HTTP/1.1 400 Bad Request", &json!({"error": "field required"}))?;
        return Ok(None);
    };
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    if consumer.is_empty()
        || !grant::token_allows_field_action(&vault, &consumer, &bearer, "read", id, field)?
    {
        http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer not authorized to read item field"}),
        )?;
        return Ok(None);
    }
    // A grant may name a role (`read:role:<role>#<field>`): the request asks
    // for `role:<role>`, the grant matched that coordinate above, and the value
    // comes from the one live item playing the role now, so the caller never
    // names an item. A plain item id resolves to itself.
    let requested = id;
    let resolved = match crate::access::acquisition::role::item_for(&vault, requested) {
        Ok(item) => item,
        Err(error) => {
            let detail = if error
                .downcast_ref::<crate::access::acquisition::AcquisitionFieldMissing>()
                .is_some()
            {
                format!("no live item carries stado:{requested}")
            } else {
                error.to_string()
            };
            http::write_response(
                stream,
                "HTTP/1.1 404 Not Found",
                &json!({
                    "error": "the role has no single item",
                    "error_code": Code::NotFound.as_str(),
                    "detail": detail,
                }),
            )?;
            return Ok(None);
        }
    };
    let id = resolved.as_str();
    // An adopt candidate the provider has not confirmed is readable only by
    // the adopt verification path, never by an ordinary read grant.
    if field != "context"
        && matches!(
            crate::credential::managed_read(&vault, id, field, &consumer)?,
            crate::credential::ManagedRead::Refused
        )
    {
        http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({"error": "credential adoption is in flight; the staged candidate is not readable"}),
        )?;
        return Ok(None);
    }
    let stored = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .and_then(|items| items.get(id));
    let Some(stored) = stored else {
        http::write_response(stream, "HTTP/1.1 404 Not Found", &json!({"error": "item not found"}))?;
        return Ok(None);
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
        http::write_response(
            stream,
            "HTTP/1.1 410 Gone",
            &json!({
                "error": "item is in trash",
                "error_code": Code::NotFound.as_str(),
                "detail": format!("restore it first: skarbiec restore {id}"),
            }),
        )?;
        return Ok(None);
    }
    if stored.get("format").and_then(Value::as_u64) != Some(crate::core::vault::current_envelope())
    {
        http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({
                "error": "item uses the legacy envelope",
                "error_code": Code::Config.as_str(),
                "detail": format!("run `skarbiec upgrade --apply` before reading {id}"),
            }),
        )?;
        return Ok(None);
    }
    // The version of the value this read answers: the item's uid (a purged
    // and recreated id starts its revisions again under a new uid) and the
    // revision every new value raises. Both are cleartext envelope fields.
    let item_uid = crate::core::vault::entry_item_uid(stored).map(str::to_string);
    let revision = vault.item_revision(id)?;
    let item = id.to_string();
    let requested = requested.to_string();
    Ok(Some(Located { vault, requested, item, item_uid, revision, field: field.to_string(), consumer }))
}

pub(crate) fn handle_items_read(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let Some(Located { vault, requested, item, item_uid, revision, field, consumer }) =
        locate(stream, headers, body)?
    else {
        return Ok(());
    };
    let (id, field) = (item.as_str(), field.as_str());
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
                    "detail": http::detail_text(&detail),
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
        &json!({"item": id, "requested": requested, "field": field, "consumer": consumer}),
    )?;
    http::write_response(
        stream,
        "HTTP/1.1 200 OK",
        &json!({
            "id": requested,
            "item": id,
            "item_uid": item_uid,
            "revision": revision,
            "field": field,
            "value": value,
        }),
    )
}
