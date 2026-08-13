// Network layer: git-backed multi-device sync of the encrypted vault, and a
// local HTTP API the separate client products integrate against. Some serve
// endpoint handlers — item read/write and the p2p donation path (owner
// pubkey + donations) — live here rather than in net::http so every file
// stays within the repository's per-file line budget; net::http keeps the
// listener, the route table, and the shared helpers they call. Routing and
// behavior are unchanged by the split.

pub mod bond;
pub mod http;
pub mod mcp;
pub mod sync;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::tokens;
use crate::core::{crypto, inbox, schema};

// Shared request helpers, re-exported by net::http so handler call sites read
// the same in every module. Moved here to keep net::http under its line
// budget after the listener went thread-per-connection.
pub(crate) fn bounded_detail(detail: &str) -> String {
    let limit: usize = "400".parse().unwrap_or_default();
    detail.chars().take(limit).collect()
}

pub(crate) fn request_json(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::Null)
}

pub(crate) fn request_id(body: &Value) -> Option<&str> {
    body.get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

pub(crate) fn request_field(body: &Value) -> Option<&str> {
    body.get("field")
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
}

/// Answer what an inbound bearer is, for a gateway that has to decide whether
/// to serve the request holding it.
///
/// The caller proves its own identity and must carry `introspect` on `tokens`;
/// asking about someone else's credential is a capability, not a side effect of
/// being able to reach this port. The subject bearer travels in the body and is
/// never logged, and an unknown bearer answers exactly like an expired one.
pub(crate) fn handle_tokens_introspect(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let Some(subject) = parsed.get("token").and_then(Value::as_str) else {
        return http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": "token required"}),
        );
    };
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    if consumer.is_empty()
        || !tokens::token_allows_action(&vault, &consumer, &bearer, "introspect", "tokens")?
    {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": "consumer not authorized to introspect tokens"}),
        );
    }
    let answer = tokens::introspect(&vault, subject)?;
    crate::runtime::audit::append(
        "http-token-introspected",
        &json!({
            "consumer": consumer,
            "subject": answer.get("consumer").cloned().unwrap_or(Value::Null),
            "active": answer.get("active").cloned().unwrap_or(Value::Null),
        }),
    )?;
    http::write_response(stream, "HTTP/1.1 200 OK", &answer)
}

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
        || !tokens::token_allows_field_action(&vault, &consumer, &bearer, "read", id, field)?
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
    // that already classifies as `not_found` for that client -- warning,
    // never retryable -- and, unlike `404`, it is not silently read as an
    // absent optional value.
    if stored.get("state").and_then(Value::as_str) == Some("trashed") {
        return http::write_response(
            stream,
            "HTTP/1.1 410 Gone",
            &json!({
                "error": "item is in trash",
                "error_code": "not_found",
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
                "error_code": "config",
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
                    "error_code": "infra_down",
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
    if crate::credential::lifecycle_owned_item(id) {
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
                || !tokens::token_allows_field_action(
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
                || !tokens::token_allows_field_action(
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
        || !tokens::token_allows_vault_action(&vault, &consumer, &bearer, "donate", item_id)?
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

// === credential lifecycle serve endpoints ===
//
// The canonical Skarbiec is the only remote hop of a credential lifecycle, so
// submit, resume, and status all arrive here. They accept exactly one
// capability action, `lifecycle`, which authorizes no read of a credential
// value: these handlers never call a read path.

/// One exact `lifecycle` capability on one exact item.
fn lifecycle_authorized(headers: &HashMap<String, String>, item: &str) -> Result<bool> {
    let (consumer, bearer) = http::presented_identity(headers);
    if consumer.is_empty() {
        return Ok(false);
    }
    let vault = http::load()?;
    tokens::token_allows_action(&vault, &consumer, &bearer, "lifecycle", item)
}

/// `POST /v1/credential/operations` — submit or resume one credential
/// operation. The body carries no directory identity: that is a sealed item
/// contract Skarbiec reads for itself.
pub(crate) fn handle_credential_operations(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let item = match crate::credential::endpoint_item(&parsed) {
        Ok(item) => item,
        Err(error) => {
            return http::write_response(
                stream,
                "HTTP/1.1 400 Bad Request",
                &json!({"error": bounded_detail(&error.to_string())}),
            );
        }
    };
    if !lifecycle_authorized(headers, &item)? {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("lifecycle:{item} grant required")}),
        );
    }
    let (consumer, _) = http::presented_identity(headers);
    match crate::credential::submit_from_endpoint(&crate::core::vault_path(), &parsed) {
        Ok(value) => {
            crate::runtime::audit::append(
                "http-credential-operation",
                &json!({
                    "item": item,
                    "consumer": consumer,
                    "status": value.get("status"),
                    "operation": value.get("operation"),
                }),
            )?;
            http::write_response(stream, "HTTP/1.1 200 OK", &value)
        }
        Err(error) => http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({"ok": false, "error": bounded_detail(&error.to_string())}),
        ),
    }
}

/// `GET /v1/credential/operations/<item>` — the persisted state of that item's
/// credential operation, with its receipt and quarantine block.
pub(crate) fn handle_credential_operation_status(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    item: &str,
) -> Result<()> {
    let item = match crate::credential::exact_credential_item(item) {
        Ok(item) => item,
        Err(error) => {
            return http::write_response(
                stream,
                "HTTP/1.1 400 Bad Request",
                &json!({"error": bounded_detail(&error.to_string())}),
            );
        }
    };
    if !lifecycle_authorized(headers, &item)? {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("lifecycle:{item} grant required")}),
        );
    }
    match crate::credential::status_from_endpoint(&crate::core::vault_path(), &item) {
        Ok(value) => http::write_response(stream, "HTTP/1.1 200 OK", &value),
        Err(error) => http::write_response(
            stream,
            "HTTP/1.1 409 Conflict",
            &json!({"ok": false, "error": bounded_detail(&error.to_string())}),
        ),
    }
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if let Some(v) = bond::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = sync::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    if let Some(v) = http::dispatch(command, flags, positionals)? {
        return Ok(Some(v));
    }
    Ok(None)
}
