// Acquiring a managed item over the local API: the provider verified it,
// the caller holds the exact stage grant, no item exists yet, and the write
// is the one the active credential operation recorded.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::net::TcpStream;

use crate::access::grant;
use crate::core::{schema, vault::Vault};
use crate::credential::Operation;
use crate::net::http;

/// What an acquire write names.
pub(super) struct Acquisition<'r> {
    pub(super) requested: &'r str,
    pub(super) id: &'r str,
    pub(super) field: &'r str,
    pub(super) operation_id: &'r str,
    pub(super) consumer: &'r str,
    pub(super) bearer: &'r str,
    pub(super) parsed: &'r Value,
}

/// Write the acquired item and answer the revision it now has; `None` means
/// the refusal was already written to `stream`.
pub(super) fn acquire(
    stream: &mut TcpStream,
    vault: &mut Vault,
    acquisition: Acquisition<'_>,
) -> Result<Option<u64>> {
    let Acquisition {
        requested,
        id,
        field,
        operation_id,
        consumer,
        bearer,
        parsed,
    } = acquisition;
    let mut refuse = |status: &str, error: Value| -> Result<Option<u64>> {
        http::write_response(stream, status, &json!({ "error": error }))?;
        Ok(None)
    };
    if parsed.get("provider_verified").and_then(Value::as_bool) != Some(true) {
        return refuse(
            "HTTP/1.1 409 Conflict",
            json!("provider verification required before acquire"),
        );
    }
    // The route refused a request without a consumer or bearer by name.
    if !grant::token_allows_field_action(
            vault,
            consumer,
            bearer,
            crate::access::actions::Action::Stage.as_str(),
            requested,
            field,
        )?
    {
        return refuse(
            "HTTP/1.1 403 Forbidden",
            json!("consumer not authorized to acquire item field"),
        );
    }
    if vault.get_item(id).is_ok() {
        return refuse(
            "HTTP/1.1 409 Conflict",
            json!("managed item already exists; use stage"),
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
    schema::field(&payload, field).context("acquired payload does not contain authorized field")?;
    let request = match crate::credential::recorded_request(vault, id) {
        Ok(request) => request,
        Err(error) => return refuse("HTTP/1.1 409 Conflict", json!(format!("{error:#}"))),
    };
    // An acquisition starts from no item, so its operation records no
    // baseline; authorize_managed_write holds the write to that.
    let baseline = request
        .as_ref()
        .and_then(|request| request.get("baseline_revision"))
        .and_then(Value::as_u64);
    if let Err(error) = crate::credential::authorize_managed_write(
        vault,
        id,
        field,
        consumer,
        operation_id,
        |operation| operation == Operation::Acquire,
        baseline,
        parsed.get("capture_origin").and_then(Value::as_str),
    ) {
        return refuse("HTTP/1.1 409 Conflict", json!(format!("{error:#}")));
    }
    let mut tags = vec!["managed:weles".to_string()];
    if let Some(role) = request
        .as_ref()
        .and_then(|request| request.get("role"))
        .and_then(Value::as_str)
    {
        tags.push(format!("stado:role:{role}"));
    }
    vault.set_managed_item(
        id,
        kind,
        &payload,
        &[],
        &tags,
        crate::core::vault::ManagedWrite {
            controller: "weles",
            writer: consumer,
            operation_id: Some(operation_id),
        },
    )?;
    Ok(Some(vault.item_revision(id)?))
}
