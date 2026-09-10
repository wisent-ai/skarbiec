// What a managed write has to match before it is allowed: the request that
// asked for it, the staged revision it activates, and the context blocks a
// finished operation leaves behind.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::core::schema;
use crate::core::vault::{ManagedWrite, Vault};
use crate::core::inbox;

use super::super::wire::{request_payload, WIRE_VERSION};
use super::lifecycle::quarantine_active;
use super::records::{item_revision, live_item_exists, request_item_id};

// Canonical context blocks are written through the item's own management
// authority so the envelope keeps its provenance. A staged revision is never
// silently dropped: metadata waits until the staging is resolved.
pub(in crate::credential) fn store_context(vault: &mut Vault, id: &str, blocks: &[(&str, Value)]) -> Result<()> {
    let entry = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(id))
        .cloned()
        .with_context(|| format!("no item: {id}"))?;
    if entry.get("state").and_then(Value::as_str) != Some("active") {
        bail!("{id} is not active; refusing to write credential lifecycle metadata");
    }
    if entry.get("pending").is_some() {
        bail!(
            "{id} has a staged revision; resolve it before writing credential lifecycle metadata"
        );
    }
    let kind = entry
        .get("kind")
        .and_then(Value::as_str)
        .context("canonical item has no kind")?
        .to_string();
    let mut payload = vault.get_item(id)?;
    let context = payload
        .get_mut("context")
        .and_then(Value::as_object_mut)
        .context("canonical item has no mutable context object")?;
    for (key, value) in blocks {
        if value.is_null() {
            context.remove(*key);
        } else {
            context.insert((*key).to_string(), value.clone());
        }
    }
    let tags: Vec<String> = entry
        .get("tags")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let recipients = vault.item_recipient_uids(id);
    let management = entry.get("management").cloned().unwrap_or_default();
    if management.get("mode").and_then(Value::as_str) == Some("managed") {
        let controller = management
            .get("controller")
            .and_then(Value::as_str)
            .context("managed item has no controller")?;
        let writer = entry
            .get("current")
            .and_then(|current| current.get("written_by"))
            .and_then(Value::as_str)
            .context("managed item has no active writer")?;
        return vault.set_managed_item(
            id,
            &kind,
            &payload,
            &recipients,
            &tags,
            ManagedWrite {
                controller,
                writer,
                operation_id: None,
            },
        );
    }
    vault.set_item(id, &kind, &payload, &recipients, &tags)
}

pub(in crate::credential) fn item_matches_request(
    vault: &Vault,
    credential_id: &str,
    request_id: &str,
    operation: &str,
    account_email: Option<&str>,
) -> bool {
    vault.get_item(credential_id).is_ok_and(|payload| {
        schema::field(&payload, "context")
            .ok()
            .and_then(Value::as_object)
            .is_some_and(|context| {
                context.get("request_id").and_then(Value::as_str) == Some(request_id)
                    && context.get("operation").and_then(Value::as_str) == Some(operation)
                    && account_email.is_none_or(|email| {
                        context.get("account_ref").and_then(Value::as_str) == Some(email)
                            && schema::field(&payload, "username")
                                .ok()
                                .and_then(Value::as_str)
                                == Some(email)
                    })
            })
    })
}

pub(in crate::credential) fn pending_matches_request(
    vault: &Vault,
    credential_id: &str,
    request_id: &str,
    field: &str,
    writer: &str,
) -> bool {
    vault
        .doc()
        .get("items")
        .and_then(|items| items.get(credential_id))
        .and_then(|item| item.get("pending"))
        .and_then(Value::as_object)
        .is_some_and(|pending| {
            pending.get("operation_id").and_then(Value::as_str) == Some(request_id)
                && pending.get("field").and_then(Value::as_str) == Some(field)
                && pending.get("written_by").and_then(Value::as_str) == Some(writer)
        })
}

// One authorization decision over eight independent coordinates, none of which
// this function can derive from the others: who is writing, as which operation,
// against which field of which credential, at which revision, from which
// capture origin, and which operations the caller is allowed to perform at all.
// Grouping them into a struct would only move the same eight names one line up
// while adding a type whose sole purpose is to satisfy a counter, so the lint is
// answered here rather than obeyed. `-D warnings` in the release quality gate
// means an unanswered lint is not a style note: it stops the product shipping.
#[allow(clippy::too_many_arguments)]
pub(in crate) fn authorize_managed_write(
    vault: &Vault,
    credential_id: &str,
    field: &str,
    writer: &str,
    operation_id: &str,
    allowed_operations: &[&str],
    expected_revision: u64,
    capture_origin: Option<&str>,
) -> Result<()> {
    let request_item = request_item_id(credential_id);
    let request = vault
        .get_item(&request_item)
        .and_then(request_payload)
        .context("managed write has no active credential operation")?;
    let request_operation = request
        .get("operation")
        .and_then(Value::as_str)
        .context("credential operation has no operation")?;
    if !allowed_operations.contains(&request_operation)
        || request.get("version").and_then(Value::as_str) != Some(WIRE_VERSION)
        || request.get("request_id").and_then(Value::as_str) != Some(operation_id)
        || request.get("credential_id").and_then(Value::as_str) != Some(credential_id)
        || request.get("field").and_then(Value::as_str) != Some(field)
        || request.get("consumer").and_then(Value::as_str) != Some(writer)
        || request.get("baseline_revision").and_then(Value::as_u64) != Some(expected_revision)
        || !matches!(
            request.get("status").and_then(Value::as_str),
            Some("submitting" | "pending")
        )
    {
        bail!("managed write does not match the active credential operation");
    }
    // A generic provider's acquisition is bound to the exact origin the caller
    // declared: Weles echoes back the origin it actually captured at, so a
    // write from anywhere else -- or one that presents an origin for an
    // operation that declared none -- is not this operation's write.
    if request.get("signup_origin").and_then(Value::as_str) != capture_origin {
        bail!(
            "managed write capture origin is not the signup origin this credential operation declared"
        );
    }
    if quarantine_active(vault, credential_id) {
        bail!("{credential_id} is quarantined; refusing every managed write until it is resolved");
    }
    match request_operation {
        "acquire" => {
            if expected_revision != u64::MIN || live_item_exists(vault, credential_id) {
                bail!("credential acquisition requires an absent item at baseline revision zero");
            }
        }
        // adopt never authorizes a remote write: Skarbiec itself stages the
        // operator-supplied candidate and Weles only returns a verdict.
        "adopt" => {
            bail!("credential adopt stages locally and authorizes no Weles managed write");
        }
        // rotate, reset, and verify all stage against a live managed item;
        // remove trashes one. reset differs from rotate only in whether the
        // current provider password was known, never in local authority.
        "rotate" | "reset" | "verify" | "remove" => {
            if item_revision(vault, credential_id) != Some(expected_revision)
                || !inbox::managed_by_weles(vault, credential_id)
            {
                bail!("credential mutation baseline is no longer current and managed");
            }
        }
        other => bail!("credential operation {other} cannot authorize a managed write"),
    }
    Ok(())
}
