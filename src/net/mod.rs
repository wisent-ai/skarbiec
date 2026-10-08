// Network layer: git-backed multi-device sync of the encrypted vault, and a
// local HTTP API the separate client products integrate against. `net::http`
// keeps the listener and the route table; `net::api` holds the handlers those
// routes call, one module per family of requests.

pub mod api;
pub mod bond;
pub mod http;
pub mod mcp;
pub mod operator;
pub mod sync;

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

pub(crate) use api::donation::handle_donation;
pub(crate) use api::identity::{handle_owner_pubkey, handle_tokens_introspect};
pub(crate) use api::items::{handle_items_put, handle_items_read, handle_items_revision};
pub(crate) use api::lifecycle::{handle_credential_operation_status, handle_credential_operations};

// Shared request helpers, re-exported by net::http so handler call sites read
// the same in every module. A failure's detail reaches the caller whole: only
// the whitespace around it, which is never information, is dropped.
pub(crate) fn detail_text(detail: &str) -> String {
    detail.trim().to_owned()
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
