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
use wisent_errors::trim_detail;

pub(crate) use api::donation::handle_donation;
pub(crate) use api::identity::{handle_owner_pubkey, handle_tokens_introspect};
pub(crate) use api::items::{handle_items_put, handle_items_read};
pub(crate) use api::lifecycle::{handle_credential_operation_status, handle_credential_operations};


// Shared request helpers, re-exported by net::http so handler call sites read
// the same in every module.
//
// The width is skarbiec's own decision; how to cut is not. `trim_detail` is the
// fleet's rule, from `wisent-errors`, so an operator reading a truncated gpg
// message here sees it cut exactly as every other product cuts one.
pub(crate) fn bounded_detail(detail: &str) -> String {
    let limit: usize = "400".parse().unwrap_or_default();
    trim_detail(detail, limit)
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
