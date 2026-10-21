// Network layer: git-backed multi-device sync of the encrypted vault, and a
// local HTTP API the separate client products integrate against. `net::http`
// keeps the listener and the route table; `net::api` holds the handlers those
// routes call, one module per family of requests.

pub mod api;
pub mod bond;
pub mod http;
pub mod mcp;
pub mod operator;
pub mod owner;
pub(crate) mod serve;
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

/// The request body as JSON. A body that does not parse is answered 400
/// here, naming the parse error and the body's length; `None` tells the
/// handler that answer was written, so no handler reads a field out of a
/// body that was never JSON and reports the field as missing.
pub(crate) fn request_json(stream: &mut std::net::TcpStream, body: &str) -> Result<Option<Value>> {
    match serde_json::from_str(body) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(error) => {
            http::write_response(
                stream,
                "HTTP/1.1 400 Bad Request",
                &serde_json::json!({
                    "error": format!("the request body is not JSON ({} bytes): {error}", body.len())
                }),
            )?;
            Ok(None)
        }
    }
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
    if command == "maintain" {
        return maintain(flags, positionals).map(Some);
    }
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

/// `skarbiec maintain`: the pass `net::http` owns (GnuPG daemons, readiness
/// proof, one pull of every pulled bond), then one push of the Git mirror on
/// the host that publishes it (`mirror publish`). Both run; either failing
/// fails the pass with every reason, so a mirror that stopped publishing is a
/// failed scheduled run, not a silent one.
fn maintain(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let pass = http::dispatch("maintain", flags, positionals);
    let mirror = sync::push_if_published();
    match (pass, mirror) {
        (Ok(Some(mut report)), Ok(mirror)) => {
            report["mirror"] = serde_json::json!(mirror);
            Ok(report)
        }
        (Ok(None), _) => anyhow::bail!("skarbiec maintain: net::http answered nothing"),
        (pass, mirror) => {
            let mut reasons = Vec::new();
            if let Err(error) = pass {
                reasons.push(format!("{error:#}"));
            }
            if let Err(error) = mirror {
                reasons.push(format!("skarbiec maintain: mirror push: {error:#}"));
            }
            anyhow::bail!("{}", reasons.join("; "))
        }
    }
}
