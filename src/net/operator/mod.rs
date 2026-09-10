// Operator routes of the loopback API: the surface a local operator console —
// the desktop app — reads and drives instead of launching the backend as a
// subprocess for every question it asks.
//
// Trust model: the listener is loopback-only, and every route here carries
// exactly the authority that invoking the backend binary on this machine
// already carries, because the local keyring decides what opens either way.
// What this surface carries is every operation and value that the command
// line offers: the operator console and the local vault CLI cannot drift.
//
// Every handler delegates to the same dispatcher the matching command uses,
// so a console and an operator reading the same vault cannot drift. A request
// names its vault in the body's optional `vault` member; the request-scoped
// override in core applies it for exactly the thread answering here.

use anyhow::Result;
use serde_json::{json, Value};
use std::net::TcpStream;
use std::path::PathBuf;

use crate::core;
use crate::net::http;

const OK_LINE: &str = "HTTP/1.1 200 OK";
const BAD_LINE: &str = "HTTP/1.1 400 Bad Request";
const ROUTE_PREFIX: &str = "/v1/operator/";

/// The mutating operator routes, for the listener's write lock: a read stays
/// parallel, while a read-modify-write on the vault file never interleaves
/// with another writer. Credential calls are all here because a status read
/// can commit or roll back a staged revision.
pub(crate) fn is_mutation(path: &str) -> bool {
    matches!(
        path,
        "/v1/operator/vaults/create"
            | "/v1/operator/items/import"
            | "/v1/operator/items/trash"
            | "/v1/operator/items/reclaim"
            | "/v1/operator/items/restore"
            | "/v1/operator/items/purge"
            | "/v1/operator/items/share"
            | "/v1/operator/items/revoke"
            | "/v1/operator/recipients/add"
            | "/v1/operator/grants/issue"
            | "/v1/operator/grants/ensure"
            | "/v1/operator/grants/revoke"
            | "/v1/operator/donations/accept"
            | "/v1/operator/donations/reject"
            | "/v1/operator/credential"
            | "/v1/operator/emergency/grant"
            | "/v1/operator/emergency/cancel"
            | "/v1/operator/emergency/activate"
            | "/v1/operator/recovery/drill"
            | "/v1/operator/policy/set"
            | "/v1/operator/sync/init"
            | "/v1/operator/sync/push"
            | "/v1/operator/sync/pull"
            | "/v1/operator/route/declare"
    )
}

/// Route one operator request; `false` when the path is not an operator
/// route, so the listener falls through to its own table.
pub(crate) fn handle(stream: &mut TcpStream, method: &str, path: &str, body: &str) -> Result<bool> {
    if !path.starts_with(ROUTE_PREFIX) {
        return Ok(false);
    }
    if method != "POST" {
        http::write_response(
            stream,
            BAD_LINE,
            &json!({"error": "operator routes are POST with a JSON body"}),
        )?;
        return Ok(true);
    }
    let parsed = http::request_json(body);
    let vault = parsed
        .get("vault")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let result = core::with_vault_override(vault, || answer(path, &parsed));
    match result {
        Ok(value) => http::write_response(stream, OK_LINE, &value)?,
        Err(error) => http::write_response(
            stream,
            BAD_LINE,
            &json!({"error": http::bounded_detail(&error.to_string())}),
        )?,
    }
    Ok(true)
}

mod calls;
mod routes;

use routes::answer;
