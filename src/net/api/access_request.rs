// The cross-host access request path: another host's agent files into this
// vault's request register, and a person here decides
// (docs/design/access-requests.md).

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::TcpStream;

use crate::access::grant;
use crate::net::http;

/// `POST /v1/access-requests` — file one request into the register. Requires
/// an exact `request:<kind>` grant for the kind filed, the same pattern
/// `donate:<item>` follows; the grant lets a colleague's host ask, and
/// nothing more: it reads no value and issues no grant.
pub(crate) fn handle_access_request(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let Some(parsed) = http::request_json(stream, body)? else {
        return Ok(());
    };
    let Some(kind) = parsed
        .get("kind")
        .and_then(Value::as_str)
        .filter(|kind| crate::access::request::KINDS.contains(kind))
    else {
        let e = &json!({"error": format!(
            "kind required: one of {}",
            crate::access::request::KINDS.join(", ")
        )});
        return http::write_response(stream, "HTTP/1.1 400 Bad Request", e);
    };
    let (consumer, bearer) = match http::presented_identity(headers) {
        Ok(identity) => identity,
        Err(reason) => return http::unidentified(stream, &reason),
    };
    let vault = http::load()?;
    if !grant::token_allows_vault_action(&vault, &consumer, &bearer, "request", kind)? {
        return http::write_response(
            stream,
            "HTTP/1.1 403 Forbidden",
            &json!({"error": format!("request:{kind} grant required")}),
        );
    }
    match crate::access::request::file_from_http(&parsed, &consumer) {
        Ok(answer) => http::write_response(stream, "HTTP/1.1 200 OK", &answer),
        Err(error) => http::write_response(
            stream,
            "HTTP/1.1 400 Bad Request",
            &json!({"error": http::detail_text(&format!("{error:#}"))}),
        ),
    }
}
