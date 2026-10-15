// The client side of a serve channel: one blocking HTTP request to another
// Skarbiec's loopback listener, used by pull, enroll, donate, bond status and
// the forwarding to a vault owner.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;

/// Minimal blocking HTTP client for a loopback serve: returns the status line
/// and the parsed JSON body. A non-JSON body is an error naming the status,
/// so a refused request surfaces the server's answer. Only plain http to an
/// explicit host:port — the serve listener is loopback-only by design. The
/// exchange runs through the shared wait, so stderr says which request waits
/// on which serve and how it ended.
pub(crate) fn serve_request(
    base: &str,
    method: &str,
    path: &str,
    consumer: &str,
    bearer: &str,
    body: Option<&Value>,
) -> Result<(String, Value)> {
    // The base is written with or without its http:// scheme.
    let authority = match base.strip_prefix("http://") {
        Some(rest) => rest,
        None => base,
    };
    let authority = authority.trim_end_matches('/');
    if authority.is_empty() || authority.contains('/') {
        bail!("base url must be http://host:port with no path: {base}");
    }
    let payload = match body {
        Some(value) => serde_json::to_string(value)?,
        None => String::new(),
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {bearer}\r\nX-Consumer: {consumer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let raw = stado_wait::blocking(
        stado_wait::Kind::Network,
        format!("Skarbiec serve {method} {path}"),
        authority,
        || -> std::io::Result<String> {
            let mut stream = TcpStream::connect(authority)?;
            stream.write_all(request.as_bytes())?;
            let mut raw = String::new();
            stream.read_to_string(&mut raw)?;
            Ok(raw)
        },
    )
    .with_context(|| format!("{method} {path} at the serve {authority}"))?;
    let (head, text) = raw
        .split_once("\r\n\r\n")
        .with_context(|| format!("malformed HTTP response to {method} {path} from {authority}"))?;
    let status = head
        .lines()
        .next()
        .with_context(|| {
            format!("{method} {path} response from {authority} has no HTTP status line")
        })?
        .to_string();
    let parsed: Value = serde_json::from_str(text).with_context(|| {
        format!("response to {method} {path} from {authority} is not JSON (status: {status})")
    })?;
    Ok((status, parsed))
}
