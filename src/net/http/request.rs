// Reading a request off the socket, and deciding whether the route it names
// mutates the vault.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;

use crate::credential::CREDENTIAL_OPERATIONS_PATH;

// `GET /v1/credential/operations/<item>` names one exact item and nothing else.
pub(super) fn credential_status_item<'a>(method: &str, path: &'a str) -> Option<&'a str> {
    if method != "GET" {
        return None;
    }
    path.strip_prefix(CREDENTIAL_OPERATIONS_PATH)?
        .strip_prefix('/')
        .filter(|item| !item.is_empty() && !item.contains('/') && !item.contains('?'))
}

/// The non-operator routes that mutate the vault, for the listener's write
/// lock. Operator routes take the lock themselves, and only for work served
/// from this host's vault (`operator::handle`), since one may be forwarded
/// to the vault owner instead.
pub(super) fn is_mutation(method: &str, path: &str) -> bool {
    // A credential status poll commits or rolls back a staged revision, so it
    // serializes with every other writer despite being a GET.
    if credential_status_item(method, path).is_some() {
        return true;
    }
    matches!(
        (method, path),
        ("PUT", "/v1/items")
            | ("DELETE", "/v1/items")
            | ("POST", "/v1/acquisitions")
            | ("POST", "/v1/acquisitions/read")
            | ("POST", "/v1/donations")
            | ("POST", "/v1/offers")
            | ("POST", "/v1/access-requests")
            | ("POST", "/v1/enroll")
            | ("POST", CREDENTIAL_OPERATIONS_PATH)
    )
}

/// One CRLF- or LF-terminated line, or `None` at the end of the stream. A line
/// the stream cuts before its end is refused as a request that ended early.
pub(super) fn read_line(reader: &mut BufReader<TcpStream>) -> Result<Option<String>> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.is_empty() {
        return Ok(None);
    }
    if !line.ends_with('\n') {
        anyhow::bail!("request ended in the middle of a line");
    }
    Ok(Some(line))
}

/// The request's body: the `content-length` bytes after the headers, or none
/// without that header. `Ok(Err(reason))` is a body to refuse: bytes that are
/// not UTF-8 are not replaced, so no value is ever stored other than as sent.
pub(super) fn read_body(
    reader: &mut BufReader<TcpStream>,
    headers: &HashMap<String, String>,
) -> Result<std::result::Result<String, String>> {
    let Some(value) = headers.get("content-length") else {
        return Ok(Ok(String::new()));
    };
    let length = value.parse::<usize>().context("invalid content-length")?;
    let mut body = vec![Default::default(); length];
    reader.read_exact(&mut body)?;
    Ok(String::from_utf8(body)
        .map_err(|error| format!("the request body is not UTF-8: {}", error.utf8_error())))
}

/// Why a request must be refused as one a web page sent, or `None` when it is
/// not one. Skarbiec's callers are local programs (the CLI, the desktop app,
/// Stado, Brama, Weles); none is a browser. A browser lets any site it shows
/// send a cross-origin POST to the loopback port, and a DNS-rebinding site can
/// read the answer, so:
/// - the `Host` must name a loopback host (a loopback IP address or
///   `localhost`): a rebinding page's Host names the attacker's domain;
/// - a request may not carry `Origin`, nor `Sec-Fetch-Site` other than
///   `none`: only browsers send them, for a request a page made;
/// - an operator POST must declare `Content-Type: application/json`: a page
///   can send a cross-site POST without a preflight only as a "simple"
///   request, whose type is never JSON
///   (https://fetch.spec.whatwg.org/#cors-safelisted-request-header).
pub(super) fn browser_refusal(
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
) -> Option<String> {
    let Some(host) = headers.get("host") else {
        return Some(
            "the request names no Host; Skarbiec answers only its loopback address".to_string(),
        );
    };
    let name = match host.strip_prefix('[') {
        Some(bracketed) => bracketed.split_once(']').map(|(address, _)| address),
        None => host
            .rsplit_once(':')
            .map(|(name, _)| name)
            .or(Some(host.as_str())),
    };
    let loopback = match name {
        Some("localhost") => true,
        Some(address) => address
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    };
    if !loopback {
        return Some(format!(
            "Host {host:?} is not a loopback address; Skarbiec answers only its loopback listener"
        ));
    }
    if let Some(origin) = headers.get("origin") {
        return Some(format!("a request from the web page {origin:?} is refused: Skarbiec serves local programs, not browsers"));
    }
    if let Some(site) = headers
        .get("sec-fetch-site")
        .filter(|site| site.as_str() != "none")
    {
        return Some(format!("a browser request (Sec-Fetch-Site {site:?}) is refused: Skarbiec serves local programs, not browsers"));
    }
    let media_type = headers
        .get("content-type")
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase());
    if method == "POST"
        && path.starts_with("/v1/operator/")
        && media_type.as_deref() != Some("application/json")
    {
        return Some(format!(
            "an operator POST must declare Content-Type: application/json (it declared {:?}); a web page can send any other type across sites",
            headers.get("content-type")
        ));
    }
    None
}
