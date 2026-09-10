// Reading a request off the socket within its declared bounds, and deciding
// whether the route it names mutates the vault.

use anyhow::Result;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;

use crate::credential::CREDENTIAL_OPERATIONS_PATH;
use crate::net::operator;

// `GET /v1/credential/operations/<item>` names one exact item and nothing else.
pub(super) fn credential_status_item<'a>(method: &str, path: &'a str) -> Option<&'a str> {
    if method != "GET" {
        return None;
    }
    path.strip_prefix(CREDENTIAL_OPERATIONS_PATH)?
        .strip_prefix('/')
        .filter(|item| !item.is_empty() && !item.contains('/') && !item.contains('?'))
}

pub(super) fn is_mutation(method: &str, path: &str) -> bool {
    // A credential status poll commits or rolls back a staged revision, so it
    // serializes with every other writer despite being a GET.
    if credential_status_item(method, path).is_some() {
        return true;
    }
    if operator::is_mutation(path) {
        return true;
    }
    matches!(
        (method, path),
        ("PUT", "/v1/items")
            | ("DELETE", "/v1/items")
            | ("POST", "/v1/acquisitions")
            | ("POST", "/v1/acquisitions/read")
            | ("POST", "/v1/donations")
            | ("POST", "/v1/enroll")
            | ("POST", CREDENTIAL_OPERATIONS_PATH)
    )
}

pub(super) fn read_line_bounded(
    reader: &mut BufReader<TcpStream>,
    maximum: usize,
) -> Result<Option<String>> {
    let mut line = String::new();
    let read = reader
        .take(u64::try_from(maximum.saturating_add(1))?)
        .read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if read > maximum || !line.ends_with('\n') {
        anyhow::bail!("request line exceeds {maximum} bytes");
    }
    Ok(Some(line))
}
