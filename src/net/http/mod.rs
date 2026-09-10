// Local HTTP API used by separate products. The listener is loopback-only.
//
// Direct item endpoints require an action capability. Acquisition endpoints
// exchange a request-only bootstrap for an exact consumer/item/field bearer,
// then atomically consume it on the first successful single-field read.
//
// This module keeps the listener, the shared helpers and the constants; the
// route table, the request reader, the readiness probe and the worker pool
// live in the modules beside it.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};

use crate::core::{vault::Vault, vault_path};

mod pool;
mod readiness;
mod request;
mod routes;

use pool::RequestPool;
use readiness::start_readiness_monitor;

const DEFAULT_PORT: &str = "8787";
const LOOPBACK: &str = "127.0.0.1";
const DEFAULT_HTTP_WORKERS: usize = 16;
const DEFAULT_HTTP_QUEUE: usize = 32;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

pub(super) fn configured_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

pub(crate) fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

pub(crate) fn presented_identity(headers: &HashMap<String, String>) -> (String, String) {
    let consumer = headers.get("x-consumer").cloned().unwrap_or_default();
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string)
        .unwrap_or_default();
    (consumer, bearer)
}

/// Operator-facing failure text, length-capped.
///
/// A gpg failure names key ids and recipient uids, which is exactly what an
/// operator needs to see and is not secret material. The cap keeps a runaway
/// message out of a JSON body; the full text stays in the process log.
pub(crate) use super::{bounded_detail, request_field, request_id, request_json};

pub(crate) fn write_response(
    stream: &mut TcpStream,
    status_line: &str,
    value: &Value,
) -> Result<()> {
    let body = serde_json::to_string(value)?;
    let response = format!("{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    stream.write_all(response.as_bytes())?;
    Ok(())
}

// Mutating routes serialize process-wide (the listener is threaded): a
// read-modify-write on the vault file must never interleave with another
// writer. Read-only routes stay parallel.
static WRITE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "serve" => {
            let port = flags
                .get("port")
                .map(String::as_str)
                .unwrap_or(DEFAULT_PORT);
            let address = format!("{LOOPBACK}:{port}");
            let listener =
                TcpListener::bind(&address).with_context(|| format!("bind {address}"))?;
            let requests = RequestPool::new()?;
            crate::runtime::audit::append("serve", &json!({"address": address}))?;
            start_readiness_monitor()?;
            eprintln!("skarbiec API listening on http://{address} (loopback only)");
            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        let deadline =
                            std::time::Duration::from_secs("30".parse().unwrap_or_default());
                        if let Err(e) = stream
                            .set_read_timeout(Some(deadline))
                            .and_then(|()| stream.set_write_timeout(Some(deadline)))
                        {
                            eprintln!("request error: socket deadline: {e}");
                            continue;
                        }
                        requests.submit(stream);
                    }
                    Err(e) => eprintln!("accept error: {e}"),
                }
            }
            Ok(Some(json!({"ok": true})))
        }
        _ => Ok(None),
    }
}
