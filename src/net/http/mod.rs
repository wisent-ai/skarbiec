// Local HTTP API used by separate products. The listener is loopback-only.
//
// Direct item endpoints require an action capability. Acquisition endpoints
// exchange a request-only bootstrap for an exact consumer/item/field bearer,
// then atomically consume it on the first successful single-field read.
//
// This module keeps the listener, the shared helpers and the constants; the
// route table, the request reader, the readiness probe and the request
// workers live in the modules beside it.

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
mod service;

pub(crate) use service::survive_accept;

use pool::RequestPool;
use readiness::maintenance_pass;

const LOOPBACK: &str = "127.0.0.1";

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
pub(crate) use super::{detail_text, request_field, request_id, request_json};

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
            // A host whose workloads only redeem capabilities - a hardened
            // capability deployment that allows no TCP at all - runs the same
            // one process with its capability socket and bonds and no HTTP API.
            let http = if flags.contains_key("no-http") {
                anyhow::ensure!(
                    !flags.contains_key("port"),
                    "serve --no-http binds no port; drop --port"
                );
                crate::runtime::audit::append("serve", &json!({"address": null}))?;
                None
            } else {
                // The port is the unit's declaration; Skarbiec has none of its own.
                let port = flags.get("port").map(String::as_str).ok_or_else(|| {
                    crate::cli::args::Usage(
                        "serve requires --port <port> (the unit declares it), or --no-http"
                            .to_string(),
                    )
                })?;
                // Started as its declared unit, the one process first retires
                // the Skarbiec units it replaces, then answers on their ports.
                let inherited = service::take_over_predecessors();
                let address = format!("{LOOPBACK}:{port}");
                let listener =
                    TcpListener::bind(&address).with_context(|| format!("bind {address}"))?;
                let mut listeners = vec![listener];
                for extra in inherited
                    .into_iter()
                    .filter(|extra| extra.to_string() != port)
                {
                    let taken = format!("{LOOPBACK}:{extra}");
                    match TcpListener::bind(&taken) {
                        Ok(listener) => {
                            eprintln!("skarbiec API also listening on http://{taken}, a retired unit's port");
                            listeners.push(listener);
                        }
                        Err(error) => eprintln!(
                            "skarbiec serve: {taken}, a retired unit's port, is held by another process: {error}"
                        ),
                    }
                }
                let requests = RequestPool::new()?;
                crate::runtime::audit::append("serve", &json!({"address": address}))?;
                eprintln!("skarbiec API listening on http://{address} (loopback only)");
                Some((listeners, requests))
            };
            service::serve(http, flags).map(Some)
        }
        // One pass of the work `serve` no longer loops on: the GnuPG daemon
        // ceiling, the readiness proof, and one pull of every pulled bond.
        // A Stado schedule pinned to the host runs it (`stado schedule create
        // --pinned-host HOST --cron '* * * * *' 'skarbiec maintain'`). Every
        // step runs; any failure makes the pass fail with every reason.
        "maintain" => {
            let mut failures: Vec<String> = Vec::new();
            let canaries = match maintenance_pass() {
                Ok(canaries) => canaries,
                Err(error) => {
                    failures.push(format!("readiness: {error:#}"));
                    Vec::new()
                }
            };
            let bonds = crate::bonds::pulled_bonds()?;
            for bond in &bonds {
                if let Err(error) = crate::bonds::pull_once(bond) {
                    failures.push(format!("{error:#}"));
                }
            }
            anyhow::ensure!(
                failures.is_empty(),
                "skarbiec maintain: {}",
                failures.join("; ")
            );
            Ok(Some(
                json!({"ok": true, "canaries": canaries, "pulled": bonds}),
            ))
        }
        _ => Ok(None),
    }
}
