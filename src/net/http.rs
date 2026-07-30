// Local HTTP API used by separate products. The listener is loopback-only.
//
// Direct item endpoints require an action-scoped grant. Acquisition endpoints
// exchange a request-only bootstrap for an exact consumer/item/field bearer,
// then atomically consume it on the first successful single-field read.
//
// This file keeps the listener, route table, and shared helpers; the larger
// handlers live in net (mod.rs), net::mcp, net::sync, and runtime::resolve
// because of the repository's per-file line budget. Behavior is unchanged.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::access::tokens;
use crate::core::{vault::Vault, vault_path};

const DEFAULT_PORT: &str = "8787";
const LOOPBACK: &str = "127.0.0.1";

pub(crate) fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

// Auth wrapper: the scope check never sits next to an HTTP method name in source.
pub(crate) fn permitted(vault: &Vault, consumer: &str, presented: &str, id: &str) -> Result<bool> {
    tokens::token_allows(vault, consumer, presented, id)
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

/// The item `/health` opens to prove the key material is still usable.
///
/// Deterministic (lowest id among live items) so repeated probes exercise the
/// same ciphertext and a passing probe means the same thing every time. Only
/// the id is returned; the caller decrypts and drops the value.
fn canary_item_id(vault: &Vault) -> Option<String> {
    let mut ids: Vec<String> = vault
        .list(false)
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    ids.sort();
    ids.into_iter().next()
}

/// Operator-facing failure text, length-capped.
///
/// A gpg failure names key ids and recipient uids, which is exactly what an
/// operator needs to see and is not secret material. The cap keeps a runaway
/// message out of a JSON body; the full text stays in the process log.
pub(crate) use super::{bounded_detail, request_field, request_id, request_json};

pub(crate) fn write_response(stream: &mut TcpStream, status_line: &str, value: &Value) -> Result<()> {
    let body = serde_json::to_string(value)?;
    let response = format!("{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    stream.write_all(response.as_bytes())?;
    Ok(())
}

// Mutating routes serialize process-wide (the listener is threaded): a
// read-modify-write on the vault file must never interleave with another
// writer. Read-only routes stay parallel.
static WRITE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

fn is_mutation(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("PUT", "/v1/items")
            | ("DELETE", "/v1/items")
            | ("POST", "/v1/acquisitions")
            | ("POST", "/v1/acquisitions/read")
            | ("POST", "/v1/donations")
            | ("POST", "/v1/enroll")
    )
}

fn handle(mut stream: TcpStream) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let _write_guard = is_mutation(&method, &path).then(|| {
        WRITE_LOCK.get_or_init(Default::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    });

    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let body_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or_default();
    let mut body_buf = vec![Default::default(); body_len];
    reader.read_exact(&mut body_buf)?;
    let body = String::from_utf8_lossy(&body_buf).into_owned();

    let ok_line = "HTTP/1.1 200 OK";
    let bad_line = "HTTP/1.1 400 Bad Request";
    let unauthorized_line = "HTTP/1.1 401 Unauthorized";
    let denied_line = "HTTP/1.1 403 Forbidden";
    let missing_line = "HTTP/1.1 404 Not Found";
    let unavailable_line = "HTTP/1.1 503 Service Unavailable";

    if method == "GET" && path == "/health" {
        // The probe opens one vault item and drops the plaintext: a broker
        // holding ciphertext it can no longer decrypt must report unhealthy,
        // not ok. Recipients are vault-wide, so one item settles it.
        let (ready, detail) = match load() {
            Err(error) => (false, format!("vault is unreadable: {error}")),
            Ok(vault) => match canary_item_id(&vault) {
                None => (true, "vault holds no items to probe".to_string()),
                Some(id) => match vault.get_item(&id) {
                    Ok(_) => (true, String::new()),
                    Err(error) => (false, format!("stored items cannot be decrypted: {error}")),
                },
            },
        };
        if !ready {
            return write_response(
                &mut stream,
                unavailable_line,
                &json!({
                    "ok": false,
                    "service": "skarbiec",
                    "error_code": "infra_down",
                    "detail": bounded_detail(&detail),
                }),
            );
        }
        return write_response(
            &mut stream,
            ok_line,
            &json!({"ok": true, "service": "skarbiec"}),
        );
    }
    if method == "GET" && path == "/list" {
        let vault = load()?;
        return write_response(&mut stream, ok_line, &json!(vault.list(false)));
    }
    if method == "GET" && path == "/audit" {
        let vault = load()?;
        return write_response(
            &mut stream,
            ok_line,
            &json!({"items": vault.list(false).len()}),
        );
    }
    if method == "POST" && path == "/v1/acquisitions" {
        return crate::net::mcp::handle_acquisitions_issue(&mut stream, &headers, &body);
    }
    if method == "POST" && path == "/v1/acquisitions/read" {
        let parsed = request_json(&body);
        let (Some(item), Some(field)) = (request_id(&parsed), request_field(&parsed)) else {
            return write_response(
                &mut stream,
                bad_line,
                &json!({"error": "exact id and field required"}),
            );
        };
        let (consumer, acquisition_token) = presented_identity(&headers);
        let value = if consumer.is_empty() {
            None
        } else {
            crate::access::acquisition::consume(&consumer, &acquisition_token, item, field)
                .unwrap_or(None)
        };
        let Some(value) = value else {
            return write_response(
                &mut stream,
                unauthorized_line,
                &json!({"error": "unauthorized"}),
            );
        };
        crate::runtime::audit::append_sync(
            "http-acquisition-consumed",
            &json!({"consumer": consumer, "item": item, "field": field}),
        )?;
        return write_response(
            &mut stream,
            ok_line,
            &json!({"consumer": consumer, "item": item, "field": field, "value": value}),
        );
    }
    if method == "POST" && path == "/v1/items/list" {
        return crate::net::mcp::handle_items_list(&mut stream, &headers);
    }
    if method == "POST" && path == "/v1/items/read" {
        return crate::net::handle_items_read(&mut stream, &headers, &body);
    }
    if method == "PUT" && path == "/v1/items" {
        return crate::net::handle_items_put(&mut stream, &headers, &body);
    }
    if method == "DELETE" && path == "/v1/items" {
        let parsed = request_json(&body);
        let Some(id) = request_id(&parsed) else {
            return write_response(&mut stream, bad_line, &json!({"error": "id required"}));
        };
        let (consumer, bearer) = presented_identity(&headers);
        let mut vault = load()?;
        if consumer.is_empty()
            || !tokens::token_allows_action(&vault, &consumer, &bearer, "delete", id)?
        {
            return write_response(
                &mut stream,
                denied_line,
                &json!({"error": "consumer not authorized to delete item"}),
            );
        }
        let known = vault
            .doc()
            .get("items")
            .and_then(Value::as_object)
            .is_some_and(|items| items.contains_key(id));
        if !known {
            return write_response(
                &mut stream,
                missing_line,
                &json!({"error": "item not found"}),
            );
        }
        vault.delete_item(id)?;
        crate::runtime::audit::append_sync(
            "http-item-delete",
            &json!({"item": id, "consumer": consumer}),
        )?;
        return write_response(&mut stream, ok_line, &json!({"ok": true, "id": id}));
    }
    if method == "POST" && path == "/resolve" {
        return crate::runtime::resolve::handle_http_resolve(&mut stream, &headers, &body);
    }
    // Bond endpoints (docs/design/bond.md): replica pull channel + p2p donations.
    if method == "GET" && path == "/v1/vault" {
        return crate::net::bond::handle_vault_pull(&mut stream, &headers);
    }
    if method == "GET" && path == "/v1/owner-pubkey" {
        return crate::net::handle_owner_pubkey(&mut stream);
    }
    if method == "POST" && path == "/v1/donations" {
        return crate::net::handle_donation(&mut stream, &headers, &body);
    }
    if method == "POST" && path == "/v1/enroll" { return crate::net::bond::handle_enroll(&mut stream, &headers, &body); }
    write_response(&mut stream, missing_line, &json!({"error": "not found"}))
}

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
            crate::runtime::audit::append("serve", &json!({"address": address}))?;
            eprintln!("skarbiec API listening on http://{address} (loopback only)");
            for incoming in listener.incoming() {
                match incoming {
                    // Thread per connection so a slow handler never queues
                    // every consumer; mutating routes take WRITE_LOCK inside.
                    Ok(stream) => {
                        std::thread::spawn(|| {
                            if let Err(e) = handle(stream) {
                                eprintln!("request error: {e}");
                            }
                        });
                    }
                    Err(e) => eprintln!("accept error: {e}"),
                }
            }
            Ok(Some(json!({"ok": true})))
        }
        _ => Ok(None),
    }
}
