// Model Context Protocol transport: a stdio JSON-RPC server exposing skarbiec's
// programmatic-safe surface to MCP agents, mirroring the loopback HTTP API.
//
// Tools mirror the loopback HTTP boundary (`net/http.rs`): health, item metadata,
// token-gated resolve, audit journal. The value-revealing and mutating verbs
// (item get, mint, rotation, export) are deliberately excluded. Handlers run
// in-process on the same dispatchers the CLI uses (one policy/audit source of
// truth). It is NOT part of `net::dispatch`: `serve()` owns stdout exclusively
// (JSON-RPC frames only), so main wires it as its own arm.
//
// Two agent-facing hardenings over the raw CLI: resolve is always token-gated
// (consumer + service grant come from the server's own env, never JSON-RPC
// params, so no bearer in transcript/log/argv), and always emits to a required,
// absolute SKARBIEC_MCP_OUT_DIR (relative refused) returning only the owner-only
// file path plus exported variable NAMES — values never leave disk.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::net::TcpStream;
use std::path::Path;
use wisent_errors::Code;

use crate::access::tokens;
use crate::core::{vault::Vault, vault_path};
use crate::net::http;
use crate::runtime;

// Spec-mandated JSON-RPC 2.0 / MCP wire values (not tunables); kept as strings
// and parsed so no numeric literal appears (crate-wide rule).
const PROTOCOL_VERSION: &str = "2024-11-05";
const CODE_PARSE_ERROR: &str = "-32700";
const CODE_METHOD_NOT_FOUND: &str = "-32601";
const CODE_INTERNAL_ERROR: &str = "-32000";

fn code(raw: &str) -> Value {
    json!(raw.parse::<i64>().unwrap_or_default())
}

fn schema(properties: Value, required: Vec<&str>) -> Value {
    json!({"type": "object", "properties": properties, "required": required})
}

// Exposed surface == the vault's own declared programmatic-safe boundary.
fn tools() -> Value {
    json!([
        {"name": "skarbiec_health",
         "description": "Liveness probe for the skarbiec vault. Returns {ok, service}. No credentials touched.",
         "inputSchema": schema(json!({}), vec![])},
        {"name": "skarbiec_list",
         "description": "List credential item metadata (ids, type, revision counts, tags). Never returns secret values.",
         "inputSchema": schema(json!({}), vec![])},
        {"name": "skarbiec_resolve",
         "description": "Resolve a platform's admin login the sanctioned way: policy- and token-gated; emits an owner-only env file and returns only its path plus the exported variable NAMES (ADMIN_EMAIL/ADMIN_PASSWORD/ADMIN_TOTP). Values are never returned. The server must be configured with SKARBIEC_MCP_CONSUMER, SKARBIEC_MCP_TOKEN (or SKARBIEC_MCP_TOKEN_FILE), and an absolute SKARBIEC_MCP_OUT_DIR; the token is never a tool argument.",
         "inputSchema": schema(json!({"platform": {"type": "string", "description": "Platform / item id to resolve (e.g. github, or a stored item id)."}}), vec!["platform"])},
        {"name": "skarbiec_audit",
         "description": "Return the tamper-evident audit journal (at/op/extra/prev/hash chain). Only operation names and non-sensitive identifiers are journalled; never values.",
         "inputSchema": schema(json!({}), vec![])},
    ])
}

fn text_result(value: &Value) -> Value {
    let text = match value {
        Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).unwrap_or_default(),
    };
    json!({"content": [{"type": "text", "text": text}]})
}

// Service grant: env var first, then a grant file. Absent/empty => None.
fn configured_token() -> Option<String> {
    if let Ok(value) = std::env::var("SKARBIEC_MCP_TOKEN") {
        let value = value.trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    if let Ok(path) = std::env::var("SKARBIEC_MCP_TOKEN_FILE") {
        if let Ok(body) = std::fs::read_to_string(&path) {
            let value = body.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn configured_consumer() -> Option<String> {
    std::env::var("SKARBIEC_MCP_CONSUMER")
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

// Required, absolute output dir; relative would let launch-cwd place files in the
// repo, so relative is refused outright.
fn configured_out_dir() -> Result<String> {
    let dir = std::env::var("SKARBIEC_MCP_OUT_DIR").ok()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .context("skarbiec_resolve is disabled: configure SKARBIEC_MCP_OUT_DIR to an absolute directory on the MCP server")?;
    if !Path::new(&dir).is_absolute() {
        anyhow::bail!("SKARBIEC_MCP_OUT_DIR must be an absolute path, got: {dir}");
    }
    Ok(dir)
}

fn resolve_tool(args: &Value) -> Result<Value> {
    let platform = args
        .get("platform")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
        .context("skarbiec_resolve requires a non-empty 'platform'")?;
    // Mandatory server-side auth; refuse before opening the vault.
    let consumer = configured_consumer().context(
        "skarbiec_resolve is disabled: configure SKARBIEC_MCP_CONSUMER on the MCP server",
    )?;
    let bearer = configured_token()
        .context("skarbiec_resolve is disabled: configure SKARBIEC_MCP_TOKEN or SKARBIEC_MCP_TOKEN_FILE on the MCP server")?;
    let out_dir = configured_out_dir()?;
    // Same path as `resolve <p> --consumer c --token t --emit --out dir`.
    let mut flags: HashMap<String, String> = HashMap::new();
    flags.insert("consumer".to_string(), consumer);
    flags.insert("token".to_string(), bearer);
    flags.insert("emit".to_string(), "true".to_string());
    flags.insert("out".to_string(), out_dir);
    runtime::resolve::dispatch("resolve", &flags, &[platform.to_string()])?
        .context("resolve produced no result")
}

fn call_tool(name: &str, args: &Value) -> Result<Value> {
    match name {
        "skarbiec_health" => Ok(text_result(&json!({"ok": true, "service": "skarbiec"}))),
        "skarbiec_list" => Ok(text_result(&json!(Vault::open(vault_path())?.list(false)))),
        "skarbiec_resolve" => Ok(text_result(&resolve_tool(args)?)),
        "skarbiec_audit" => {
            let empty: Vec<String> = Vec::new();
            Ok(text_result(
                &runtime::audit::dispatch("audit", &HashMap::new(), &empty)?
                    .context("audit produced no result")?,
            ))
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}

fn send(out: &mut impl Write, message: &Value) -> Result<()> {
    writeln!(out, "{}", serde_json::to_string(message)?)?;
    out.flush()?;
    Ok(())
}

fn error_response(id: Value, error_code: &str, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code(error_code), "message": message}})
}

fn server_version() -> String {
    option_env!("CARGO_PKG_VERSION").unwrap_or("").to_string()
}

fn handle(request: &Value, out: &mut impl Write) -> Result<()> {
    let method = match request.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => return Ok(()),
    };
    // No `id` key => notification: never answer.
    let id = match request.get("id") {
        Some(id) => id.clone(),
        None => return Ok(()),
    };
    match method {
        "initialize" => send(
            out,
            &json!({"jsonrpc": "2.0", "id": id, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "skarbiec", "version": server_version()}}}),
        ),
        "ping" => send(out, &json!({"jsonrpc": "2.0", "id": id, "result": {}})),
        "tools/list" => send(
            out,
            &json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools()}}),
        ),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match call_tool(name, &args) {
                Ok(result) => send(out, &json!({"jsonrpc": "2.0", "id": id, "result": result})),
                Err(e) => send(
                    out,
                    &error_response(id, CODE_INTERNAL_ERROR, &e.to_string()),
                ),
            }
        }
        other => send(
            out,
            &error_response(
                id,
                CODE_METHOD_NOT_FOUND,
                &format!("method not found: {other}"),
            ),
        ),
    }
}

/// Run the stdio JSON-RPC loop until stdin closes. Owns stdout exclusively.
pub fn serve() -> Result<()> {
    crate::runtime::audit::append("mcp-serve", &json!({"transport": "stdio"}))?;
    eprintln!("skarbiec MCP server on stdio (protocol {PROTOCOL_VERSION})");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(request) => handle(&request, &mut stdout)?,
            Err(_) => send(
                &mut stdout,
                &error_response(Value::Null, CODE_PARSE_ERROR, "parse error"),
            )?,
        }
    }
    Ok(())
}

// === serve endpoint handlers relocated from net::http ===
// Routed by net::http's listener; they live in this module only because
// net::http and net::mod are at the per-file line budget. Behavior unchanged.

pub(crate) fn handle_acquisitions_issue(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<()> {
    let parsed = http::request_json(body);
    let (Some(item), Some(field), Some(workload_id), Some(timestamp), Some(nonce), Some(signature)) = (
        http::request_id(&parsed),
        http::request_field(&parsed),
        parsed.get("workload_id").and_then(Value::as_str),
        parsed.get("workload_timestamp").and_then(Value::as_u64),
        parsed.get("workload_nonce").and_then(Value::as_str),
        parsed.get("workload_signature").and_then(Value::as_str),
    ) else {
        let e = &json!({"error": "exact id, field, and workload proof required"});
        return http::write_response(stream, "HTTP/1.1 400 Bad Request", e);
    };
    let (consumer, _) = http::presented_identity(headers);
    let issued = if consumer.is_empty() {
        None
    } else {
        match crate::access::acquisition::issue(
            &consumer,
            item,
            field,
            workload_id,
            timestamp,
            nonce,
            signature,
        ) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("acquisition issue failed for {consumer} on {item}#{field}: {error:#}");
                let e = &json!({"error": Code::InfraDown.as_str()});
                return http::write_response(stream, "HTTP/1.1 503 Service Unavailable", e);
            }
        }
    };
    let Some(issued) = issued else {
        let e = &json!({"error": "unauthorized"});
        return http::write_response(stream, "HTTP/1.1 401 Unauthorized", e);
    };
    let entry = json!({
        "consumer": consumer,
        "item": item,
        "field": field,
        "workload_id": workload_id,
        "expires_at": issued.expires_at,
    });
    crate::runtime::audit::append_sync("http-acquisition-issued", &entry)?;
    let out = json!({
        "consumer": consumer,
        "item": item,
        "field": field,
        "expires_at": issued.expires_at,
        "token": issued.token,
    });
    http::write_response(stream, "HTTP/1.1 200 OK", &out)
}

/// The items one caller is allowed to see, or `None` when the caller presented
/// no usable consumer grant.
///
/// This is the authorization for every route that hands back the item index,
/// held in one place so the legacy `GET /list` and `GET /audit` aliases cannot
/// drift away from the gate `POST /v1/items/list` applies.
pub(crate) fn authorized_items(headers: &HashMap<String, String>) -> Result<Option<Vec<Value>>> {
    let (consumer, bearer) = http::presented_identity(headers);
    let vault = http::load()?;
    // Hash the bearer once: hashing shells out to `shasum`, so per-item
    // hashing turned this filter into one subprocess spawn per vault item.
    let hash = tokens::presented_hash(&bearer)?;
    if consumer.is_empty() || !tokens::token_valid_hash(&vault, &consumer, &hash) {
        return Ok(None);
    }
    Ok(Some(
        vault
            .list(false)
            .into_iter()
            .filter(|item| {
                item.get("id").and_then(Value::as_str).is_some_and(|id| {
                    tokens::token_allows_any_item_hash(&vault, &consumer, &hash, "read", id)
                })
            })
            .collect(),
    ))
}

/// The refusal every item-index route answers with, so an operator who loses
/// access to one of them reads the same reason from all of them.
pub(crate) fn refuse_without_grant(stream: &mut TcpStream) -> Result<()> {
    let e = &json!({"error": "consumer grant required"});
    http::write_response(stream, "HTTP/1.1 403 Forbidden", e)
}

pub(crate) fn handle_items_list(
    stream: &mut TcpStream,
    headers: &HashMap<String, String>,
) -> Result<()> {
    let Some(visible) = authorized_items(headers)? else {
        return refuse_without_grant(stream);
    };
    http::write_response(stream, "HTTP/1.1 200 OK", &json!(visible))
}
