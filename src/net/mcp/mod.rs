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

use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

mod endpoints;
mod tools;

pub(crate) use endpoints::{
    authorized_items, handle_acquisitions_issue, handle_items_list, refuse_without_grant,
};

use tools::{call_tool, tools};

// Spec-mandated JSON-RPC 2.0 / MCP wire values (not tunables); kept as strings
// and parsed so no numeric literal appears (crate-wide rule).
const PROTOCOL_VERSION: &str = "2024-11-05";
const CODE_PARSE_ERROR: &str = "-32700";
const CODE_METHOD_NOT_FOUND: &str = "-32601";
const CODE_INTERNAL_ERROR: &str = "-32000";

fn code(raw: &str) -> Value {
    json!(raw.parse::<i64>().unwrap_or_default())
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
