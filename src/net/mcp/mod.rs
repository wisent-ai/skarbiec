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

mod catalog;
mod endpoints;
mod resolve;
mod tools;

pub(crate) use endpoints::{
    authorized_items, handle_acquisitions_issue, handle_items_list, refuse_items,
};

use catalog::tools;
use tools::call_tool;

/// The MCP protocol revision this server speaks, as the MCP specification names it.
const PROTOCOL_VERSION: &str = "2024-11-05";
/// Invalid JSON was received: https://www.jsonrpc.org/specification#error_object
const CODE_PARSE_ERROR: i64 = -32700;
/// The method does not exist: https://www.jsonrpc.org/specification#error_object
const CODE_METHOD_NOT_FOUND: i64 = -32601;
/// Invalid method parameters: https://www.jsonrpc.org/specification#error_object
const CODE_INVALID_PARAMS: i64 = -32602;
/// The implementation-defined server error range starts here: https://www.jsonrpc.org/specification#error_object
const CODE_INTERNAL_ERROR: i64 = -32000;
/// The JSON sent is not a valid request object: https://www.jsonrpc.org/specification#error_object
const CODE_INVALID_REQUEST: i64 = -32600;

fn send(out: &mut impl Write, message: &Value) -> Result<()> {
    writeln!(out, "{}", serde_json::to_string(message)?)?;
    out.flush()?;
    Ok(())
}

fn error_response(id: Value, error_code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": error_code, "message": message}})
}

fn server_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn handle(request: &Value, out: &mut impl Write) -> Result<()> {
    // No `id` key => notification: never answer.
    let id = match request.get("id") {
        Some(id) => id.clone(),
        None => return Ok(()),
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return send(out, &error_response(id, CODE_INVALID_REQUEST, "the request names no method"));
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
            // JSON-RPC lets a call omit `params`; a tool call without a tool name cannot run.
            let Some(name) = request.pointer("/params/name").and_then(Value::as_str) else {
                return send(
                    out,
                    &error_response(id, CODE_INVALID_PARAMS, "tools/call needs params.name, the tool to call"),
                );
            };
            // A tool called with no `arguments` is called with an empty argument object, as MCP defines it.
            let mut args = json!({});
            if let Some(stated) = request.pointer("/params/arguments") {
                args.clone_from(stated);
            }
            match call_tool(name, &args) {
                Ok(result) => send(out, &json!({"jsonrpc": "2.0", "id": id, "result": result})),
                Err(e) => send(
                    out,
                    &error_response(id, CODE_INTERNAL_ERROR, &format!("{e:#}")),
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
            Err(error) => send(
                &mut stdout,
                &error_response(Value::Null, CODE_PARSE_ERROR, &format!("parse error: {error}")),
            )?,
        }
    }
    Ok(())
}
