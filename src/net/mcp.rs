//! Stdio MCP surface. Exactly three metadata/capability tools are exposed.
//! Credential plaintext is available only through the target AF_UNIX redemption wire.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::io::{BufRead, Write};

use crate::access::capability::Broker;

const PROTOCOL_VERSION: &str = "2024-11-05";
const CODE_PARSE_ERROR: i64 = -32700;
const CODE_METHOD_NOT_FOUND: i64 = -32601;
const CODE_INTERNAL_ERROR: i64 = -32000;

fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

fn tools() -> Value {
    json!([
        {"name":"health","description":"Return a non-sensitive broker health summary.","inputSchema":object_schema(json!({}),&[])},
        {"name":"capability_available","description":"Check whether the server-authenticated agent may request an exactly bounded capability. Returns only availability.","inputSchema":object_schema(json!({
            "purpose":{"type":"string","minLength":1},"resource":{"type":"string","minLength":1},"target":{"type":"string","minLength":1},
            "ttl_seconds":{"type":"integer","minimum":1},"max_uses":{"type":"integer","minimum":1}
        }),&["purpose","resource","target","ttl_seconds","max_uses"])},
        {"name":"capability_request","description":"Request an opaque, bounded capability for the server-authenticated agent. Returns only status and opaque capability ID; redemption is target-socket-only.","inputSchema":object_schema(json!({
            "purpose":{"type":"string","minLength":1},"resource":{"type":"string","minLength":1},"target":{"type":"string","minLength":1},
            "ttl_seconds":{"type":"integer","minimum":1},"max_uses":{"type":"integer","minimum":1},"delegation_depth":{"type":"integer","minimum":0}
        }),&["purpose","resource","target","ttl_seconds","max_uses"])}
    ])
}

fn text_result(value: Value) -> Value {
    json!({"content":[{"type":"text","text":serde_json::to_string(&value).unwrap_or_else(|_| "{\"status\":\"denied\"}".into())}]})
}
fn agent_id() -> Result<String> {
    let id = std::env::var("SKARBIEC_MCP_AGENT_ID")
        .context("broker agent identity is not configured")?;
    let id = id.trim();
    if id.is_empty() || id == "*" {
        bail!("broker agent identity is invalid");
    }
    Ok(id.into())
}
fn args<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().context("arguments must be an object")?;
    let allow: HashSet<&str> = allowed.iter().copied().collect();
    if object.keys().any(|k| !allow.contains(k.as_str())) {
        bail!("unknown capability argument");
    }
    Ok(object)
}
fn string_arg<'a>(args: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    let value = args
        .get(name)
        .and_then(Value::as_str)
        .context("invalid capability argument")?;
    if value.trim() != value || value.is_empty() || value == "*" {
        bail!("invalid capability argument");
    }
    Ok(value)
}
fn u64_arg(args: &Map<String, Value>, name: &str) -> Result<u64> {
    let n = args
        .get(name)
        .and_then(Value::as_u64)
        .context("invalid capability argument")?;
    if n == 0 {
        bail!("invalid capability argument")
    };
    Ok(n)
}

fn call_tool(name: &str, input: &Value) -> Result<Value> {
    match name {
        "health" => {
            args(input, &[])?;
            Ok(text_result(Broker::open()?.health()?))
        }
        "capability_available" => {
            let a = args(
                input,
                &["purpose", "resource", "target", "ttl_seconds", "max_uses"],
            )?;
            let broker = Broker::open()?;
            let available = broker.available(
                &agent_id()?,
                string_arg(a, "purpose")?,
                string_arg(a, "resource")?,
                string_arg(a, "target")?,
                u64_arg(a, "ttl_seconds")?,
                u64_arg(a, "max_uses")?,
            );
            Ok(text_result(json!({"available":available})))
        }
        "capability_request" => {
            let a = args(
                input,
                &[
                    "purpose",
                    "resource",
                    "target",
                    "ttl_seconds",
                    "max_uses",
                    "delegation_depth",
                ],
            )?;
            let mut broker = Broker::open()?;
            let id = broker.issue(
                &agent_id()?,
                string_arg(a, "purpose")?,
                string_arg(a, "resource")?,
                string_arg(a, "target")?,
                u64_arg(a, "ttl_seconds")?,
                u64_arg(a, "max_uses")?,
                a.get("delegation_depth")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .try_into()
                    .context("invalid delegation depth")?,
            )?;
            Ok(text_result(json!({"status":"issued","capability_id":id})))
        }
        _ => bail!("unknown tool"),
    }
}
fn send(out: &mut impl Write, value: &Value) -> Result<()> {
    writeln!(out, "{}", serde_json::to_string(value)?)?;
    out.flush()?;
    Ok(())
}
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn handle(request: &Value, out: &mut impl Write) -> Result<()> {
    let object = request.as_object().context("request must be an object")?;
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .context("method missing")?;
    let Some(id) = object.get("id").cloned() else {
        return Ok(());
    };
    match method {
        "initialize" => send(
            out,
            &json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{}},"serverInfo":{"name":"skarbiec","version":env!("CARGO_PKG_VERSION")}}}),
        ),
        "ping" => send(out, &json!({"jsonrpc":"2.0","id":id,"result":{}})),
        "tools/list" => send(
            out,
            &json!({"jsonrpc":"2.0","id":id,"result":{"tools":tools()}}),
        ),
        "tools/call" => {
            let p = object
                .get("params")
                .and_then(Value::as_object)
                .context("params missing")?;
            let name = p.get("name").and_then(Value::as_str).unwrap_or("");
            let input = p.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match call_tool(name, &input) {
                Ok(result) => send(out, &json!({"jsonrpc":"2.0","id":id,"result":result})),
                Err(_) => send(
                    out,
                    &error(id, CODE_INTERNAL_ERROR, "capability request denied"),
                ),
            }
        }
        _ => send(out, &error(id, CODE_METHOD_NOT_FOUND, "method not found")),
    }
}
pub fn serve() -> Result<()> {
    // Opening first makes signed policy/trust/state/socket/WORM configuration a startup requirement.
    Broker::open()?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(v) => {
                if handle(&v, &mut stdout).is_err() {
                    send(
                        &mut stdout,
                        &error(Value::Null, CODE_PARSE_ERROR, "invalid request"),
                    )?
                }
            }
            Err(_) => send(
                &mut stdout,
                &error(Value::Null, CODE_PARSE_ERROR, "parse error"),
            )?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(request: Value) -> Value {
        let mut output = Vec::new();
        handle(&request, &mut output).expect("MCP request should produce a response");
        serde_json::from_slice(&output).expect("MCP response should be valid JSON")
    }

    #[test]
    fn tools_list_is_exactly_the_non_secret_capability_surface() {
        let result = response(json!({"jsonrpc":"2.0","id":7,"method":"tools/list"}));

        assert_eq!(
            result,
            json!({
                "jsonrpc":"2.0",
                "id":7,
                "result":{"tools":[
                    {
                        "name":"health",
                        "description":"Return a non-sensitive broker health summary.",
                        "inputSchema":{"type":"object","properties":{},"required":[],"additionalProperties":false}
                    },
                    {
                        "name":"capability_available",
                        "description":"Check whether the server-authenticated agent may request an exactly bounded capability. Returns only availability.",
                        "inputSchema":{
                            "type":"object",
                            "properties":{
                                "purpose":{"type":"string","minLength":1},
                                "resource":{"type":"string","minLength":1},
                                "target":{"type":"string","minLength":1},
                                "ttl_seconds":{"type":"integer","minimum":1},
                                "max_uses":{"type":"integer","minimum":1}
                            },
                            "required":["purpose","resource","target","ttl_seconds","max_uses"],
                            "additionalProperties":false
                        }
                    },
                    {
                        "name":"capability_request",
                        "description":"Request an opaque, bounded capability for the server-authenticated agent. Returns only status and opaque capability ID; redemption is target-socket-only.",
                        "inputSchema":{
                            "type":"object",
                            "properties":{
                                "purpose":{"type":"string","minLength":1},
                                "resource":{"type":"string","minLength":1},
                                "target":{"type":"string","minLength":1},
                                "ttl_seconds":{"type":"integer","minimum":1},
                                "max_uses":{"type":"integer","minimum":1},
                                "delegation_depth":{"type":"integer","minimum":0}
                            },
                            "required":["purpose","resource","target","ttl_seconds","max_uses"],
                            "additionalProperties":false
                        }
                    }
                ]}
            })
        );
    }

    #[test]
    fn denied_tool_call_never_echoes_secret_bearing_name_or_arguments() {
        let result = response(json!({
            "jsonrpc":"2.0",
            "id":11,
            "method":"tools/call",
            "params":{
                "name":"secret_read_/private/vault.json",
                "arguments":{"path":"/private/vault.json","secret":"plaintext"}
            }
        }));

        assert_eq!(
            result,
            json!({
                "jsonrpc":"2.0",
                "id":11,
                "error":{"code":CODE_INTERNAL_ERROR,"message":"capability request denied"}
            })
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("/private/vault.json"));
        assert!(!serialized.contains("plaintext"));
        assert!(!serialized.contains("secret_read"));
    }
}
