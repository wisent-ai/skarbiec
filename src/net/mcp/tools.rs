// The tools an agent may call over MCP, and the configuration each of them
// needs. Raw item reads, minting and rotation are deliberately absent.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::core::vault::Vault;
use crate::core::vault_path;
use crate::runtime;
use std::collections::HashMap;
use std::path::Path;

pub(super) fn schema(properties: Value, required: Vec<&str>) -> Value {
    json!({"type": "object", "properties": properties, "required": required})
}

// Exposed surface == the vault's own declared programmatic-safe boundary.
pub(super) fn tools() -> Value {
    json!([
        {"name": "skarbiec_health",
         "description": "Liveness probe for the skarbiec vault. Returns {ok, service}. No credentials touched.",
         "inputSchema": schema(json!({}), vec![])},
        {"name": "skarbiec_list",
         "description": "List credential item metadata (ids, type, revision counts, tags). Never returns secret values.",
         "inputSchema": schema(json!({}), vec![])},
        {"name": "skarbiec_route_resolve",
         "description": "Resolve one declared route the sanctioned way: policy- and token-gated; emits an owner-only env file and returns only its path plus the exported variable NAMES (ADMIN_EMAIL/ADMIN_PASSWORD/ADMIN_TOTP). Values are never returned. The server must be configured with SKARBIEC_MCP_CONSUMER, SKARBIEC_MCP_TOKEN (or SKARBIEC_MCP_TOKEN_FILE), and an absolute SKARBIEC_MCP_OUT_DIR; the token is never a tool argument.",
         "inputSchema": schema(json!({"name": {"type": "string", "description": "The resource name to resolve, as route resolve accepts it: login:<item> for one login item, provider:<provider>, agent:<agent>, or a hand-declared resource."}}), vec!["name"])},
        {"name": "skarbiec_audit",
         "description": "Return the tamper-evident audit journal (at/op/extra/prev/hash chain). Only operation names and non-sensitive identifiers are journalled; never values.",
         "inputSchema": schema(json!({}), vec![])},
    ])
}

pub(super) fn text_result(value: &Value) -> Result<Value> {
    let text = match value {
        Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).context("render the tool result as text")?,
    };
    Ok(json!({"content": [{"type": "text", "text": text}]}))
}

// Service grant: env var first, then a grant file. Unset/blank => None; a
// token that is set but not UTF-8, or a grant file that is named but cannot
// be read, is refused with its cause, so the refusal does not tell the
// operator to configure what is set.
pub(super) fn configured_token() -> Result<Option<String>> {
    if let Some(value) = crate::core::env::text("SKARBIEC_MCP_TOKEN")? {
        return Ok(Some(value.trim().to_string()));
    }
    if let Some(path) = crate::core::env::path("SKARBIEC_MCP_TOKEN_FILE") {
        let body = std::fs::read_to_string(&path).map_err(|error| {
            anyhow::anyhow!(
                "SKARBIEC_MCP_TOKEN_FILE names {}, which cannot be read: {error}",
                path.display()
            )
        })?;
        let value = body.trim().to_string();
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// The consumer the MCP server resolves routes as; `None` when unset or
/// blank, an error naming the variable when it is set but not UTF-8.
pub(super) fn configured_consumer() -> Result<Option<String>> {
    Ok(
        crate::core::env::text("SKARBIEC_MCP_CONSUMER")?
            .map(|consumer| consumer.trim().to_string()),
    )
}

// Required, absolute output dir; relative would let launch-cwd place files in the
// repo, so relative is refused outright.
pub(super) fn configured_out_dir() -> Result<String> {
    let dir = crate::core::env::text("SKARBIEC_MCP_OUT_DIR")?
        .map(|d| d.trim().to_string())
        .context("skarbiec_route_resolve is disabled: configure SKARBIEC_MCP_OUT_DIR to an absolute directory on the MCP server")?;
    if !Path::new(&dir).is_absolute() {
        anyhow::bail!("SKARBIEC_MCP_OUT_DIR must be an absolute path, got: {dir}");
    }
    Ok(dir)
}

pub(super) fn resolve_tool(args: &Value) -> Result<Value> {
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .context("skarbiec_route_resolve requires a non-empty 'name'")?;
    // Mandatory server-side auth; refuse before opening the vault.
    let consumer = configured_consumer()?.context(
        "skarbiec_route_resolve is disabled: configure SKARBIEC_MCP_CONSUMER on the MCP server",
    )?;
    let bearer = configured_token()?
        .context("skarbiec_route_resolve is disabled: configure SKARBIEC_MCP_TOKEN or SKARBIEC_MCP_TOKEN_FILE on the MCP server")?;
    let out_dir = configured_out_dir()?;
    // Same path as `route resolve <name> --consumer c --token t --emit --out dir`.
    let mut flags: HashMap<String, String> = HashMap::new();
    flags.insert("consumer".to_string(), consumer);
    flags.insert("token".to_string(), bearer);
    flags.insert("emit".to_string(), "true".to_string());
    flags.insert("out".to_string(), out_dir);
    crate::access::route::dispatch("route", &flags, &["resolve".to_string(), name.to_string()])?
        .context("route resolve produced no result")
}

pub(super) fn call_tool(name: &str, args: &Value) -> Result<Value> {
    match name {
        "skarbiec_health" => text_result(&json!({"ok": true, "service": "skarbiec"})),
        "skarbiec_list" => text_result(&json!(Vault::open(vault_path())?.list(false))),
        "skarbiec_route_resolve" => text_result(&resolve_tool(args)?),
        "skarbiec_audit" => {
            let empty: Vec<String> = Vec::new();
            text_result(
                &runtime::audit::dispatch("audit list", &HashMap::new(), &empty)?
                    .context("audit produced no result")?,
            )
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}
