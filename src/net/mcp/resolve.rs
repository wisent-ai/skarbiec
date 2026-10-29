// skarbiec_route_resolve, the one MCP tool that needs server-side
// configuration: the consumer it resolves as, that consumer's bearer and the
// directory the resolved credential is written to.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

// Service grant: env var first, then a grant file. Unset/blank => None; a
// token that is set but not UTF-8, or a grant file that is named but cannot
// be read, is refused with its cause, so the refusal does not tell the
// operator to configure what is set.
fn configured_token() -> Result<Option<String>> {
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
        if value.is_empty() {
            anyhow::bail!(
                "SKARBIEC_MCP_TOKEN_FILE names {}, which holds no grant; write the grant into it or unset the variable",
                path.display()
            );
        }
        return Ok(Some(value));
    }
    Ok(None)
}

/// The consumer the MCP server resolves routes as; `None` when unset or
/// blank, an error naming the variable when it is set but not UTF-8.
fn configured_consumer() -> Result<Option<String>> {
    Ok(
        crate::core::env::text("SKARBIEC_MCP_CONSUMER")?
            .map(|consumer| consumer.trim().to_string()),
    )
}

// Required, absolute output dir; relative would let launch-cwd place files in the
// repo, so relative is refused outright.
fn configured_out_dir() -> Result<String> {
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
    // Same path as `route resolve <name> --consumer c --token-file f --emit
    // --out dir`, with the bearer this server already read handed over in
    // process rather than through a flag.
    let mut flags: HashMap<String, String> = HashMap::new();
    flags.insert("consumer".to_string(), consumer);
    flags.insert("emit".to_string(), "true".to_string());
    flags.insert("out".to_string(), out_dir);
    crate::access::route::resolve_as(&flags, name, &bearer)
}
