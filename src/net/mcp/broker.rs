// `skarbiec mcp broker`: the capability broker v1 surface Las federates
// (las/src/registry/skarbiec.mjs pins every name, schema and result here).
//
// Exactly four tools, in this order, and nothing else: Las refuses a child
// whose tool list differs from its signed manifest. Each answer is one text
// item holding one JSON object with exactly the keys Las accepts. The agent is
// the operator's statement in SKARBIEC_MCP_AGENT_ID, never a tool argument.
//
// A capability is issued only by a person: `capability_request` with no
// approved request behind it files one and answers `pending` with its id, and
// `access_request_status` reports the decision. The issued capability carries
// that id as its authorization id, so the workload signs it into its proof.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

const SERVICE: &str = "skarbiec-capability-broker";
const WIRE: &str = "skarbiec.redeem.v1";
const BOUNDED: &[&str] = &["purpose", "resource", "target", "ttl_seconds", "max_uses"];
/// The minimum Las pins for `ttl_seconds` and `max_uses`: one second, one use
/// (las/src/registry/skarbiec.mjs, SKARBIEC_TOOL_SCHEMA_DIGESTS).
const AT_LEAST_ONE: u64 = 1;

fn text_property() -> Value {
    json!({"type": "string", "minLength": 1})
}

fn whole(minimum: u64) -> Value {
    json!({"type": "integer", "minimum": minimum})
}

fn bounded_schema(delegation: bool) -> Value {
    let mut properties = json!({
        "purpose": text_property(),
        "resource": text_property(),
        "target": text_property(),
        "ttl_seconds": whole(AT_LEAST_ONE),
        "max_uses": whole(AT_LEAST_ONE),
    });
    if delegation {
        properties["delegation_depth"] = whole(u64::MIN);
    }
    json!({"type": "object", "properties": properties, "required": BOUNDED, "additionalProperties": false})
}

pub(super) fn tools() -> Value {
    json!([
        {"name": "health",
         "description": "Return a non-sensitive broker health summary.",
         "inputSchema": {"type": "object", "properties": {}, "required": [], "additionalProperties": false}},
        {"name": "capability_available",
         "description": "Check whether the authenticated agent may request an exactly bounded capability. Returns only availability.",
         "inputSchema": bounded_schema(false)},
        {"name": "capability_request",
         "description": "Request an opaque, bounded capability for the authenticated agent. Returns status issued with an opaque capability ID, or status pending with the access request ID a person decides.",
         "inputSchema": bounded_schema(true)},
        {"name": "access_request_status",
         "description": "Report the decision on one access request this agent filed: pending, denied, withdrawn, or approved with its capability ID.",
         "inputSchema": {"type": "object", "properties": {"request_id": text_property()}, "required": ["request_id"], "additionalProperties": false}},
    ])
}

fn answer(payload: Value) -> Value {
    json!({"content": [{"type": "text", "text": payload.to_string()}]})
}

fn agent() -> Result<String> {
    std::env::var("SKARBIEC_MCP_AGENT_ID")
        .ok()
        .filter(|agent| crate::core::schema::exact_component(agent))
        .context("the broker surface is disabled: the operator must set SKARBIEC_MCP_AGENT_ID to this agent's exact name")
}

/// The bounded arguments as the flags `request file` reads, refused when
/// they are not exactly the shape the schema declares.
fn bounded_flags(args: &Value, delegation: bool) -> Result<HashMap<String, String>> {
    let object = args.as_object().context("arguments must be an object")?;
    let mut flags = HashMap::new();
    for (name, value) in object {
        let rendered = match (name.as_str(), value) {
            ("purpose" | "resource" | "target", Value::String(text))
                if crate::core::schema::exact_token(text) && text.trim() == text =>
            {
                text.clone()
            }
            ("ttl_seconds" | "max_uses", Value::Number(number))
                if number.as_u64().is_some_and(|value| value > u64::MIN) =>
            {
                number.to_string()
            }
            ("delegation_depth", Value::Number(number)) if delegation && number.is_u64() => {
                number.to_string()
            }
            _ => bail!("argument {name} is not part of this tool's schema or has the wrong shape"),
        };
        flags.insert(name.replace('_', "-"), rendered);
    }
    for name in BOUNDED {
        if !flags.contains_key(&name.replace('_', "-")) {
            bail!("argument {name} is required");
        }
    }
    Ok(flags)
}

fn health() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let generation = vault.doc()["generation"].as_u64().unwrap_or_default();
    let chain = crate::runtime::audit::chain_report(&HashMap::new())?;
    Ok(json!({
        "ok": true,
        "service": SERVICE,
        "wire": WIRE,
        "policy_sequence": generation,
        "registry_sequence": chain["entries"],
        "active_capabilities": crate::access::capability::active_count()?,
        "anomaly_count": chain["faults"].as_array().map_or(usize::MIN, Vec::len),
    }))
}

fn available(args: &Value) -> Result<Value> {
    let flags = bounded_flags(args, false)?;
    let agent = agent()?;
    let resolves = crate::access::route::resolution::coordinate_for(&flags["resource"])?.is_ok();
    let vault = Vault::open(vault_path())?;
    let redeemable = crate::access::capability::workload_registered(&vault, &agent);
    Ok(json!({"available": resolves && redeemable}))
}

fn same_capability(record: &Value, agent: &str, flags: &HashMap<String, String>) -> bool {
    record["requester"]["agent"] == json!(agent)
        && record["grant"]["form"] == json!("capability")
        && record["resource"] == json!(flags["resource"])
        && record["grant"]["purpose"] == json!(flags["purpose"])
        && record["grant"]["target"] == json!(flags["target"])
}

fn request(args: &Value) -> Result<Value> {
    let mut flags = bounded_flags(args, true)?;
    let agent = agent()?;
    for record in crate::access::request::snapshot()? {
        if record["state"] == json!("approved") && same_capability(&record, &agent, &flags) {
            if let Some(id) = record["issued"]["capability_id"].as_str() {
                if crate::access::capability::live(id)? {
                    return Ok(json!({"status": "issued", "capability_id": id}));
                }
            }
        }
    }
    let reason = format!(
        "{agent} asked through the broker for {} on {} via {}",
        flags["purpose"], flags["resource"], flags["target"]
    );
    flags.insert("reason".into(), reason);
    flags.insert("kind".into(), "secret".into());
    flags.insert("action".into(), "read".into());
    flags.insert("agent".into(), agent);
    for (flag, variable) in [
        ("harness", "SKARBIEC_MCP_HARNESS"),
        ("person", "SKARBIEC_MCP_PERSON"),
    ] {
        if let Ok(value) = std::env::var(variable) {
            flags.insert(flag.into(), value);
        }
    }
    let record = crate::access::request::file_broker(&flags)?;
    Ok(json!({"status": "pending", "request_id": record["id"]}))
}

fn status(args: &Value) -> Result<Value> {
    let object = args.as_object().context("arguments must be an object")?;
    let id = object
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && object.len() == std::iter::once(()).count())
        .context("access_request_status takes exactly one non-empty request_id")?;
    let agent = agent()?;
    let record = crate::access::request::snapshot()?
        .into_iter()
        .find(|record| record["id"] == json!(id) && record["requester"]["agent"] == json!(agent))
        .with_context(|| format!("no access request {id} filed by {agent}"))?;
    match record["state"].as_str().unwrap_or_default() {
        "approved" => {
            let capability = record["issued"]["capability_id"]
                .as_str()
                .context("access request was approved without a capability; ask its decider")?;
            Ok(json!({"request_id": id, "state": "approved", "capability_id": capability}))
        }
        state @ ("pending" | "denied" | "withdrawn") => {
            Ok(json!({"request_id": id, "state": state}))
        }
        other => bail!("access request {id} is in an unknown state {other}"),
    }
}

pub(super) fn call_tool(name: &str, args: &Value) -> Result<Value> {
    let payload = match name {
        "health" => {
            if args.as_object().is_some_and(|object| !object.is_empty()) {
                bail!("health takes no arguments");
            }
            health()?
        }
        "capability_available" => available(args)?,
        "capability_request" => request(args)?,
        "access_request_status" => status(args)?,
        other => bail!("unknown tool: {other}"),
    };
    Ok(answer(payload))
}
