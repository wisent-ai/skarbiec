// `skarbiec mcp broker`: the capability broker v1 surface Las federates
// (las/src/registry/skarbiec/policy.mjs pins every name, schema and result
// here).
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
//
// Every argument is checked against the schema the tool declares, so the
// schema Las pins and the check this broker makes cannot drift apart.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::num::{NonZeroU64, NonZeroUsize};

use crate::core::vault::Vault;
use crate::core::vault_path;

const SERVICE: &str = "skarbiec-capability-broker";
const WIRE: &str = "skarbiec.redeem.v1";

/// One argument's declared shape, as a tool's input schema states it and as
/// this broker reads it back to check a call.
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Shape {
    /// A non-empty exact token.
    String {
        #[serde(rename = "minLength")]
        min_length: NonZeroUsize,
    },
    /// A whole number of at least `minimum`.
    Integer { minimum: u64 },
}

/// A non-empty string, as Las pins every text argument.
const TEXT: Shape = Shape::String { min_length: NonZeroUsize::MIN };
/// At least one second, or one use, as Las pins `ttl_seconds` and `max_uses`.
const AT_LEAST_ONE: Shape = Shape::Integer { minimum: NonZeroU64::MIN.get() };

/// Any whole number of hops, as Las pins `delegation_depth`.
fn unsigned() -> Shape {
    Shape::Integer { minimum: Default::default() }
}

/// The input schema of one tool: its named arguments, the ones it requires,
/// and no others.
fn schema(properties: &[(&str, Shape)], required: &[&str]) -> Value {
    let properties: serde_json::Map<String, Value> = properties
        .iter()
        .map(|(name, shape)| (name.to_string(), json!(shape)))
        .collect();
    json!({"type": "object", "properties": properties, "required": required, "additionalProperties": false})
}

/// The bounded capability every request names.
fn bounded() -> Vec<(&'static str, Shape)> {
    vec![
        ("purpose", TEXT),
        ("resource", TEXT),
        ("target", TEXT),
        ("ttl_seconds", AT_LEAST_ONE),
        ("max_uses", AT_LEAST_ONE),
    ]
}

fn bounded_required() -> Vec<&'static str> {
    bounded().into_iter().map(|(name, _)| name).collect()
}

fn input_schema(tool: &str) -> Result<Value> {
    Ok(match tool {
        "health" => schema(&[], &[]),
        "capability_available" => schema(&bounded(), &bounded_required()),
        "capability_request" => {
            let mut properties = bounded();
            properties.push(("delegation_depth", unsigned()));
            schema(&properties, &bounded_required())
        }
        "access_request_status" => schema(&[("request_id", TEXT)], &["request_id"]),
        other => bail!("unknown tool: {other}"),
    })
}

/// The tools in the order Las's signed release lists them.
const ORDER: &[(&str, &str)] = &[
    ("health", "Return a non-sensitive broker health summary."),
    ("capability_available", "Check whether the authenticated agent may request an exactly bounded capability. Returns only availability."),
    ("capability_request", "Request an opaque, bounded capability for the authenticated agent. Returns status issued with an opaque capability ID, or status pending with the access request ID a person decides."),
    ("access_request_status", "Report the decision on one access request this agent filed: pending, denied, withdrawn, or approved with its capability ID."),
];

pub(super) fn tools() -> Result<Value> {
    let listed = ORDER
        .iter()
        .map(|(name, description)| {
            Ok(json!({"name": name, "description": description, "inputSchema": input_schema(name)?}))
        })
        .collect::<Result<Vec<Value>>>()?;
    Ok(Value::Array(listed))
}

fn answer(payload: Value) -> Value {
    json!({"content": [{"type": "text", "text": payload.to_string()}]})
}

fn agent() -> Result<String> {
    let agent = std::env::var("SKARBIEC_MCP_AGENT_ID").map_err(|error| {
        anyhow!("the broker surface is disabled: the operator must set SKARBIEC_MCP_AGENT_ID to this agent's exact name ({error})")
    })?;
    if !crate::core::schema::exact_component(&agent) {
        bail!("SKARBIEC_MCP_AGENT_ID {agent:?} is not one exact name");
    }
    Ok(agent)
}

/// A call's arguments as the flags `request file` reads, each checked against
/// the shape its tool's schema declares; an undeclared or misshapen argument
/// and a missing required one are refused by name.
fn arguments(tool: &str, args: &Value) -> Result<HashMap<String, String>> {
    let declared = input_schema(tool)?;
    let object = args.as_object().context("arguments must be an object")?;
    let mut flags = HashMap::new();
    for (name, value) in object {
        let shape: Shape = serde_json::from_value(declared["properties"][name].clone())
            .with_context(|| format!("argument {name} is not part of {tool}'s schema"))?;
        let rendered = match (shape, value) {
            (Shape::String { .. }, Value::String(text))
                if crate::core::schema::exact_token(text) && text.trim() == text =>
            {
                text.clone()
            }
            (Shape::Integer { minimum }, Value::Number(number))
                if number.as_u64().is_some_and(|given| given >= minimum) =>
            {
                number.to_string()
            }
            _ => bail!("argument {name} does not have the shape {tool}'s schema declares: {}", json!(shape)),
        };
        flags.insert(name.replace('_', "-"), rendered);
    }
    for required in declared["required"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if !flags.contains_key(&required.replace('_', "-")) {
            bail!("argument {required} is required");
        }
    }
    Ok(flags)
}

fn health() -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let generation = vault.doc()["generation"]
        .as_u64()
        .context("the vault document records no generation")?;
    let chain = crate::runtime::audit::chain_report(&HashMap::new())?;
    Ok(json!({
        "ok": true,
        "service": SERVICE,
        "wire": WIRE,
        "policy_sequence": generation,
        "registry_sequence": chain.entries,
        "active_capabilities": crate::access::capability::active_count()?,
        "anomaly_count": chain.faults.len(),
    }))
}

fn available(args: &Value) -> Result<Value> {
    let flags = arguments("capability_available", args)?;
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

/// An optional statement of the operator's, set as `flag` when present; a
/// variable that is set but unreadable is refused rather than skipped.
fn stated(flags: &mut HashMap<String, String>, flag: &str, variable: &str) -> Result<()> {
    match std::env::var(variable) {
        Ok(value) => {
            flags.insert(flag.into(), value);
            Ok(())
        }
        Err(std::env::VarError::NotPresent) => Ok(()),
        Err(error) => bail!("{variable} cannot be read: {error}"),
    }
}

fn request(args: &Value) -> Result<Value> {
    let mut flags = arguments("capability_request", args)?;
    let agent = agent()?;
    for record in crate::access::request::snapshot()? {
        if record["state"] == json!(State::Approved) && same_capability(&record, &agent, &flags) {
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
    stated(&mut flags, "harness", "SKARBIEC_MCP_HARNESS")?;
    stated(&mut flags, "person", "SKARBIEC_MCP_PERSON")?;
    let record = crate::access::request::file_broker(&flags)?;
    Ok(json!({"status": "pending", "request_id": record["id"]}))
}

/// The state the register records for an access request.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum State {
    Pending,
    Approved,
    Denied,
    Withdrawn,
}

fn status(args: &Value) -> Result<Value> {
    let flags = arguments("access_request_status", args)?;
    let id = &flags["request-id"];
    let agent = agent()?;
    let record = crate::access::request::snapshot()?
        .into_iter()
        .find(|record| record["id"] == json!(id) && record["requester"]["agent"] == json!(agent))
        .with_context(|| format!("no access request {id} filed by {agent}"))?;
    let state: State = serde_json::from_value(record["state"].clone())
        .with_context(|| format!("access request {id} is in a state this broker does not know: {}", record["state"]))?;
    if state != State::Approved {
        return Ok(json!({"request_id": id, "state": state}));
    }
    let capability = record["issued"]["capability_id"]
        .as_str()
        .context("access request was approved without a capability; ask its decider")?;
    Ok(json!({"request_id": id, "state": state, "capability_id": capability}))
}

pub(super) fn call_tool(name: &str, args: &Value) -> Result<Value> {
    let payload = match name {
        "health" => {
            arguments(name, args)?;
            health()?
        }
        "capability_available" => available(args)?,
        "capability_request" => request(args)?,
        "access_request_status" => status(args)?,
        other => bail!("unknown tool: {other}"),
    };
    Ok(answer(payload))
}
