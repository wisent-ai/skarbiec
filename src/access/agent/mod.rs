// `agent-enrol <agent>`: give one fleet agent the request-signing identity
// Brama verifies its calls with.
//
// Brama resolves an agent's signing secret through the resource
// `agent:<agent>`, which the vault answers from the `internal-authority` item
// whose `id` field names that agent and whose `agent_auth_secret` holds the
// secret (`route::declaration::agent_items`). Nothing created that item: an
// agent with none was refused by Brama ("no auth secret for agent") and the
// only way to add one was writing a payload by hand. This command creates it
// with a secret generated here, so no value is typed, printed or passed in argv.

use anyhow::{bail, Result};
use serde_json::{json, Map, Value};

use super::route::declaration::{agent_items, AGENT_IDENTITY_KIND, AGENT_SECRET_FIELD};
use crate::cli::args::OrUsage;
use crate::cli::items::ensure_not_replica;
use crate::core::schema::{self, exact_component};
use crate::core::vault::Vault;
use crate::core::{crypto, vault_path};

pub fn enrol(positionals: &[String]) -> Result<Value> {
    let agent = positionals.first().or_usage("usage: agent-enrol <agent>")?;
    if !exact_component(agent) {
        bail!(
            "agent-enrol requires an agent name of letters, digits, '.', '_' and '-', got {agent:?}"
        );
    }
    let mut vault = Vault::open(vault_path())?;
    ensure_not_replica(&vault, "agent-enrol")?;
    if let Some((_, item)) = agent_items(&vault, Some(agent)).into_iter().next() {
        bail!(
            "agent {agent} already has a signing identity in item {item}; \
             `skarbiec route resolve agent:{agent}` shows it"
        );
    }
    let item = format!("{agent}-agent-signing");
    if vault
        .list(false)
        .iter()
        .any(|entry| entry.get("id").and_then(Value::as_str) == Some(item.as_str()))
    {
        bail!(
            "item {item} already exists and is not {agent}'s signing identity; \
             rename or remove it before enrolling {agent}"
        );
    }
    let mut fields = Map::new();
    fields.insert("id".to_string(), json!(agent));
    fields.insert(
        AGENT_SECRET_FIELD.to_string(),
        json!(crypto::random_token()?),
    );
    let payload = schema::payload(AGENT_IDENTITY_KIND, fields, Map::new())?;
    let writer = vault.owner_uid().to_string();
    vault.set_item_written_by(&item, AGENT_IDENTITY_KIND, &payload, &[], &[], &writer)?;
    Ok(json!({
        "ok": true,
        "agent": agent,
        "item": item,
        "resource": format!("agent:{agent}"),
        "created": true,
    }))
}
