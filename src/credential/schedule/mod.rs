// Scheduled rotation: a per-item policy that says how often a Weles-managed
// credential is rotated, and `rotation run`, which starts each due rotation
// through the same `credential rotate` lifecycle an operator would start by
// hand. A recurring trigger calls `rotation run`: on the Wisent fleet a Stado
// schedule pinned to the vault owner, on a standalone host cron or launchd.
//
// Policies live in the vault document under `rotation`, keyed by item id, so
// they travel with the vault. A replica never runs them: its document is
// replaced by the next pull, and the rotation belongs to the vault that is
// written.

mod policy;
mod run;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;

use run::runs_here;

/// The vault document section holding every policy.
const SECTION: &str = "rotation";

/// The member of a policy holding the `credential rotate` flags it was
/// declared with.
const SUBMISSION: &str = "submission";

const USAGE: &str = "usage: rotation set <item-id> --every-days <N> --provider <provider> --consumer <consumer> [--purpose <text>] | rotation list | rotation remove <item-id> | rotation run [--item <item-id>]";

pub(super) fn dispatch(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let leaf = positionals.first().map(String::as_str).unwrap_or("help");
    let args = positionals
        .get(std::iter::once(()).count()..)
        .unwrap_or_default();
    match leaf {
        "set" => policy::set(flags, args),
        "list" => policy::list(),
        "remove" => policy::remove(args),
        "run" => run::run_due(flags.get("item").map(String::as_str)),
        "help" => Ok(json!({
            "commands": ["rotation set", "rotation list", "rotation remove", "rotation run"],
            "usage": USAGE,
        })),
        other => bail!("unknown rotation command: {other}; {USAGE}"),
    }
}

/// Every policy, as the vault holds it.
fn policies(vault: &Vault) -> Map<String, Value> {
    vault
        .doc()
        .get(SECTION)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// The policy section, created empty when absent.
fn section(vault: &mut Vault) -> Result<&mut Map<String, Value>> {
    let doc = vault
        .doc_mut()
        .as_object_mut()
        .context("vault document is not an object")?;
    doc.entry(SECTION.to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("rotation section is not an object")
}

/// Mark the items among `ids` that carry a policy as due now, naming why.
/// Returns the items marked; an item without a policy is left to the caller
/// to report, because nothing here can rotate it.
pub(crate) fn mark_due(ids: &[String], reason: &str) -> Result<Vec<String>> {
    let path = crate::core::vault_path();
    if ids.is_empty() || !path.exists() {
        return Ok(Vec::new());
    }
    let mut vault = Vault::open(path)?;
    let mut marked = Vec::new();
    for id in ids {
        if let Some(entry) = section(&mut vault)?
            .get_mut(id)
            .and_then(Value::as_object_mut)
        {
            entry.insert("due_reason".to_string(), json!(reason));
            marked.push(id.clone());
        }
    }
    if !marked.is_empty() {
        vault.save()?;
    }
    Ok(marked)
}
