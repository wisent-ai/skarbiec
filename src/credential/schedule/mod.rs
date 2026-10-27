// Scheduled rotation: a per-item policy that says how often a credential is
// rotated, and `rotation run`, which starts each due rotation. A Weles-managed
// credential goes through the same `credential rotate` lifecycle an operator
// would start by hand; an owner-controlled item goes through the provider
// its policy names with --with, as `skarbiec rotate <id> --with <provider>`.
// A recurring trigger calls `rotation run`: on the Wisent fleet a Stado
// schedule pinned to the vault owner, on a standalone host cron or launchd.
//
// Policies live in the vault document under `rotation`, keyed by item id, so
// they travel with the vault. A replica never runs them: its document is
// replaced by the next pull, and the rotation belongs to the vault that is
// written.

mod local;
mod policy;
mod run;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;

use run::runs_here;

/// The vault document section holding every policy.
const SECTION: &str = "rotation";

/// The member of a policy holding the `credential rotate` flags it was
/// declared with.
const SUBMISSION: &str = "submission";

const USAGE: &str = "usage: rotation set <item-id> --every-days <N> (--provider <provider> --consumer <consumer> [--purpose <text>] | --with <provider> [that provider's flags]) | rotation list [--due] | rotation remove <item-id> | rotation run [--item <item-id> [--now]] | rotation providers";

pub(super) fn dispatch(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let help = || -> Result<Value> {
        Ok(json!({
            "commands": ["rotation set", "rotation list", "rotation remove", "rotation run", "rotation providers"],
            "usage": USAGE,
        }))
    };
    let Some((leaf, args)) = positionals.split_first() else {
        return help();
    };
    match leaf.as_str() {
        "set" => policy::set(flags, args),
        "list" => policy::list(flags),
        "remove" => policy::remove(args),
        "providers" => {
            if !args.is_empty() || !flags.is_empty() {
                return Err(crate::cli::args::Usage(format!("rotation providers takes no argument or flag; {USAGE}")).into());
            }
            Ok(crate::runtime::rotate::providers())
        }
        "run" => {
            let at_once = crate::cli::args::flag_set(flags, "now");
            let only = flags.get("item").map(String::as_str);
            if at_once && only.is_none() {
                return Err(crate::cli::args::Usage(format!("rotation run --now runs one policy before it falls due and needs --item <item-id>; {USAGE}")).into());
            }
            run::run_due(only, at_once)
        }
        "help" => help(),
        other => Err(crate::cli::args::Usage(format!(
            "unknown rotation command: {other}; {USAGE}"
        ))
        .into()),
    }
}

/// Every policy, as the vault holds it; a vault that never declared one holds none.
/// A rotation section that is not an object is refused.
fn policies(vault: &Vault) -> Result<Map<String, Value>> {
    match vault.doc().get(SECTION) {
        None => Ok(Map::new()),
        Some(Value::Object(section)) => Ok(section.clone()),
        Some(other) => anyhow::bail!("the vault's {SECTION} section is {other}, not an object of policies"),
    }
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
    if ids.is_empty() || !crate::core::is_present(&path, "vault")? {
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

/// Carry an item's rotation policy to its new id after a rename, so the
/// schedule keeps rotating it; the caller saves. True when there was one.
pub(crate) fn follow_rename(vault: &mut Vault, from: &str, to: &str) -> bool {
    let Some(section) = vault.doc_mut().get_mut(SECTION).and_then(Value::as_object_mut) else {
        return false;
    };
    match section.remove(from) {
        Some(policy) => {
            section.insert(to.to_string(), policy);
            true
        }
        None => false,
    }
}

/// Drop a purged item's rotation policy, which could only ever fail to run
/// again; the caller saves. True when there was one.
pub(crate) fn forget(vault: &mut Vault, id: &str) -> bool {
    vault
        .doc_mut()
        .get_mut(SECTION)
        .and_then(Value::as_object_mut)
        .is_some_and(|section| section.remove(id).is_some())
}
