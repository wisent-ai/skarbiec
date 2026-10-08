// Tamper-evident audit journal. Each line records at/op/extra plus the hash of
// the previous line, forming a chain: any retroactive edit breaks every hash
// after it, which `audit verify` detects. Values are never journalled — only
// operation names and non-sensitive identifiers.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

mod journal;
mod reports;

pub use journal::{append, append_sync, retired_ports};
pub use reports::{chain_report, probe};

use reports::{audit, start_epoch};

/// `audit list|verify|epoch` is a group: the journal is the object and the
/// verb its first positional; the operator routes call the leaves by their
/// whole name ("audit list"). A started epoch is still journalled under its
/// own operation name, audit-epoch-start, which every chain already holds.
pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == "audit" {
        return group(flags, positionals).map(Some);
    }
    leaf(command, flags)
}

fn group(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let Some(verb) = positionals.first() else {
        return Err(crate::cli::args::Usage(
            "audit needs a subcommand; `skarbiec audit help` lists them".to_string(),
        )
        .into());
    };
    if verb == "help" {
        return Ok(json!({
            "commands": [
                "audit list [--op <operation>] [--consumer <name>] [--item <id>] [--since <iso>] [--until <iso>] [--limit <N>]",
                "audit verify [--tail <N>]",
                "audit epoch --reason <text>",
            ],
            "usage": "audit list reads the journal oldest first, filtered by operation, consumer, item and time, every match or with --limit the newest N; audit verify checks the journal's linkage and entry digests and reports every fault; audit epoch starts a signed epoch after acknowledging an already-broken chain.",
        }));
    }
    leaf(&format!("audit {verb}"), flags)?.ok_or_else(|| {
        crate::cli::args::Usage(format!(
            "unknown audit command: {verb}; `skarbiec audit help` lists them"
        ))
        .into()
    })
}

fn leaf(command: &str, flags: &HashMap<String, String>) -> Result<Option<Value>> {
    match command {
        "audit list" => Ok(Some(audit(flags)?)),
        "audit verify" => Ok(Some(chain_report(flags)?)),
        "audit epoch" => Ok(Some(start_epoch(flags)?)),
        _ => Ok(None),
    }
}
