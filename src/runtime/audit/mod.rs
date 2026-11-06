// Tamper-evident audit journal. Each line records at/op/extra plus the hash of
// the previous line, forming a chain: any retroactive edit breaks every hash
// after it, which `audit verify` detects. The chain runs through the closed
// segments in `<journal>.d/` and then the open file (`segments`). Values are
// never journalled — only operation names and non-sensitive identifiers.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

mod epoch;
mod journal;
mod reports;
mod retired;
mod segments;
mod summary;

pub use journal::{append, append_sync};
pub use reports::{chain_report, probe};
pub use retired::retired_ports;

use epoch::start_epoch;
use reports::audit;

/// `audit list|verify|epoch|rotate|summary` is a group: the journal is the
/// object and the verb its first positional; the operator routes call the
/// leaves by their whole name ("audit list"). A started epoch is still
/// journalled under its own operation name, audit-epoch-start, which every
/// chain already holds.
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
                "audit summary --since <iso> [--until <iso>]",
                "audit verify [--tail <N>]",
                "audit epoch --reason <text>",
                "audit rotate",
            ],
            "usage": "audit list reads the journal oldest first, filtered by operation, consumer, item and time, every match or with --limit the newest N; audit summary counts a span's entries by operation, consumer and item, most frequent first; audit verify checks the journal's linkage, segments and entry digests across every closed segment and the open file and reports every fault; audit epoch starts a signed epoch after acknowledging an already-broken chain; audit rotate closes the open file as the next segment now instead of at the first entry of the next UTC day.",
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
        "audit summary" => Ok(Some(summary::summary(flags)?)),
        "audit verify" => Ok(Some(serde_json::to_value(chain_report(flags)?)?)),
        "audit epoch" => Ok(Some(start_epoch(flags)?)),
        "audit rotate" => Ok(Some(journal::rotate()?)),
        _ => Ok(None),
    }
}
