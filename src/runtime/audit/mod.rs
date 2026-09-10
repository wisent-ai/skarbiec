// Tamper-evident audit journal. Each line records at/op/extra plus the hash of
// the previous line, forming a chain: any retroactive edit breaks every hash
// after it, which `verify-chain` detects. Values are never journalled — only
// operation names and non-sensitive identifiers.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

mod journal;
mod reports;

pub use journal::{append, append_sync};
pub use reports::{chain_report, probe};

use reports::{query, recent, start_epoch};

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "audit" => Ok(Some(json!(recent(flags)?))),
        "audit-query" => Ok(Some(query(flags)?)),
        "audit-epoch-start" => Ok(Some(start_epoch(flags)?)),
        "verify-chain" => Ok(Some(chain_report(flags)?)),
        _ => Ok(None),
    }
}
