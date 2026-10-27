// `list --untouched-since <iso>`: the items no audit journal entry has named
// since a moment — nobody read one through the API, wrote it, shared it or
// changed it. A secret nothing uses is one to retire, and its grants and
// readers with it.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::super::args::Usage;

/// The item ids the journal names at or after `moment`, or `None` without
/// a moment, so every item passes.
pub(super) fn named_since(moment: Option<&String>) -> Result<Option<HashSet<String>>> {
    let Some(moment) = moment else {
        return Ok(None);
    };
    if !crate::core::clock::is_iso(moment) {
        return Err(Usage(format!(
            "--untouched-since {moment} is not a UTC time of the form {}",
            crate::core::clock::now_iso()
        ))
        .into());
    }
    let flags = HashMap::from([("since".to_string(), moment.clone())]);
    let answer = crate::runtime::audit::dispatch("audit", &flags, &["list".to_string()])?
        .context("audit list answered nothing")?;
    let entries = answer
        .get("entries")
        .and_then(Value::as_array)
        .context("audit list answered no entries")?;
    let mut named = HashSet::new();
    for extra in entries.iter().filter_map(|entry| entry.get("extra")) {
        // An entry names one item in `item`, or several in `items`.
        if let Some(item) = extra.get("item").and_then(Value::as_str) {
            named.insert(item.to_string());
        }
        for item in extra.get("items").and_then(Value::as_array).into_iter().flatten() {
            if let Some(item) = item.as_str() {
                named.insert(item.to_string());
            }
        }
    }
    Ok(Some(named))
}
