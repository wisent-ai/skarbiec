// `audit summary --since <iso> [--until <iso>]`: what happened to the vault in
// a span, counted rather than listed — how often each operation ran, which
// consumers acted and how often, and which items were named most — so a week
// of activity reads at a glance and an unexpected consumer or a burst of
// reads of one item stands out. It reads the same journal `audit list`
// reads, with the same span filters, and names nothing a journal entry does
// not already name.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

use crate::cli::args::Usage;
use crate::core::clock;

const USAGE: &str = "usage: audit summary --since <iso8601> [--until <iso8601>]";

pub(in crate::runtime::audit) fn summary(flags: &HashMap<String, String>) -> Result<Value> {
    let Some(since) = flags.get("since") else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let until = flags.get("until");
    for (flag, moment) in [("since", Some(since)), ("until", until)] {
        if let Some(moment) = moment.filter(|moment| !clock::is_iso(moment)) {
            return Err(Usage(format!("--{flag} {moment} is not a UTC time of the form {}", clock::now_iso())).into());
        }
    }
    let mut span = HashMap::from([("since".to_string(), since.clone())]);
    if let Some(until) = until {
        span.insert("until".to_string(), until.clone());
    }
    let listed = super::reports::audit(&span)?;
    let entries = listed
        .get("entries")
        .and_then(Value::as_array)
        .context("audit list answered no entries")?;
    // Each name keeps the entries that named it; its count is how many.
    let mut operations: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    let mut consumers: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    let mut items: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for entry in entries {
        if let Some(op) = entry.get("op").and_then(Value::as_str) {
            operations.entry(op).or_default().push(entry);
        }
        let extra = entry.get("extra");
        if let Some(consumer) = extra.and_then(|extra| extra.get("consumer")).and_then(Value::as_str) {
            consumers.entry(consumer).or_default().push(entry);
        }
        // An entry names one item in `item`, or several in `items`.
        let named = extra
            .and_then(|extra| extra.get("item"))
            .and_then(Value::as_str)
            .into_iter()
            .chain(
                extra
                    .and_then(|extra| extra.get("items"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str),
            );
        for item in named {
            items.entry(item).or_default().push(entry);
        }
    }
    Ok(json!({
        "ok": true,
        "since": since,
        "until": until,
        "entries": entries.len(),
        "operations": ranked(&operations, "op"),
        "consumers": ranked(&consumers, "consumer"),
        "items": ranked(&items, "item"),
    }))
}

/// Counts as rows, the most frequent first and ties in name order.
fn ranked(named: &BTreeMap<&str, Vec<&Value>>, key: &str) -> Vec<Value> {
    let mut rows: Vec<(&str, usize)> = named.iter().map(|(name, entries)| (*name, entries.len())).collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    rows.into_iter()
        .map(|(name, count)| json!({key: name, "count": count}))
        .collect()
}
