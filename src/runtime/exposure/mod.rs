// `skarbiec exposure <id> [--since <iso8601>]`: everything that could have
// learned one item's value, in one answer — the question after a leak or a
// lost laptop, before deciding whether to rotate it. The keys its ciphertext
// is encrypted to (`readers`), the consumers whose grant reaches it (`grant
// list --item`), every journal entry naming it, optionally since a moment,
// with the consumers those entries name, and the plain-text copies `scan`
// would look for are left to scan: this answers from the vault alone.
// Nothing is decrypted; no value leaves.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

use crate::cli::args::Usage;
use crate::core::clock;

const USAGE: &str = "usage: exposure <id> [--since <iso8601>]";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "exposure" {
        return Ok(None);
    }
    let [id] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let since = flags.get("since");
    if let Some(moment) = since.filter(|moment| !clock::is_iso(moment)) {
        return Err(Usage(format!(
            "--since {moment} is not a UTC time of the form {}; {USAGE}",
            clock::now_iso()
        ))
        .into());
    }
    let readers = crate::cli::reads::cmd_readers(positionals)?;
    let grants = crate::access::dispatch(
        "grant",
        &HashMap::from([("item".to_string(), id.clone())]),
        &["list".to_string()],
    )?
    .context("grant list answered nothing")?;
    let mut journal_flags = HashMap::from([("item".to_string(), id.clone())]);
    if let Some(moment) = since {
        journal_flags.insert("since".to_string(), moment.clone());
    }
    let journal = crate::runtime::dispatch("audit list", &journal_flags, &[])?
        .context("audit list answered nothing")?;
    let entries = journal["entries"]
        .as_array()
        .context("audit list answered no entries")?;
    // Who the journal says acted on the item, and how: each consumer once,
    // with every operation it was named in.
    let mut acted: HashMap<String, BTreeSet<String>> = HashMap::new();
    for entry in entries {
        let Some(consumer) = entry["extra"]["consumer"].as_str() else {
            continue;
        };
        let operation = entry["op"]
            .as_str()
            .context("a journal entry names no operation")?;
        acted
            .entry(consumer.to_string())
            .or_default()
            .insert(operation.to_string());
    }
    let mut acted: Vec<Value> = acted
        .into_iter()
        .map(|(consumer, operations)| json!({"consumer": consumer, "operations": operations}))
        .collect();
    acted.sort_by(|left, right| left["consumer"].as_str().cmp(&right["consumer"].as_str()));
    let granted: Vec<Value> = grants
        .as_array()
        .context("grant list did not answer a list")?
        .iter()
        .map(|grant| json!({"consumer": grant["consumer"], "expired": grant["expired"], "until_revoked": grant["until_revoked"]}))
        .collect();
    crate::runtime::audit::append("exposure", &json!({"item": id, "since": since}))?;
    Ok(Some(json!({
        "ok": true,
        "item": id,
        "since": since,
        "keys": readers,
        "grants": granted,
        "journal_entries": entries.len(),
        "acted": acted,
        "read_here_by": crate::runtime::wiring::naming(id),
        "next": format!(
            "to shut it out: lockdown or grant revoke for each grant, revoke {id} <uid> for each key that should not open it, helper unset aws --profile <name> or helper unset kube --user <name> for each profile or user here that should not read it, then replace the value where it is issued"
        ),
    })))
}
