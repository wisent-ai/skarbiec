// `skarbiec lockdown [--except <consumer,...>] [--yes]`: the first step when a
// machine, a laptop or a bearer may be compromised — withdraw every grant at
// once, so no consumer's bearer opens anything until it is issued again.
// Without --yes it names every grant it would withdraw and changes nothing;
// --except keeps the named consumers, each of which must hold a grant, so a
// misspelled one is refused rather than silently withdrawn. Each grant is
// revoked as `grant revoke <consumer>` revokes it, and one that fails is
// named with its error while the others still go.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

use crate::cli::args::{flag_set, Usage};

const USAGE: &str = "usage: lockdown [--except <consumer,...>] [--yes]";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "lockdown" {
        return Ok(None);
    }
    if !positionals.is_empty() {
        return Err(Usage(USAGE.to_string()).into());
    }
    let listed = crate::access::dispatch("grant", &HashMap::new(), &["list".to_string()])?
        .context("grant list answered nothing")?;
    let consumers: BTreeSet<String> = listed
        .as_array()
        .context("grant list did not answer a list")?
        .iter()
        .filter_map(|grant| grant["consumer"].as_str().map(str::to_string))
        .collect();
    let kept: BTreeSet<String> = match flags.get("except") {
        Some(names) => names
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect(),
        None => BTreeSet::new(),
    };
    let unknown: Vec<&String> = kept
        .iter()
        .filter(|name| !consumers.contains(*name))
        .collect();
    if !unknown.is_empty() {
        let named: Vec<&str> = unknown.iter().map(|name| name.as_str()).collect();
        bail!("--except names {}, which hold no grant; nothing was withdrawn. `skarbiec grant list` names the consumers", named.join(", "));
    }
    let withdrawn: Vec<&String> = consumers
        .iter()
        .filter(|consumer| !kept.contains(*consumer))
        .collect();
    if !flag_set(flags, "yes") {
        return Ok(Some(
            json!({"ok": true, "applied": false, "would_withdraw": withdrawn, "kept": kept}),
        ));
    }
    let mut revoked = Vec::new();
    let mut failed = Vec::new();
    for consumer in withdrawn {
        match crate::access::dispatch(
            "grant",
            &HashMap::new(),
            &["revoke".to_string(), consumer.clone()],
        ) {
            Ok(_) => revoked.push(consumer.clone()),
            Err(error) => failed.push(json!({"consumer": consumer, "error": format!("{error:#}")})),
        }
    }
    crate::runtime::audit::append(
        "lockdown",
        &json!({"revoked": revoked, "kept": kept, "failed": failed.len()}),
    )?;
    Ok(Some(
        json!({"ok": failed.is_empty(), "applied": true, "revoked": revoked, "kept": kept, "failed": failed}),
    ))
}
