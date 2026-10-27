// Starting every due rotation. `rotation run` is what a recurring trigger
// calls — on the Wisent fleet a Stado schedule pinned to the vault owner, on a
// standalone host cron or launchd — so Skarbiec keeps the policies and their
// outcomes and owns no clock loop of its own.
//
// A managed credential's rotation goes through `start_operation("rotate", …)`,
// the path `credential rotate --local` takes, so a scheduled rotation obeys
// every rule a requested one does: managed items only, one operation at a
// time, no retry after an uncertain provider effect. A policy naming a
// rotation command with --with runs that command as it runs typed by hand.
// What came back is written onto the
// policy — status, request id, the refusal in full — so `rotation list` shows
// why a credential did not rotate, not only that it did not.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::items::ensure_not_replica;
use crate::core::clock::{now_epoch, now_iso};
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::super::lifecycle::start_operation;
use super::policy::is_due;
use super::{policies, section, SUBMISSION};

/// Whether this host can run the schedule: a vault exists here and it is not
/// a replica of another.
pub(super) fn runs_here() -> Result<bool> {
    let path = crate::core::vault_path();
    if !crate::core::is_present(&path, "vault")? {
        return Ok(false);
    }
    Ok(ensure_not_replica(&Vault::open(path)?, "rotation run").is_ok())
}

struct Due {
    item: String,
    flags: HashMap<String, String>,
}

/// The policies to run now: every due one, or `only`'s when it is due — or,
/// with `now`, `only`'s whether or not it is due yet.
fn due_now(only: Option<&str>, now: i64, at_once: bool) -> Result<Vec<Due>> {
    let vault = Vault::open(crate::core::vault_path())?;
    ensure_not_replica(&vault, "rotation run")?;
    let mut due = Vec::new();
    for (item, entry) in policies(&vault)? {
        if only.is_some_and(|wanted| wanted != item) || !(at_once || is_due(&entry, now)) {
            continue;
        }
        // The flags `rotation set` validated, passed on exactly as a
        // `credential rotate --local` command line would carry them.
        let flags = entry
            .get(SUBMISSION)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(key, value)| value.as_str().map(|text| (key.clone(), text.to_string())))
            .collect();
        due.push(Due { item, flags });
    }
    Ok(due)
}

/// What a rotation that was not accepted answered, in its own words: the
/// Weles code and message when there is one, the recorded status otherwise.
fn refusal(report: &Value) -> String {
    let words: Vec<&str> = report
        .get("weles")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(_, value)| value.as_str())
        .collect();
    if !words.is_empty() {
        return words.join(": ");
    }
    match report.get("status").and_then(Value::as_str) {
        Some(status) => status.to_string(),
        None => format!("not accepted, and the report states no status: {report}"),
    }
}

fn record(item: &str, outcome: &Result<Value>, now: i64) -> Result<Value> {
    let (accepted, status, request_id, error) = match outcome {
        Ok(report) => {
            let accepted = report.get("ok").and_then(Value::as_bool) == Some(true);
            // The status the rotation report states, or none: no word is
            // stored as the policy's last status that the report did not say.
            let status = report
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string);
            let error = (!accepted).then(|| refusal(report));
            (accepted, status, report.get("request_id").cloned(), error)
        }
        Err(error) => (
            false,
            Some("refused".to_string()),
            None,
            Some(format!("{error:#}")),
        ),
    };
    let request_id = json!(request_id);
    let stamp = now_iso();
    let mut vault = Vault::open(crate::core::vault_path())?;
    if let Some(entry) = section(&mut vault)?
        .get_mut(item)
        .and_then(Value::as_object_mut)
    {
        entry.insert("last_attempt_at".to_string(), json!(stamp));
        entry.insert("last_status".to_string(), json!(status));
        entry.insert("last_error".to_string(), json!(error));
        entry.insert("last_request_id".to_string(), request_id.clone());
        if accepted {
            entry.insert("anchor_epoch".to_string(), json!(now));
            entry.insert("last_accepted_at".to_string(), json!(stamp));
            entry.remove("failed_attempts_at");
            entry.remove("due_reason");
        } else {
            entry
                .entry("failed_attempts_at")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .with_context(|| {
                    format!("rotation policy {item} records failed_attempts_at that is not a list")
                })?
                .push(json!(stamp));
        }
        // The failure count is read from failed_attempts_at; no separate
        // counter is kept.
        entry.remove("consecutive_failures");
        vault.save()?;
    }
    let line = json!({
        "item": item,
        "accepted": accepted,
        "status": status,
        "request_id": request_id,
        "error": error,
    });
    audit::append(
        if accepted {
            "rotation-started"
        } else {
            "rotation-failed"
        },
        &line,
    )?;
    Ok(line)
}

/// Start every due rotation now, or only `only`'s when it is due. One refused
/// rotation does not stop the others; each is recorded on its policy and in
/// the journal, and the command fails when any of them was not accepted, so a
/// scheduler that watches exit codes sees it. `at_once` runs `only`'s policy
/// before it falls due — after a leak, or to try a policy just set.
pub(super) fn run_due(only: Option<&str>, at_once: bool) -> Result<Value> {
    let path = crate::core::vault_path();
    let now = now_epoch();
    let mut ran = Vec::new();
    for Due { item, flags } in due_now(only, now, at_once)? {
        // A policy naming a rotation command runs it; a managed credential's
        // goes through the provider lifecycle.
        let outcome = match flags.get(super::local::WITH) {
            Some(with) => super::local::run(with, &flags, &item),
            None => start_operation("rotate", &path, &flags, std::slice::from_ref(&item)),
        };
        ran.push(record(&item, &outcome, now)?);
    }
    let refused = ran
        .iter()
        .filter(|line| line.get("accepted").and_then(Value::as_bool) != Some(true))
        .count();
    let all_accepted = ran
        .iter()
        .all(|line| line.get("accepted").and_then(Value::as_bool) == Some(true));
    let report = json!({"ok": all_accepted, "ran": ran, "failed": refused});
    if !all_accepted {
        let items: Vec<String> = ran
            .iter()
            .filter(|line| line.get("accepted").and_then(Value::as_bool) != Some(true))
            .map(|line| line["item"].to_string())
            .collect();
        // A credential that should have changed and did not is told where
        // people look, when this host set an alert.
        let alerted = match crate::runtime::alert::send(&format!(
            "skarbiec rotation run: {refused} scheduled rotation(s) failed: {}; `skarbiec rotation list` names why",
            items.join(", ")
        )) {
            Ok(Some(_)) => "the alert was posted".to_string(),
            Ok(None) => "no alert is set".to_string(),
            Err(error) => format!("the alert could not be posted: {error:#}"),
        };
        anyhow::bail!("{refused} scheduled rotation(s) were not accepted ({alerted}): {report}");
    }
    Ok(report)
}
