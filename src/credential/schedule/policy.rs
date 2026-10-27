// Declaring, reading and withdrawing one item's rotation policy.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::cli::items::ensure_not_replica;
use crate::core::clock::{iso_at, now_epoch, now_iso};
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::super::common::{exact_name, purpose};
use super::super::state::{lifecycle_state, live_item_exists};
use super::super::STATE_MANAGED;
use super::{policies, section, SUBMISSION, USAGE};

fn text<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str)
}

/// When the policy next falls due: its interval after the last accepted
/// rotation, or after the policy was declared when none has been accepted.
/// `None` when the policy records no anchor or interval.
pub(super) fn next_due_epoch(entry: &Value) -> Option<i64> {
    let anchor = entry.get("anchor_epoch").and_then(Value::as_i64)?;
    anchor.checked_add(every_seconds(entry)?)
}

fn every_seconds(entry: &Value) -> Option<i64> {
    entry.get("every_seconds").and_then(Value::as_i64)
}

/// A policy is due when its interval has passed or something marked it due
/// now — a removed recipient who could read the value. A policy without an
/// interval is never due; `rotation list` names it.
pub(super) fn is_due(entry: &Value, now: i64) -> bool {
    text(entry, "due_reason").is_some() || next_due_epoch(entry).is_some_and(|due| now >= due)
}

pub(super) fn view(id: &str, entry: &Value, now: i64) -> Result<Value> {
    let damaged = || {
        format!("rotation policy {id} records no anchor_epoch or every_seconds; set it again with rotation set")
    };
    let every = every_seconds(entry).with_context(damaged)?;
    let next_due = next_due_epoch(entry).with_context(damaged)?;
    let submission = entry.get(SUBMISSION);
    let flag = |key: &str| submission.and_then(|flags| flags.get(key)).cloned();
    // A stored noncanonical provider remains visible with its refusal. Known
    // retired command spellings are migrated by upgrade, never accepted as aliases.
    let (with, with_error) = match flag(super::local::WITH) {
        Some(Value::String(saved)) => match crate::runtime::rotate::provider(&saved) {
            Ok(provider) => (json!(provider.name), Value::Null),
            Err(error) => (json!(saved), json!(format!("{error:#}; use skarbiec upgrade --apply for a known stored command spelling, or rotation set with a canonical provider"))),
        },
        None => (Value::Null, Value::Null),
        Some(saved) => (
            Value::Null,
            json!(format!("rotation policy {id} submission.with is not a provider name: received {saved}; set the policy again with a canonical provider")),
        ),
    };
    Ok(json!({
        "item": id,
        "every_days": every / time::Duration::DAY.whole_seconds(),
        "provider": flag("provider"),
        "consumer": flag("consumer"),
        "purpose": flag("purpose"),
        "with": with,
        "with_error": with_error,
        "with_flags": super::local::passed(submission),
        "due": is_due(entry, now),
        "due_reason": entry.get("due_reason"),
        "next_due_at": iso_at(next_due),
        "last_attempt_at": entry.get("last_attempt_at"),
        "last_status": entry.get("last_status"),
        "last_error": entry.get("last_error"),
        "last_request_id": entry.get("last_request_id"),
        "last_accepted_at": entry.get("last_accepted_at"),
        "consecutive_failures": entry
            .get("failed_attempts_at")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .count(),
    }))
}

/// `--every-days` as a whole number of days above zero, and in seconds.
pub(super) fn interval(flags: &HashMap<String, String>) -> Result<(i64, i64)> {
    let every_days = flags
        .get("every-days")
        .context("--every-days is required")?;
    let every_days: i64 = every_days.parse().with_context(|| {
        format!("--every-days must be a whole number of days above zero, not {every_days}")
    })?;
    if !every_days.is_positive() {
        bail!("--every-days must be a whole number of days above zero, not {every_days}");
    }
    let every_seconds = every_days
        .checked_mul(time::Duration::DAY.whole_seconds())
        .context("--every-days is too large")?;
    Ok((every_days, every_seconds))
}

pub(super) fn set(flags: &HashMap<String, String>, args: &[String]) -> Result<Value> {
    // An owner-controlled item rotated by a command this vault runs itself.
    if flags.contains_key(super::local::WITH) {
        return super::local::set(flags, args);
    }
    let allowed = ["every-days", "provider", "consumer", "purpose"];
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{USAGE}");
    }
    let [item] = args else {
        bail!("{USAGE}");
    };
    let (every_days, every_seconds) = interval(flags)?;
    let provider = flags.get("provider").context("--provider is required")?;
    let consumer = flags.get("consumer").context("--consumer is required")?;
    exact_name("provider", provider)?;
    exact_name("consumer", consumer)?;
    let purpose = flags
        .get("purpose")
        .map(|value| purpose(value))
        .transpose()?;

    let mut vault = Vault::open(crate::core::vault_path())?;
    ensure_not_replica(&vault, "rotation set")?;
    if !live_item_exists(&vault, item) {
        bail!("no live item: {item}");
    }
    let state = lifecycle_state(&vault, item)?;
    if state != STATE_MANAGED {
        bail!(
            "{item} is {state}, not a Weles-managed credential; only a managed credential can be rotated on a schedule. Bring it under management with credential adopt or credential acquire first"
        );
    }
    let now = now_epoch();
    let stamp = now_iso();
    let mut submission = json!({"provider": provider, "consumer": consumer});
    if let Some(purpose) = purpose {
        submission["purpose"] = json!(purpose);
    }
    let entry = section(&mut vault)?
        .entry(item.clone())
        .or_insert_with(|| json!({"created_at": stamp, "anchor_epoch": now}));
    let record = entry
        .as_object_mut()
        .context("rotation policy is not an object")?;
    record.insert("every_seconds".to_string(), json!(every_seconds));
    record.insert(SUBMISSION.to_string(), submission);
    record.insert("updated_at".to_string(), json!(stamp));
    let report = view(item, entry, now)?;
    vault.save()?;
    audit::append(
        "rotation-set",
        &json!({"item": item, "every_days": every_days, "provider": provider, "consumer": consumer}),
    )?;
    Ok(json!({"ok": true, "policy": report}))
}

/// `rotation list [--due]`: every policy, or with `--due` only the ones the
/// next `rotation run` would start.
pub(super) fn list(flags: &HashMap<String, String>) -> Result<Value> {
    let due_only = crate::cli::args::flag_set(flags, "due");
    let path = crate::core::vault_path();
    let now = now_epoch();
    let policies: Map<String, Value> = if crate::core::is_present(&path, "vault")? {
        policies(&Vault::open(path)?)?
    } else {
        Map::new()
    };
    let rows = policies
        .iter()
        .filter(|(_, entry)| !due_only || is_due(entry, now))
        .map(|(id, entry)| view(id, entry, now))
        .collect::<Result<Vec<Value>>>()?;
    Ok(json!({
        "policies": rows,
        "runs_here": super::runs_here()?,
    }))
}

pub(super) fn remove(args: &[String]) -> Result<Value> {
    let item = args.first().context(USAGE)?;
    let mut vault = Vault::open(crate::core::vault_path())?;
    ensure_not_replica(&vault, "rotation remove")?;
    if section(&mut vault)?.remove(item).is_none() {
        bail!("no rotation policy for {item}");
    }
    vault.save()?;
    audit::append("rotation-remove", &json!({"item": item}))?;
    Ok(json!({"ok": true, "item": item}))
}
