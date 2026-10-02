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

/// Seconds in one day, the unit `--every-days` is given in.
pub(super) fn day_seconds() -> Result<i64> {
    Ok(86400)
}

fn text<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str)
}

/// When the policy next falls due: its interval after the last accepted
/// rotation, or after the policy was declared when none has been accepted.
pub(super) fn next_due_epoch(entry: &Value) -> i64 {
    let anchor = entry
        .get("anchor_epoch")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let every = entry
        .get("every_seconds")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    anchor.saturating_add(every)
}

/// A policy is due when its interval has passed or something marked it due
/// now — a removed recipient who could read the value.
pub(super) fn is_due(entry: &Value, now: i64) -> bool {
    text(entry, "due_reason").is_some() || now >= next_due_epoch(entry)
}

pub(super) fn view(id: &str, entry: &Value, now: i64) -> Result<Value> {
    let every = entry
        .get("every_seconds")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let submission = entry.get(SUBMISSION);
    let flag = |key: &str| submission.and_then(|flags| flags.get(key)).cloned();
    Ok(json!({
        "item": id,
        "every_days": every / day_seconds()?,
        "provider": flag("provider"),
        "consumer": flag("consumer"),
        "purpose": flag("purpose"),
        "due": is_due(entry, now),
        "due_reason": entry.get("due_reason"),
        "next_due_at": iso_at(next_due_epoch(entry)),
        "last_attempt_at": entry.get("last_attempt_at"),
        "last_status": entry.get("last_status"),
        "last_error": entry.get("last_error"),
        "last_request_id": entry.get("last_request_id"),
        "last_accepted_at": entry.get("last_accepted_at"),
        "consecutive_failures": entry.get("consecutive_failures").and_then(Value::as_u64).unwrap_or_default(),
    }))
}

pub(super) fn set(flags: &HashMap<String, String>, args: &[String]) -> Result<Value> {
    let allowed = ["every-days", "provider", "consumer", "purpose"];
    if flags.keys().any(|key| !allowed.contains(&key.as_str()))
        || args.len() != std::iter::once(()).count()
    {
        bail!("{USAGE}");
    }
    let item = args.first().context(USAGE)?;
    let every_days: i64 = flags
        .get("every-days")
        .context("--every-days is required")?
        .parse()
        .ok()
        .filter(|days: &i64| *days > i64::default())
        .context("--every-days must be a whole number of days above zero")?;
    let every_seconds = every_days
        .checked_mul(day_seconds()?)
        .context("--every-days is too large")?;
    let provider = flags.get("provider").context("--provider is required")?;
    let consumer = flags.get("consumer").context("--consumer is required")?;
    exact_name("provider", provider, 128)?;
    exact_name("consumer", consumer, 200)?;
    let purpose = flags
        .get("purpose")
        .map(|value| purpose(Some(value), consumer))
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

pub(super) fn list() -> Result<Value> {
    let path = crate::core::vault_path();
    let now = now_epoch();
    let policies: Map<String, Value> = if path.exists() {
        policies(&Vault::open(path)?)
    } else {
        Map::new()
    };
    let rows = policies
        .iter()
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
