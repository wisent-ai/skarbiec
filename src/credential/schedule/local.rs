// Scheduled rotation of an owner-controlled item through a provider this
// vault rotates through itself — `skarbiec rotate <id> --with <provider>` —
// rather than a Weles-managed credential's provider workflow. `rotation set
// <id> --every-days <N> --with <provider> [its flags]` keeps the provider
// and its flags as the policy's submission; `rotation run` runs that
// rotation for the item when it is due, exactly as it would run typed by
// hand, and records the outcome on the policy as it records a managed
// rotation's.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::cli::items::ensure_not_replica;
use crate::core::clock::{now_epoch, now_iso};
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::super::state::live_item_exists;
use super::policy::{interval, view};
use super::{section, SUBMISSION, USAGE};

/// The submission member naming the provider a local policy rotates with.
pub(super) const WITH: &str = crate::runtime::rotate::WITH;

/// The command's own flags a submission keeps, without the command itself;
/// null for a managed policy's submission.
pub(super) fn passed(submission: Option<&Value>) -> Value {
    let Some(flags) = submission
        .and_then(Value::as_object)
        .filter(|flags| flags.contains_key(WITH))
    else {
        return Value::Null;
    };
    Value::Object(
        flags
            .iter()
            .filter(|(key, _)| key.as_str() != WITH)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

pub(super) fn set(flags: &HashMap<String, String>, args: &[String]) -> Result<Value> {
    let [item] = args else {
        bail!("{USAGE}");
    };
    let with = flags.get(WITH).context(USAGE)?;
    let provider = crate::runtime::rotate::provider(with)?;
    let taken = provider.flags();
    let mut submission = Map::new();
    submission.insert(WITH.to_string(), json!(provider.name));
    for (key, value) in flags {
        if key == WITH || key == "every-days" {
            continue;
        }
        if !taken.iter().any(|flag| flag == key) {
            bail!(
                "--with {} takes no --{key}, so a policy rotating with it cannot keep one. {USAGE}",
                provider.name
            );
        }
        submission.insert(key.clone(), json!(value));
    }
    let (every_days, every_seconds) = interval(flags)?;
    let mut vault = Vault::open(crate::core::vault_path())?;
    ensure_not_replica(&vault, "rotation set")?;
    if !live_item_exists(&vault, item) {
        bail!("no live item: {item}");
    }
    crate::cli::items::ensure_owner_mutation_allowed(&vault, item, "rotate")?;
    let now = now_epoch();
    let stamp = now_iso();
    let entry = section(&mut vault)?
        .entry(item.clone())
        .or_insert_with(|| json!({"created_at": stamp, "anchor_epoch": now}));
    let record = entry
        .as_object_mut()
        .context("rotation policy is not an object")?;
    record.insert("every_seconds".to_string(), json!(every_seconds));
    record.insert(SUBMISSION.to_string(), Value::Object(submission));
    record.insert("updated_at".to_string(), json!(stamp));
    let report = view(item, entry, now)?;
    vault.save()?;
    audit::append(
        "rotation-set",
        &json!({"item": item, "every_days": every_days, "with": provider.name}),
    )?;
    Ok(json!({"ok": true, "policy": report}))
}

/// Run a due local policy's rotation for `item` with the flags it keeps; the
/// provider refuses missing flags in its own words, as typed by hand.
pub(super) fn run(with: &str, flags: &HashMap<String, String>, item: &str) -> Result<Value> {
    let provider = crate::runtime::rotate::provider(with).context("use skarbiec upgrade --apply for a known stored command spelling, or set the policy again with a canonical provider")?;
    let mut report = crate::runtime::rotate::run(provider, flags, item)?;
    if report.get("ok").and_then(Value::as_bool) == Some(true) {
        report["status"] = json!("rotated");
    }
    Ok(report)
}
