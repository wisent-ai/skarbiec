// Withdrawing grants: one consumer's (`grant revoke <consumer>`), every
// grant whose end has passed (`grant revoke --expired`), the ones that answer
// nothing and only clutter the list, or every grant nobody has used since a
// moment (`grant revoke --idle-since <iso> --yes`).

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::access::grant::lookup::load;
use crate::access::grant::UNTIL_REVOKED;
use crate::cli::args::{flag_set, OrUsage, Usage};

/// Revoking a consumer that holds no grant stays a success, as documented, so
/// a repeat is harmless; the answer says `revoked: false` so it is never read
/// as having withdrawn something.
pub(in crate::access::grant) fn revoke(
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let seen = crate::access::grant::rules::idle::Seen::since(flags.get("idle-since"))?;
    let mut vault = load()?;
    let tokens = vault
        .doc_mut()
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("tokens section")?;
    if flag_set(flags, "expired") {
        if !positionals.is_empty() {
            return Err(Usage(
                "grant revoke takes either one consumer or --expired, not both".to_string(),
            )
            .into());
        }
        let now = crate::core::clock::epoch_seconds()?;
        let expired: Vec<String> = tokens
            .iter()
            .filter(|(_, entry)| {
                entry
                    .get("expires_at")
                    .and_then(Value::as_u64)
                    .is_some_and(|end| end != UNTIL_REVOKED && end <= now)
            })
            .map(|(consumer, _)| consumer.clone())
            .collect();
        for consumer in &expired {
            tokens.remove(consumer);
        }
        if !expired.is_empty() {
            vault.save()?;
            crate::runtime::audit::append(
                "grant-revoked",
                &json!({"consumers": expired, "reason": "expired"}),
            )?;
        }
        return Ok(json!({"ok": true, "revoked": expired}));
    }
    if let (Some(seen), Some(moment)) = (seen, flags.get("idle-since")) {
        if !positionals.is_empty() {
            return Err(Usage(
                "grant revoke takes either one consumer or --idle-since, not both".to_string(),
            )
            .into());
        }
        // A grant used once a year is idle most of the year: the list comes
        // first, and withdrawing every one of them is said out loud.
        if !flag_set(flags, "yes") {
            return Err(Usage(format!(
                "grant revoke --idle-since {moment} withdraws every grant unused since then; `skarbiec grant list --idle-since {moment}` lists them, and --yes withdraws them"
            ))
            .into());
        }
        let idle: Vec<String> = tokens
            .keys()
            .filter(|consumer| seen.idle(consumer))
            .cloned()
            .collect();
        for consumer in &idle {
            tokens.remove(consumer);
        }
        if !idle.is_empty() {
            vault.save()?;
            crate::runtime::audit::append(
                "grant-revoked",
                &json!({"consumers": idle, "reason": "idle", "idle_since": moment}),
            )?;
        }
        return Ok(json!({"ok": true, "revoked": idle, "idle_since": moment}));
    }
    let consumer = positionals
        .first()
        .or_usage("usage: grant revoke <consumer> | grant revoke --expired | grant revoke --idle-since <iso8601> --yes")?;
    let removed = tokens.remove(consumer).is_some();
    if removed {
        vault.save()?;
        crate::runtime::audit::append("grant-revoked", &json!({"consumer": consumer}))?;
    }
    Ok(json!({"ok": true, "consumer": consumer, "revoked": removed}))
}
