// `credential status`: one poll of the exact Weles action log, persisted
// exactly like a manual run, and the `--follow` watch that ends on a terminal
// state. What one poll does lives in `poll`; what a finished operation does to
// the vault lives in `commit`; what a caller reads lives in `snapshot`.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

mod commit;
mod poll;
mod snapshot;
mod subscription;

pub(super) use poll::status_once;

use super::TERMINAL_STATUSES;

pub(super) fn status(
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = ["follow", "local"];
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("usage: credential status <item-id> [--follow] [--local]");
    }
    if !flags.get("follow").is_some_and(|value| value == "true") {
        return status_once(vault_path, args);
    }
    let interval = Duration::from_secs("5".parse()?);
    let limit = Duration::from_secs("1800".parse()?);
    let started = Instant::now();
    loop {
        let snapshot = status_once(vault_path, args)?;
        let current = snapshot
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        // `pending` is the only state another poll can advance. Everything
        // else ends the watch: the contract terminal states, and local states
        // such as managed, unmanaged, adopting, quarantined, or failed that
        // carry no pollable action log. `follow_settled` says which happened.
        if current != "pending" {
            let mut settled = snapshot;
            settled
                .as_object_mut()
                .context("credential status is not an object")?
                .insert(
                    "follow_settled".to_string(),
                    Value::Bool(TERMINAL_STATUSES.contains(&current.as_str())),
                );
            return Ok(settled);
        }
        if started.elapsed().saturating_add(interval) > limit {
            let mut timed_out = snapshot;
            timed_out
                .as_object_mut()
                .context("credential status is not an object")?
                .insert("follow_timed_out".to_string(), Value::Bool(true));
            return Ok(timed_out);
        }
        std::thread::sleep(interval);
    }
}
