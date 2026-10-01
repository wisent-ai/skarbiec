// `credential status`: one poll of the exact Weles action log, persisted
// exactly like a manual run. It reads once and says whether the operation is
// settled; it never sleeps and re-reads, because a watch with a limit turns a
// stuck operation into a quiet `timed_out` instead of a state the caller sees.
// What one poll does lives in `poll`; what a finished operation does to the
// vault lives in `commit`; what a caller reads lives in `snapshot`.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

mod commit;
mod poll;
mod snapshot;
mod subscription;

pub(super) use poll::status_once;

use super::TERMINAL_STATUSES;

/// Add `settled` to one status snapshot: true when its state is one no later
/// read can change.
pub(super) fn with_settled(mut snapshot: Value) -> Result<Value> {
    let settled = snapshot
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| TERMINAL_STATUSES.contains(&status));
    snapshot
        .as_object_mut()
        .context("credential status is not an object")?
        .insert("settled".to_string(), Value::Bool(settled));
    Ok(snapshot)
}

pub(super) fn status(
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    if flags.keys().any(|key| key != "local") {
        bail!("usage: credential status <item-id> [--local]; it reads once and reports settled");
    }
    with_settled(status_once(vault_path, args)?)
}
