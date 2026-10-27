// The capability state as a journal: one line per change, so a grant or a
// redemption writes the bytes of its own entry, never every capability the
// broker holds.
//
// The file is a sequence of JSON values, one per line. A snapshot
// (`{"capabilities": {...}, "nonces": {...}}`) replaces everything read
// before it; an entry sets one capability's record
// (`{"capability": ID, "record": {...}}`) or records one seen nonce
// (`{"nonce": "ID:NONCE", "seen_at": EPOCH}`). Reading replays them in order.
// Once the entries the journal still carries for capabilities that can no
// longer be redeemed outweigh the live state, the writer replaces the
// journal with one snapshot of the live state, so the file stays the size of
// what can still be redeemed.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// What a replay of the journal's bytes found: the state, whether it read
/// any complete value, and the error of the bytes after them that do not
/// parse (an append or replacement interrupted mid-write).
pub(super) struct Replayed {
    pub state: Value,
    pub complete: bool,
    pub trailing: Option<serde_json::Error>,
}

pub(super) fn empty() -> Value {
    json!({"capabilities": {}, "nonces": {}})
}

/// Replay `raw` in order. A value that is neither a snapshot nor an entry
/// is damaged state and refused naming its position.
pub(super) fn replay(raw: &str) -> Result<Replayed> {
    let mut state = empty();
    let mut complete = false;
    let mut trailing = None;
    let values = serde_json::Deserializer::from_str(raw).into_iter::<Value>();
    for (position, value) in values.enumerate() {
        let value = match value {
            Ok(value) => value,
            Err(error) => {
                trailing = Some(error);
                break;
            }
        };
        complete = true;
        apply(&mut state, value).with_context(|| {
            format!("the capability state value at position {position} cannot be applied")
        })?;
    }
    Ok(Replayed {
        state,
        complete,
        trailing,
    })
}

fn apply(state: &mut Value, value: Value) -> Result<()> {
    if value.get("capabilities").is_some() {
        *state = value;
        return Ok(());
    }
    match (value.get("capability"), value.get("nonce")) {
        (Some(Value::String(id)), None) => match value.get("record") {
            Some(record @ Value::Object(_)) => {
                state["capabilities"][id.as_str()] = record.clone();
                Ok(())
            }
            other => bail!("the entry of capability {id} holds record {other:?}, not an object"),
        },
        (None, Some(Value::String(key))) => match value.get("seen_at") {
            Some(seen @ Value::Number(_)) => {
                state["nonces"][key.as_str()] = seen.clone();
                Ok(())
            }
            other => bail!("the entry of nonce {key} holds seen_at {other:?}, not a time"),
        },
        _ => bail!("{value} is neither a snapshot, a capability entry nor a nonce entry"),
    }
}

/// The entry lines that record `capability_id`'s record as `state` holds it
/// now, preceded by the nonce `nonce` names when one was seen.
pub(super) fn entries(state: &Value, capability_id: &str, nonce: Option<&str>) -> Result<Vec<u8>> {
    let mut lines = Vec::new();
    if let Some(key) = nonce {
        let seen = state["nonces"]
            .get(key)
            .with_context(|| format!("the nonce {key} to record was never seen"))?;
        serde_json::to_writer(&mut lines, &json!({"nonce": key, "seen_at": seen}))?;
        lines.push(b'\n');
    }
    let record = state["capabilities"]
        .get(capability_id)
        .with_context(|| format!("the capability {capability_id} to record is not held"))?;
    serde_json::to_writer(
        &mut lines,
        &json!({"capability": capability_id, "record": record}),
    )?;
    lines.push(b'\n');
    Ok(lines)
}

/// Append `lines` to the journal at `path`, which only its owner can read.
pub(super) fn append(path: &Path, lines: &[u8]) -> Result<()> {
    let mode = crate::core::vault::private_file_mode()?;
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("open capability journal {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .with_context(|| format!("make {} owner-only", path.display()))?;
    file.write_all(lines)
        .with_context(|| format!("append to capability journal {}", path.display()))?;
    file.sync_data()
        .with_context(|| format!("flush capability journal {}", path.display()))
}

/// Whether the bytes the journal at `path` carries beyond the live `state`
/// it replays to outweigh that state: the entries of capabilities that can
/// no longer be redeemed then hold more than the live ones, and the journal
/// is replaced by one snapshot of `state`.
pub(super) fn outweighed(path: &Path, state: &Value) -> Result<bool> {
    let held = fs::metadata(path)
        .with_context(|| format!("read the size of capability journal {}", path.display()))?
        .len();
    let live = u64::try_from(serde_json::to_vec(state)?.len())
        .context("the live capability state is larger than a file can hold")?;
    Ok(held.saturating_sub(live) > live)
}
