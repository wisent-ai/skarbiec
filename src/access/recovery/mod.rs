// Recovery + emergency access.
//
// Recovery: the recovery recipient is on every item (see core::vault), so
// losing the day-to-day identity never loses data — the offline recovery
// material still opens everything. `recovery-status` reports it.
//
// Emergency access: grant a registered user access that becomes active only at
// or after an operator-set timestamp, unless cancelled first. Activation shares
// every live item with the grantee by re-encrypting to include their identity.
// Timestamps are ISO-8601 and compared as strings (which sorts chronologically),
// so there is no numeric time arithmetic here.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::core::{vault::Vault, vault_path};

pub(super) fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

pub(super) fn now_iso() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub(super) fn ensure_section<'a>(
    doc: &'a mut Value,
    key: &str,
) -> &'a mut serde_json::Map<String, Value> {
    let object = doc.as_object_mut().expect("vault doc is object");
    object.entry(key).or_insert_with(|| json!({}));
    object
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("section is object")
}

mod drill;
mod emergency;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if let Some(answer) = drill::dispatch(command, flags, positionals)? {
        return Ok(Some(answer));
    }
    emergency::dispatch(command, flags, positionals)
}
