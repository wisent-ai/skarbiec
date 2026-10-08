// Recovery + emergency access.
//
// Recovery: the recovery recipient is on every item (see core::vault), so
// losing the day-to-day identity never loses data — the offline recovery
// material still opens everything. `recovery status` reports it.
//
// Emergency access: grant a registered user access that becomes active only at
// or after an operator-set timestamp, unless cancelled first. Activation shares
// every live item with the grantee by re-encrypting to include their identity.
// Timestamps are ISO-8601 and compared as strings (which sorts chronologically),
// so there is no numeric time arithmetic here.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{vault::Vault, vault_path};

pub(super) fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

pub(super) fn now_iso() -> String {
    crate::core::clock::now_iso()
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

/// `recovery status|drill` and `emergency list|grant|cancel|activate` are
/// groups: the object is the command and the verb its first positional. The
/// operator routes call the leaves by their whole name ("emergency grant").
pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if matches!(command, "recovery" | "emergency") {
        return group(command, flags, positionals).map(Some);
    }
    if let Some(answer) = drill::dispatch(command, flags, positionals)? {
        return Ok(Some(answer));
    }
    emergency::dispatch(command, flags, positionals)
}

fn group(object: &str, flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let Some((verb, positionals)) = positionals.split_first() else {
        return Err(crate::cli::args::Usage(format!(
            "{object} needs a subcommand; `skarbiec {object} help` lists them"
        ))
        .into());
    };
    if verb == "help" {
        return Ok(help(object));
    }
    let leaf = format!("{object} {verb}");
    let answer = if object == "recovery" {
        drill::dispatch(&leaf, flags, positionals)?
    } else {
        emergency::dispatch(&leaf, flags, positionals)?
    };
    answer.ok_or_else(|| {
        crate::cli::args::Usage(format!(
            "unknown {object} command: {verb}; `skarbiec {object} --help` lists them"
        ))
        .into()
    })
}

fn help(object: &str) -> Value {
    if object == "recovery" {
        return json!({
            "commands": [
                "recovery status",
                "recovery drill <recipient-uid|recovery>",
            ],
            "usage": "recovery status reports the vault's recovery recipient and whether its secret key is in this keyring; recovery drill proves that one expected recovery identity in an isolated keyring can open the vault.",
        });
    }
    json!({
        "commands": [
            "emergency list",
            "emergency grant <grantee> --activate-after <iso8601>",
            "emergency cancel <grantee>",
            "emergency activate <grantee>",
        ],
        "usage": "An emergency grant waits out its delay in the open: emergency grant records a pending grant for one recipient, emergency cancel withdraws it while it waits, emergency activate shares every live item with the grantee once it is due, and emergency list prints them all.",
    })
}
