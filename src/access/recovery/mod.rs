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

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{vault::Vault, vault_path};

pub(super) fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

pub(super) fn now_iso() -> String {
    crate::core::clock::now_iso()
}

/// The vault's `key` section, created empty when the vault has none. A vault
/// document or section that is not a JSON object is refused naming it,
/// never a panic of the process serving every consumer.
pub(super) fn ensure_section<'a>(
    doc: &'a mut Value,
    key: &str,
) -> Result<&'a mut serde_json::Map<String, Value>> {
    let object = doc.as_object_mut().context("the vault document is not a JSON object")?;
    match object.entry(key).or_insert_with(|| json!({})) {
        Value::Object(section) => Ok(section),
        other => bail!("the vault's {key} section is not a JSON object: {other}"),
    }
}

mod drill;
mod emergency;

/// `recovery status|drill` and `emergency list|grant|cancel|activate|revoke`
/// are groups: the object is the command and the verb its first positional.
/// The operator routes call the leaves by their whole name ("emergency
/// grant"). Each module names its own object, answers its own leaves and
/// writes its own help, so a verb added to one module is listed where it is
/// implemented.
struct Group {
    object: &'static str,
    leaves: fn(&str, &HashMap<String, String>, &[String]) -> Result<Option<Value>>,
    help: fn() -> Value,
}

const GROUPS: &[Group] = &[
    Group {
        object: drill::GROUP,
        leaves: drill::dispatch,
        help: drill::help,
    },
    Group {
        object: emergency::GROUP,
        leaves: emergency::dispatch,
        help: emergency::help,
    },
];

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    // `keys check` is a leaf of the recovery group's, under the keys noun:
    // whether any key on this machine still opens the vault.
    if let Some(rest) = crate::cli::args::verb(command, positionals, "keys", "check") {
        return drill::dispatch("keys check", flags, rest);
    }
    for group in GROUPS {
        if command == group.object {
            return run_group(group, flags, positionals).map(Some);
        }
        if let Some(answer) = (group.leaves)(command, flags, positionals)? {
            return Ok(Some(answer));
        }
    }
    Ok(None)
}

fn run_group(group: &Group, flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let object = group.object;
    let Some((verb, positionals)) = positionals.split_first() else {
        return Err(crate::cli::args::Usage(format!(
            "{object} needs a subcommand; `skarbiec {object} help` lists them"
        ))
        .into());
    };
    if verb == "help" {
        return Ok((group.help)());
    }
    let leaf = format!("{object} {verb}");
    (group.leaves)(&leaf, flags, positionals)?.ok_or_else(|| {
        crate::cli::args::Usage(format!(
            "unknown {object} command: {verb}; `skarbiec {object} --help` lists them"
        ))
        .into()
    })
}
