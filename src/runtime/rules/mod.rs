// `skarbiec password rules <id> [--set '<rules>' | --lookup | --clear]`: the
// password rules of the site a login signs in to, in the Password Rules
// language (https://developer.apple.com/password-rules/), kept in the login's
// encrypted context so `generate --rules-of <id>` — and a rotation that uses
// it — makes a value the site accepts. `--lookup` takes them from the list
// password managers share (`registry.rs`). Rules are checked by turning them
// into generator options before they are stored, so a rule the generator
// could not follow is refused when it is written, not on the day of a
// rotation.

mod registry;

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{flag_set, Usage};
use crate::core::items::PASSWORD_RULES;
use crate::core::{vault::Vault, vault_path};

const USAGE: &str = "usage: password rules <id> [--set '<rules>' | --lookup | --clear]";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let Some(rest) = crate::cli::args::verb(command, positionals, "password", "rules") else {
        return Ok(None);
    };
    let [id] = rest else {
        return Err(Usage(USAGE.to_string()).into());
    };
    let lookup = flag_set(flags, "lookup");
    let clear = flag_set(flags, "clear");
    let answer = match (flags.get("set"), lookup, clear) {
        (Some(rules), false, false) => set(id, rules)?,
        (None, true, false) => registry::lookup(id)?,
        (None, false, true) => crate::runtime::notes::set_context_text(
            id,
            PASSWORD_RULES,
            "",
            "clear the password rules of",
            "password-rules-cleared",
        )?,
        (None, false, false) => read(id)?,
        _ => {
            return Err(Usage(format!(
                "--set, --lookup and --clear each change the rules; give one. {USAGE}"
            ))
            .into())
        }
    };
    Ok(Some(answer))
}

/// The rules one item keeps, or null, with the generator options they ask
/// for so the reader sees what a generated value would be made of.
fn read(id: &str) -> Result<Value> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    let rules = payload
        .get("context")
        .and_then(|context| context.get(PASSWORD_RULES))
        .and_then(Value::as_str);
    let options = match rules {
        Some(text) => Some(crate::cli::generate::rule_options(text)?),
        None => None,
    };
    Ok(json!({"ok": true, "item": id, "password_rules": rules, "generator": options}))
}

pub(super) fn set(id: &str, rules: &str) -> Result<Value> {
    let trimmed = rules.trim();
    if trimmed.is_empty() {
        return Err(Usage(format!(
            "--set needs the rules; --clear removes them. {USAGE}"
        ))
        .into());
    }
    let options = crate::cli::generate::rule_options(trimmed)?;
    let mut answer = crate::runtime::notes::set_context_text(
        id,
        PASSWORD_RULES,
        trimmed,
        "set the password rules of",
        "password-rules-set",
    )?;
    answer["generator"] = json!(options);
    Ok(answer)
}
