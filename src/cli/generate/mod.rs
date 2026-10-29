// `generate`: a password or a passphrase nobody has to invent, printed, or
// with --into written straight into one field of one item so the value never
// passes through stdout, a shell variable or a pipe.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::{items, schema, vault_path};

use super::args::{emit, flag_set, OrUsage};

mod conform;
mod rules;

pub(crate) use conform::broken as rules_broken;

const PASSPHRASE_USAGE: &str =
    "usage: generate --passphrase --words N --separator TEXT [--capitalize] [--with-digit]";

pub(crate) fn cmd_generate(flags: &HashMap<String, String>) -> Result<()> {
    emit(&generate_value(flags)?)
}

/// The answer of `generate`: the value itself, or, with `--into`, the item
/// it was written into and never the value. `--rules` takes a site's
/// password rules and `--rules-of <id>` the rules a login keeps, and either
/// becomes the generator's options.
pub(crate) fn generate_value(given: &HashMap<String, String>) -> Result<Value> {
    let flags = &match (given.get("rules"), given.get("rules-of")) {
        (Some(_), Some(_)) => {
            return Err(super::args::Usage(
                "--rules and --rules-of both name rules; give one".to_string(),
            )
            .into())
        }
        (Some(text), None) => rules::options(text, given.clone())?,
        (None, Some(id)) => rules::options(&kept_rules(id)?, given.clone())?,
        (None, None) => given.clone(),
    };
    let (label, value) = if flag_set(flags, "passphrase") {
        let count: usize = flags
            .get("words")
            .or_usage(PASSPHRASE_USAGE)?
            .parse()
            .or_usage("--words must be a number")?;
        // What joins the words is the caller's choice, as the count is.
        let sep = flags.get("separator").or_usage(PASSPHRASE_USAGE)?;
        // A site that asks for an upper-case letter or a digit gets one
        // without giving up the words: each word capitalized, one random
        // digit after the last.
        let phrase = items::generate_passphrase(
            count,
            sep,
            flag_set(flags, "capitalize"),
            flag_set(flags, "with-digit"),
        )?;
        ("passphrase", phrase)
    } else {
        let length: usize = flags
            .get("length")
            .or_usage("usage: generate --length N [--lower] [--upper] [--digits] [--symbols | --symbols-from <chars>] [--unambiguous]")?
            .parse()
            .or_usage("--length must be a number")?;
        let password = items::generate_password(
            length,
            flag_set(flags, "lower"),
            flag_set(flags, "upper"),
            flag_set(flags, "digits"),
            flag_set(flags, "symbols"),
            flags.get("symbols-from").map(String::as_str),
            flag_set(flags, "unambiguous"),
        )?;
        ("password", password)
    };
    match flags.get("into") {
        Some(id) => store_generated(flags, id, &value),
        None => {
            let mut answer = serde_json::Map::new();
            answer.insert(label.to_string(), json!(value));
            Ok(Value::Object(answer))
        }
    }
}

/// The password rules one login keeps under its context's `password_rules`.
fn kept_rules(id: &str) -> Result<String> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    match payload
        .get("context")
        .and_then(|context| context.get(items::PASSWORD_RULES))
        .and_then(Value::as_str)
    {
        Some(text) => Ok(text.to_string()),
        None => bail!("{id} keeps no password rules; `skarbiec password rules {id} --set '<rules>'` records the site's"),
    }
}

/// The generator options a site's password rules ask for, alone; a rule the
/// generator cannot follow is refused naming it.
pub(crate) fn rule_options(text: &str) -> Result<HashMap<String, String>> {
    rules::options(text, HashMap::new())
}

/// `generate ... --into <id> --field <field>`: replace one field of one
/// owner-controlled item with the value just generated, so the value never
/// passes through stdout, a shell variable or a pipe on its way into the
/// vault. The answer names the item, the field and the new revision, never
/// the value. The policy's rules are checked before anything is written.
fn store_generated(flags: &HashMap<String, String>, id: &str, value: &str) -> Result<Value> {
    let field = flags
        .get("field")
        .or_usage("--into <id> needs --field <field>, the field the generated value replaces")?;
    if field == "context" {
        return Err(super::args::Usage(
            "--field context names the item's context, not a secret field; name the field the generated value replaces".to_string(),
        )
        .into());
    }
    let verdict = crate::access::policy::check(value)?;
    if verdict["ok"] != json!(true) {
        bail!(
            "the generated value does not clear the vault policy ({}); nothing was stored in {id}. Generate a longer value",
            verdict["rules"]
        );
    }
    let mut vault = Vault::open(vault_path())?;
    super::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    let mut payload = vault.get_item(id)?;
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{id} records no kind"))?
        .to_string();
    if !schema::kind_allows_field(&kind, field) {
        bail!("a {kind} item has no field {field}, so nothing was stored in {id}; name a field its kind declares");
    }
    payload
        .get_mut("fields")
        .and_then(Value::as_object_mut)
        .with_context(|| format!("{id} has no fields object"))?
        .insert(field.clone(), json!(value));
    let recipients = vault.item_recipient_uids(id)?;
    let tags = {
        let entry = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        crate::core::vault::entry_texts(id, entry, "tags")?
    };
    vault.set_item(id, &kind, &payload, &recipients, &tags)?;
    let revision = vault.item_revision(id)?;
    crate::runtime::audit::append(
        "generate-into",
        &json!({"item": id, "field": field, "revision": revision}),
    )?;
    Ok(json!({"ok": true, "item": id, "field": field, "revision": revision}))
}
