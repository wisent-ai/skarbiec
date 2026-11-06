// Second-factor recovery codes: how many one login or identity has left, and
// taking one so it is never offered twice. A recovery code is single-use at
// its provider; a vault that hands the same one out again hands out a code
// the provider already refused.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::{flag_set, OrUsage};
use crate::core::{vault::Vault, vault_path};

const RECOVERY_CODES: &str = "recovery_codes";

pub fn recovery_code_dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    let Some(positionals) = crate::cli::args::verb(command, positionals, "totp", "recovery") else {
        return Ok(None);
    };
    let id = positionals
        .first()
        .or_usage("usage: totp recovery <item-id> [--take | --replace]  (--replace reads the new codes on stdin, one per line)")?;
    if flag_set(flags, "take") && flag_set(flags, "replace") {
        return Err(crate::cli::args::Usage(
            "--take uses one code and --replace stores a new set; name one".to_string(),
        )
        .into());
    }
    if flag_set(flags, "take") {
        take(id).map(Some)
    } else if flag_set(flags, "replace") {
        let mut given = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut given)
            .context("the new recovery codes could not be read from standard input")?;
        replace(id, &given).map(Some)
    } else {
        count(id).map(Some)
    }
}

/// The codes one item stores, in order. A list is a list; one text holds
/// one code per line, the form an export pastes. Anything else is refused
/// naming its shape rather than read as none.
fn codes(id: &str, payload: &Value) -> Result<Vec<String>> {
    let stored = payload
        .get("fields")
        .and_then(|fields| fields.get(RECOVERY_CODES))
        .with_context(|| format!("{id} stores no {RECOVERY_CODES} field"))?;
    let listed: Vec<String> = match stored {
        Value::Array(listed) => listed
            .iter()
            .map(|code| {
                code.as_str()
                    .map(|code| code.trim().to_string())
                    .with_context(|| {
                        format!("{id}'s {RECOVERY_CODES} holds {code}, which is not text")
                    })
            })
            .collect::<Result<_>>()?,
        Value::String(text) => text.lines().map(|line| line.trim().to_string()).collect(),
        other => bail!("{id}'s {RECOVERY_CODES} is {other}, neither a list nor text"),
    };
    Ok(listed.into_iter().filter(|code| !code.is_empty()).collect())
}

/// `totp recovery <id>`: the number left, never a code.
fn count(id: &str) -> Result<Value> {
    let vault = Vault::open(vault_path())?;
    let remaining = codes(id, &vault.get_item(id)?)?.len();
    Ok(json!({"ok": true, "item": id, "remaining": remaining}))
}

/// `totp recovery <id> --take`: print the first code and store the item
/// without it as a new revision, so the next take offers the next code. The
/// list is written back as a list whatever form it was stored in.
fn take(id: &str) -> Result<Value> {
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "take a recovery code from")?;
    let mut payload = vault.get_item(id)?;
    let mut left = codes(id, &payload)?.into_iter();
    let Some(code) = left.next() else {
        bail!("{id} has no recovery code left; generate new ones at the provider and store them with totp recovery {id} --replace");
    };
    let left: Vec<String> = left.collect();
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{id} records no kind"))?
        .to_string();
    payload
        .get_mut("fields")
        .and_then(Value::as_object_mut)
        .with_context(|| format!("{id} has no fields object"))?
        .insert(RECOVERY_CODES.to_string(), json!(left));
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
    crate::runtime::audit::append(
        "recovery-code-taken",
        &json!({"item": id, "remaining": left.len()}),
    )?;
    Ok(json!({"ok": true, "item": id, "code": code, "remaining": left.len()}))
}

/// `totp recovery <id> --replace`: store the set a provider just issued,
/// one code per line, in place of whatever the item held. A provider that
/// issues new codes invalidates the old ones, so the old set is not kept
/// beside them; the saved versions still hold it. The codes are never
/// printed back.
pub fn replace(id: &str, given: &str) -> Result<Value> {
    let fresh: Vec<String> = given
        .lines()
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .map(str::to_string)
        .collect();
    if fresh.is_empty() {
        bail!("standard input held no recovery code; send the provider's new codes, one per line");
    }
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "replace the recovery codes of")?;
    let mut payload = vault.get_item(id)?;
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{id} records no kind"))?
        .to_string();
    if !crate::core::schema::kind_allows_field(&kind, RECOVERY_CODES) {
        bail!("a {kind} item has no {RECOVERY_CODES} field, so nothing was stored in {id}; a login or an identity holds them");
    }
    payload
        .get_mut("fields")
        .and_then(Value::as_object_mut)
        .with_context(|| format!("{id} has no fields object"))?
        .insert(RECOVERY_CODES.to_string(), json!(fresh));
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
    crate::runtime::audit::append(
        "recovery-codes-replaced",
        &json!({"item": id, "count": fresh.len()}),
    )?;
    Ok(json!({"ok": true, "item": id, "remaining": fresh.len()}))
}
