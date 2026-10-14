// Whether a reauth actually produced the subscription it was run for: the
// named login item has to carry a live subscription record, not just a token.
//
// For every provider, not one of them. A check that required one provider's
// tag and the field names that provider's grant happens to use could never
// confirm another provider's reauth however completely it had succeeded.
// Which provider a subscription is held with is what its own
// `brama:provider:` tag says, and what a grant looks like inside is the
// router's contract, not this vault's -- so the record is judged on being a
// subscription of some provider whose stored document carries credential
// material, and never on one provider's field names.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::core::vault::Vault;

/// Whether one stored document carries credential material: a JSON object
/// with a non-empty string somewhere inside it.
///
/// Deliberately not a field list. A sign-in descriptor, an account record and
/// an empty envelope are all JSON, and none of them is a grant; every
/// provider's grant, whatever it names its tokens, has text in it.
fn carries_material(value: &Value) -> bool {
    match value {
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(values) => values.iter().any(carries_material),
        Value::Object(fields) => fields.values().any(carries_material),
        _ => false,
    }
}

/// Whether the login item named by a reauth now backs a live subscription of
/// any provider. A subscription record tagged for this login whose payload
/// cannot be decrypted is the error, naming it: read as absent it would mark
/// a completed reauth unconfirmed with no cause.
pub(super) fn named_subscription_present(vault: &Vault, login_item: &str) -> Result<bool> {
    let login_tag = format!("brama:login:{login_item}");
    let Some(items) = vault.doc().get("items").and_then(Value::as_object) else {
        return Ok(false);
    };
    for (item_id, record) in items {
        if record
            .get("deleted_at")
            .is_some_and(|value| !value.is_null())
        {
            continue;
        }
        // A record with no tag list carries no subscription tag either.
        let Some(tags) = record.get("tags").and_then(Value::as_array) else {
            continue;
        };
        let tagged = |wanted: &str| tags.iter().any(|tag| tag.as_str() == Some(wanted));
        let declares_provider = tags.iter().filter_map(Value::as_str).any(|tag| {
            tag.strip_prefix("brama:provider:")
                .is_some_and(|provider| !provider.is_empty())
        });
        if !tagged("brama:subscription") || !declares_provider || !tagged(login_tag.as_str()) {
            continue;
        }
        let payload = vault.get_item(item_id).with_context(|| {
            format!("subscription {item_id} for login {login_item} cannot be read, so the reauth cannot be confirmed")
        })?;
        let Some(stored) = payload
            .get("fields")
            .and_then(|fields| fields.get("value"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if serde_json::from_str::<Value>(stored)
            .is_ok_and(|grant| grant.is_object() && carries_material(&grant))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
