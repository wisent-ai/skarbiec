// Whether a reauth actually produced the subscription it was run for: the
// named login item has to carry a live subscription record, not just a token.
//
// For every provider, not one of them. Until 2026-09-21 this required
// `brama:provider:codex` and the three field names a Codex grant happens to
// use, so a Claude Code or Kimi subscription reauth could never be confirmed
// however completely it had succeeded: the item was there, the grant was
// there, and the check answered no because the tag said another provider.
// Which provider a subscription is held with is what its own
// `brama:provider:` tag says, and what a grant looks like inside is the
// router's contract, not this vault's -- so the record is judged on being a
// subscription of some provider whose stored document carries credential
// material, and never on one provider's field names.

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
/// any provider.
pub(super) fn named_subscription_present(vault: &Vault, login_item: &str) -> bool {
    let login_tag = format!("brama:login:{login_item}");
    let Some(items) = vault.doc().get("items").and_then(Value::as_object) else {
        return false;
    };
    items.iter().any(|(item_id, record)| {
        if record
            .get("deleted_at")
            .is_some_and(|value| !value.is_null())
        {
            return false;
        }
        let tags = record
            .get("tags")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let tagged = |wanted: &str| tags.iter().any(|tag| tag.as_str() == Some(wanted));
        let declares_provider = tags.iter().filter_map(Value::as_str).any(|tag| {
            tag.strip_prefix("brama:provider:")
                .is_some_and(|provider| !provider.is_empty())
        });
        if !tagged("brama:subscription") || !declares_provider || !tagged(login_tag.as_str()) {
            return false;
        }
        let Ok(payload) = vault.get_item(item_id) else {
            return false;
        };
        let Some(stored) = payload
            .get("fields")
            .and_then(|fields| fields.get("value"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        serde_json::from_str::<Value>(stored)
            .is_ok_and(|grant| grant.is_object() && carries_material(&grant))
    })
}
