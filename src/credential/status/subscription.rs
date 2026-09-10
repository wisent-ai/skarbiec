// Whether a reauth actually produced the subscription it was run for: the
// named login item has to carry a live subscription record, not just a token.

use serde_json::Value;

use crate::core::vault::Vault;

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
        if !tagged("brama:subscription")
            || !tagged("brama:provider:codex")
            || !tagged(login_tag.as_str())
        {
            return false;
        }
        let Ok(payload) = vault.get_item(item_id) else {
            return false;
        };
        let Some(auth_text) = payload
            .get("fields")
            .and_then(|fields| fields.get("value"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        let Ok(auth) = serde_json::from_str::<Value>(auth_text) else {
            return false;
        };
        let Some(tokens) = auth.get("tokens") else {
            return false;
        };
        ["access_token", "id_token", "account_id"]
            .iter()
            .all(|field| {
                tokens
                    .get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
    })
}
