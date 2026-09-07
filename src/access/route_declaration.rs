// What the vault declares about itself, and which coordinate a resource name
// therefore resolves to.
//
// An item id is a mutable, human-chosen name. Discovery that reads meaning out
// of one is the defect this module exists to end: a `provider:` prefix electing
// which items become routes, an `-agent-auth` suffix electing an agent's
// signing credential, a `-primary` suffix electing a provider default. Each of
// them silently changed behaviour on a rename with nothing raised anywhere --
// which is how Brama came to show one subscription where four existed.
//
// So a credential joins the provider vocabulary by declaring `brama:provider:`
// and, for one subscription among several, `brama:id:`; an agent signing
// identity is an `internal-authority` item whose own `id` field names the agent
// and whose `agent_auth_secret` is the credential; a login declares its fields
// through its kind. Rename any of those items and the same name resolves to the
// same credential, because the declaration travels inside the item.
//
// Only a resource no item can express -- `origin:<page origin>/<field class>`,
// a sign-in form's own name for itself -- is answered from the hand-declared
// table, by exact id, where a rename fails loudly instead of quietly.

use super::route_values::login_fields;
use crate::core::schema::{exact_token, MAX_NAME_CHARS};
use crate::core::vault::Vault;
use serde_json::{json, Map, Value};

// The tag vocabulary Brama's gateway and its desktop console already decide
// item identity by. Reading a declared tag is not reading a name: the tag is a
// classification an operator wrote down, and renaming the item does not touch
// it. Both namespaces are registered in this binary's own tag registry.
const PROVIDER_TAG: &str = "brama:provider:";
const SUBSCRIPTION_TAG: &str = "brama:id:";

// The one canonical kind whose schema declares an agent signing identity:
// `fields.id` names the Brama agent and `fields.agent_auth_secret` is its
// credential, both first-class in `core::schema`. Every other kind either
// forbids those fields outright or is a free-form dump that declares nothing.
const AGENT_IDENTITY_KIND: &str = "internal-authority";
const AGENT_SECRET_FIELD: &str = "agent_auth_secret";
const LOGIN_KIND: &str = "login";

pub(super) const PROVIDER_PREFIX: &str = "provider:";
pub(super) const AGENT_PREFIX: &str = "agent:";
pub(super) const LOGIN_PREFIX: &str = "login:";

// The fields a provider credential can carry its secret in. A kind states the
// shape, so the field is read from the item rather than assumed; an item
// carrying two of them is ambiguous and this never chooses for the operator.
const CREDENTIAL_FIELDS: &[&str] = &[
    "api_key",
    "token",
    "access_token",
    "apiKey",
    "key",
    "secret",
    "value",
];

/// One coordinate a name resolves to, before the vault is asked about it.
pub(super) struct Target {
    pub(super) item: String,
    pub(super) field: String,
    /// The canonical exported variable name, for the login fields that have
    /// one. Absent for a single-field credential, which is exported under the
    /// name its caller chose.
    pub(super) exported: Option<&'static str>,
    /// Which declaration answered: the item's tags, its own fields, its kind,
    /// the name itself, or the hand-declared table.
    pub(super) declared_by: &'static str,
    pub(super) item_uid: Option<String>,
}

/// One resolved route, with the vault's answer beside it.
pub(crate) struct Row {
    pub(crate) resource: String,
    pub(crate) item: String,
    pub(crate) field: String,
    pub(crate) exported: Option<&'static str>,
    pub(crate) declared_by: &'static str,
    pub(crate) item_present: bool,
    pub(crate) field_present: bool,
    pub(crate) problem: Option<String>,
}

impl Row {
    pub(crate) fn as_json(&self) -> Value {
        let mut row = Map::new();
        row.insert("resource".to_string(), json!(self.resource));
        row.insert("item".to_string(), json!(self.item));
        row.insert("field".to_string(), json!(self.field));
        row.insert("declared_by".to_string(), json!(self.declared_by));
        row.insert("item_present".to_string(), json!(self.item_present));
        row.insert("field_present".to_string(), json!(self.field_present));
        if let Some(exported) = self.exported {
            row.insert("exported".to_string(), json!(exported));
        }
        if let Some(problem) = &self.problem {
            row.insert("problem".to_string(), json!(problem));
        }
        Value::Object(row)
    }
}

fn items(vault: &Vault) -> Option<&Map<String, Value>> {
    vault.doc().get("items").and_then(Value::as_object)
}

fn live(record: &Value) -> bool {
    record.get("state").and_then(Value::as_str) != Some("trashed")
}

/// Values an item declares under one tag prefix. The prefix is this product's
/// and Brama's own vocabulary; the value after it is the declaration itself,
/// not a name this crate minted or may rewrite.
fn declared_tags<'a>(record: &'a Value, prefix: &str) -> Vec<&'a str> {
    record
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .filter_map(|tag| tag.strip_prefix(prefix))
                .collect()
        })
        .unwrap_or_default()
}

/// Every item declaring exactly one provider, with the subscription id it
/// declares when it declares one. An item declaring two of either is ambiguous
/// and is reported by [`ambiguous`] rather than picked from.
pub(super) fn provider_items(vault: &Vault) -> Vec<(&str, &str, Option<&str>)> {
    let Some(items) = items(vault) else {
        return Vec::new();
    };
    let mut declared: Vec<(&str, &str, Option<&str>)> = items
        .iter()
        .filter(|(_, record)| live(record))
        .filter_map(|(item, record)| {
            let providers = declared_tags(record, PROVIDER_TAG);
            let [provider] = providers[..] else {
                return None;
            };
            if !exact_token(provider, MAX_NAME_CHARS) {
                return None;
            }
            let ids = declared_tags(record, SUBSCRIPTION_TAG);
            let subscription = match ids[..] {
                [] => None,
                [id] if exact_token(id, MAX_NAME_CHARS) => Some(id),
                _ => return None,
            };
            Some((item.as_str(), provider, subscription))
        })
        .collect();
    declared.sort();
    declared
}

/// Items whose declaration cannot be acted on, and why. Reported rather than
/// dropped: an item that silently declares nothing is the failure this whole
/// capability replaces.
pub(super) fn ambiguous(vault: &Vault) -> Vec<Value> {
    let Some(items) = items(vault) else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    for (item, record) in items.iter().filter(|(_, record)| live(record)) {
        let providers = declared_tags(record, PROVIDER_TAG);
        if providers.len() > 1 {
            problems.push(json!({
                "item": item,
                "problem": format!("item declares {} provider tags: {}", providers.len(), providers.join(", ")),
            }));
            continue;
        }
        if providers
            .iter()
            .any(|value| !exact_token(value, MAX_NAME_CHARS))
        {
            problems
                .push(json!({"item": item, "problem": "declared provider is not an exact name"}));
            continue;
        }
        let ids = declared_tags(record, SUBSCRIPTION_TAG);
        if ids.len() > 1 {
            problems.push(json!({
                "item": item,
                "problem": format!("item declares {} subscription ids: {}", ids.len(), ids.join(", ")),
            }));
        } else if ids.iter().any(|value| !exact_token(value, MAX_NAME_CHARS)) {
            problems.push(
                json!({"item": item, "problem": "declared subscription id is not an exact name"}),
            );
        }
    }
    problems
}

/// Every agent signing identity the vault declares: an `internal-authority`
/// item carrying `agent_auth_secret` whose own `id` field names the agent.
pub(super) fn agent_items(vault: &Vault, agent: Option<&str>) -> Vec<(String, String)> {
    let Some(items) = items(vault) else {
        return Vec::new();
    };
    let mut declared: Vec<(String, String)> = items
        .iter()
        .filter(|(_, record)| {
            live(record) && record.get("kind").and_then(Value::as_str) == Some(AGENT_IDENTITY_KIND)
        })
        .filter_map(|(item, _)| {
            let payload = vault.get_item(item).ok()?;
            let fields = payload.get("fields").and_then(Value::as_object)?;
            fields.get(AGENT_SECRET_FIELD).and_then(Value::as_str)?;
            let declared = fields
                .get("id")
                .and_then(Value::as_str)
                .filter(|value| exact_token(value, MAX_NAME_CHARS))?;
            if agent.is_some_and(|needle| needle != declared) {
                return None;
            }
            Some((declared.to_string(), item.clone()))
        })
        .collect();
    declared.sort();
    declared
}

/// The one credential field an item declares, or the sentence saying why it
/// declares none this can act on.
pub(super) fn credential_field(vault: &Vault, item: &str) -> Result<String, String> {
    let payload = vault.get_item(item).map_err(|error| error.to_string())?;
    let fields = payload
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("vault item {item} carries no fields object"))?;
    let candidates: Vec<&str> = CREDENTIAL_FIELDS
        .iter()
        .copied()
        .filter(|name| fields.get(*name).is_some_and(Value::is_string))
        .collect();
    match candidates[..] {
        [field] => Ok(field.to_string()),
        _ => Err(format!(
            "vault item {item} declares {} credential fields: {}",
            candidates.len(),
            candidates.join(", ")
        )),
    }
}

/// The fields one login item declares, under their canonical exported names.
pub(super) fn login_targets(vault: &Vault, item: &str) -> Result<Vec<Target>, String> {
    let record = items(vault)
        .and_then(|items| items.get(item))
        .filter(|record| live(record))
        .ok_or_else(|| format!("no vault item {item}"))?;
    let kind = record
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if kind != LOGIN_KIND {
        return Err(format!(
            "vault item {item} declares kind {kind}, not {LOGIN_KIND}: only a {LOGIN_KIND} declares the fields a sign-in exports"
        ));
    }
    let payload = vault.get_item(item).map_err(|error| error.to_string())?;
    let fields = payload
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("vault item {item} carries no fields object"))?;
    let targets: Vec<Target> = login_fields()
        .iter()
        .filter(|(field, _)| fields.contains_key(*field))
        .map(|(field, exported)| Target {
            item: item.to_string(),
            field: (*field).to_string(),
            exported: Some(*exported),
            declared_by: "kind",
            item_uid: None,
        })
        .collect();
    if targets.is_empty() {
        return Err(format!("vault item {item} declares no {LOGIN_KIND} field"));
    }
    Ok(targets)
}
