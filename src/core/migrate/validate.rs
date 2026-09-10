// Reading the migrated vault back: every item, every revision and every
// grant has to be canonical before the migration is called done.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::items::revision_payload;
use super::patterns::{exact_resource, future_contract_field, supported_action};
use crate::core::vault::Vault;
use crate::core::schema;

pub(super) fn validate_v2(vault: &Vault) -> Result<()> {
    let items = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .context("vault items section is not an object")?;
    for (id, item) in items {
        if item.get("format").and_then(Value::as_u64)
            != Some(crate::core::vault::current_envelope())
        {
            bail!("{id} is not a v2 envelope");
        }
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .context("v2 item has no kind")?;
        let current = item
            .get("current")
            .and_then(Value::as_object)
            .context("v2 item has no current revision")?;
        if current.get("kind").and_then(Value::as_str) != Some(kind) {
            bail!("{id} current revision kind differs from its envelope");
        }
        let current_value = Value::Object(current.clone());
        let payload = revision_payload(&current_value)?;
        schema::validate_payload(&payload, kind)?;
        let management = item
            .get("management")
            .and_then(Value::as_object)
            .context("v2 item has no management object")?;
        let mode = management
            .get("mode")
            .and_then(Value::as_str)
            .context("v2 item management has no mode")?;
        if !matches!(mode, "owner" | "managed" | "external") {
            bail!("{id} has an invalid management mode");
        }
        let controller = management
            .get("controller")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("v2 item management has no controller")?;
        // Both families the credential lifecycle writes carry the same managed
        // authority; a stored record claiming either kind without it did not
        // come from the lifecycle.
        if matches!(kind, "credential-operation" | "credential-directory-seal")
            && (mode != "managed" || controller != "skarbiec-credential-lifecycle")
        {
            bail!("{id} credential record is not lifecycle-managed");
        }
        let mut previous_revision = u64::MIN;
        for revision in item
            .get("history")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(std::iter::once(&current_value))
        {
            let number = revision
                .get("revision")
                .and_then(Value::as_u64)
                .context("v2 revision has no number")?;
            if number <= previous_revision {
                bail!("{id} revisions are not strictly increasing");
            }
            previous_revision = number;
            let revision_kind = revision
                .get("kind")
                .and_then(Value::as_str)
                .context("v2 revision has no kind")?;
            let revision_payload = revision_payload(revision)?;
            schema::validate_payload(&revision_payload, revision_kind)?;
        }
        if item.get("revision").and_then(Value::as_u64) != Some(previous_revision) {
            bail!("{id} envelope revision does not match current revision");
        }
    }
    let tokens = vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .context("vault tokens section is not an object")?;
    for (consumer, entry) in tokens {
        if entry.get("scopes").is_some() || entry.get("acquisition_scopes").is_some() {
            bail!("{consumer} retains legacy scopes");
        }
        let capabilities = entry
            .get("capabilities")
            .and_then(Value::as_array)
            .context("v2 grant has no capabilities array")?;
        let has_acquire = capabilities
            .iter()
            .any(|capability| capability.get("action").and_then(Value::as_str) == Some("acquire"));
        if has_acquire
            && entry
                .get("workload_public_key")
                .and_then(Value::as_str)
                .is_none()
        {
            bail!("{consumer} acquire grant has no workload public key");
        }
        if capabilities.iter().any(|capability| {
            capability
                .get("action")
                .and_then(Value::as_str)
                .is_some_and(|action| !supported_action(action))
        }) {
            bail!("{consumer} has an unsupported capability action");
        }
        if has_acquire
            && capabilities.iter().any(|capability| {
                capability.get("action").and_then(Value::as_str) != Some("acquire")
            })
        {
            bail!("{consumer} mixes acquisition and direct capabilities");
        }
        for capability in capabilities {
            let action = capability
                .get("action")
                .and_then(Value::as_str)
                .context("capability has no action")?;
            let item = capability
                .get("item")
                .and_then(Value::as_str)
                .context("capability has no exact item")?;
            if !exact_resource(item) || item.contains('*') || item.contains('?') {
                bail!("{consumer} has a non-exact capability resource");
            }
            let field = capability.get("field").and_then(Value::as_str);
            if matches!(action, "acquire" | "stage" | "rotate" | "verify") && field.is_none() {
                bail!("{consumer} field action has no exact field");
            }
            if let Some(field) = field {
                if let Some(current) = items.get(item).and_then(|entry| entry.get("current")) {
                    let payload = revision_payload(current)?;
                    if schema::field(&payload, field).is_err() {
                        bail!("{consumer} capability names a missing field");
                    }
                } else if future_contract_field(item, Some(field)) != Some(field) {
                    bail!("{consumer} field capability item has no canonical contract");
                }
                if field == "context" && action != "read" {
                    bail!("{consumer} mutation capability targets context metadata");
                }
            } else if matches!(action, "share" | "trash" | "purge" | "admin")
                && !items.contains_key(item)
            {
                bail!("{consumer} item action names a missing item");
            }
        }
    }
    Ok(())
}
