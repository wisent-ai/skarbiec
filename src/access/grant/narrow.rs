// Narrowing a grant: the inverse of `grant ensure`. One exact field read is
// taken out of a consumer's grant; the rest of the grant, its bearer and its
// lifetime are left as they were.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::lookup::load;
use super::rules::capabilities::parse_capabilities;
use super::rules::validation::{exact_component, exact_resource};
use crate::core::vault_path;

/// Remove `read:<item>#<field>` from `consumer`'s grant. A consumer without a
/// grant is refused by name; a grant that does not hold the capability is
/// reported `absent` and the vault is not written, so a repeated narrow
/// changes nothing.
pub(in crate::access::grant) fn narrow_read_once(
    consumer: &str,
    item: &str,
    field: &str,
) -> Result<Value> {
    if !exact_component(consumer) || !exact_resource(item) || !exact_component(field) {
        bail!("grant narrow requires exact consumer, item, and field names");
    }
    let mut vault = load()?;
    let mut requested = parse_capabilities(&vault, &format!("read:{item}#{field}"), &[])?;
    let capability = requested
        .pop()
        .context("grant narrow produced no capability")?;
    let capabilities = vault
        .doc_mut()
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .and_then(|tokens| tokens.get_mut(consumer))
        .with_context(|| format!("consumer {consumer} has no grant in {}", vault_path().display()))?
        .get_mut("capabilities")
        .and_then(Value::as_array_mut)
        .context("existing grant is not v2; run migrate-v2 first")?;
    let before = capabilities.len();
    capabilities.retain(|held| held != &capability);
    let status = if capabilities.len() == before {
        "absent"
    } else {
        vault.save()?;
        crate::runtime::audit::append(
            "grant-narrowed-read",
            &json!({
                "consumer": consumer,
                "item": item,
                "field": field,
            }),
        )?;
        "removed"
    };
    Ok(json!({
        "ok": true,
        "consumer": consumer,
        "capability": capability,
        "status": status,
        "decided_against_vault": vault_path().display().to_string(),
    }))
}
