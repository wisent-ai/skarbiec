// What one item declares it carries: the credential field a provider route
// reads, and the fields a login exports under their canonical names.

use super::super::values::login_fields;
use super::{items, live, Target, CREDENTIAL_FIELDS, LOGIN_KIND};
use crate::core::vault::Vault;
use serde_json::Value;

/// The one credential field an item declares, or the sentence saying why it
/// declares none this can act on.
pub(in crate::access::route) fn credential_field(
    vault: &Vault,
    item: &str,
) -> Result<String, String> {
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
/// An item that records no kind is refused as declaring none, not as one
/// declaring an empty kind.
pub(in crate::access::route) fn login_targets(
    vault: &Vault,
    item: &str,
) -> Result<Vec<Target>, String> {
    let record = items(vault)
        .and_then(|items| items.get(item))
        .filter(|record| live(record))
        .ok_or_else(|| format!("no vault item {item}"))?;
    let kind = record.get("kind").and_then(Value::as_str).ok_or_else(|| {
        format!(
            "vault item {item} declares no kind: only a {LOGIN_KIND} declares the fields a sign-in exports"
        )
    })?;
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
