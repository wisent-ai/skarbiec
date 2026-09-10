// Building and checking one canonical payload: the fields a kind requires,
// the values it accepts, and reading one field back out.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use super::kinds::{allowed_fields, supported_kind};
use super::{exact_component, ITEM_SCHEMA};

fn required(fields: &Map<String, Value>, names: &[&str], kind: &str) -> Result<()> {
    for name in names {
        if !fields.contains_key(*name) {
            bail!("{kind} payload requires fields.{name}");
        }
    }
    Ok(())
}

fn valid_field_value(kind: &str, name: &str, value: &Value) -> bool {
    if matches!(
        kind,
        "stado-secret"
            | "internal-authority"
            | "credential-operation"
            | "credential-directory-seal"
            | "bundle"
    ) {
        return true;
    }
    match name {
        "ports" | "recovery_codes" | "chain" => value.is_array() || value.is_string(),
        "credential_json" => value.is_object() || value.is_string(),
        _ => value.is_string(),
    }
}

pub fn validate_payload(payload: &Value, expected_kind: &str) -> Result<()> {
    if !supported_kind(expected_kind) {
        bail!("unsupported canonical item kind: {expected_kind}");
    }
    let object = payload
        .as_object()
        .context("canonical item payload must be an object")?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "schema" | "kind" | "fields" | "context" | "extensions"
        ) {
            bail!("unknown canonical item property: {key}");
        }
    }
    if object.get("schema").and_then(Value::as_str) != Some(ITEM_SCHEMA) {
        bail!("canonical item schema must be {ITEM_SCHEMA}");
    }
    if object.get("kind").and_then(Value::as_str) != Some(expected_kind) {
        bail!("payload kind does not match the item envelope kind");
    }
    let fields = object
        .get("fields")
        .and_then(Value::as_object)
        .context("canonical item fields must be an object")?;
    if fields.is_empty() {
        bail!("canonical item fields cannot be empty");
    }
    if let Some(allowed) = allowed_fields(expected_kind) {
        for (name, value) in fields {
            if !allowed.contains(&name.as_str()) {
                bail!("field {name} is not allowed for {expected_kind}");
            }
            if !valid_field_value(expected_kind, name, value) {
                bail!("{expected_kind} field {name} has an invalid value type");
            }
        }
    } else {
        for name in fields.keys() {
            if !exact_component(name) {
                bail!("invalid logical field name: {name}");
            }
        }
    }
    match expected_kind {
        "note" => required(fields, &["value"], expected_kind)?,
        "login" => {
            required(fields, &["username"], expected_kind)?;
            if !["password", "totp_secret", "recovery_codes"]
                .iter()
                .any(|name| fields.contains_key(*name))
            {
                bail!("login payload requires at least one authentication factor");
            }
        }
        // Both fields are required because a host account with only a username is
        // not a credential, and one with only a password cannot say who it is.
        "host-account" => required(fields, &["username", "password"], expected_kind)?,
        "api-key" => required(fields, &["api_key"], expected_kind)?,
        "access-key" => required(
            fields,
            &["access_key_id", "secret_access_key"],
            expected_kind,
        )?,
        "token" => required(fields, &["token"], expected_kind)?,
        "oauth-client" => required(fields, &["client_id", "client_secret"], expected_kind)?,
        "proxy" => required(fields, &["username", "password"], expected_kind)?,
        "key-pair" => required(fields, &["private_key"], expected_kind)?,
        "certificate" => required(fields, &["certificate", "private_key"], expected_kind)?,
        "service-account" => required(fields, &["credential_json"], expected_kind)?,
        "credential-operation" | "credential-directory-seal" => {
            required(fields, &["value"], expected_kind)?;
        }
        "stado-secret" | "internal-authority" | "bundle" => {}
        _ => unreachable!(),
    }
    if object.get("context").and_then(Value::as_object).is_none() {
        bail!("canonical item context must be an object");
    }
    // A machine account that does not name its host and its user cannot be matched
    // back to a registry target, and an unmatchable credential is precisely the
    // sort of declaration nothing ever reads. Demand the naming at write time.
    if expected_kind == "host-account"
        && !object
            .get("context")
            .and_then(|context| context.get("account_ref"))
            .and_then(Value::as_str)
            .is_some_and(|reference| reference.contains('@'))
    {
        bail!("host-account payload requires context.account_ref naming <user>@<host>");
    }
    if object
        .get("extensions")
        .is_some_and(|extensions| !extensions.is_object())
    {
        bail!("canonical item extensions must be an object");
    }
    Ok(())
}

pub fn payload(
    kind: &str,
    fields: Map<String, Value>,
    context: Map<String, Value>,
) -> Result<Value> {
    let value = json!({
        "schema": ITEM_SCHEMA,
        "kind": kind,
        "fields": fields,
        "context": context,
    });
    validate_payload(&value, kind)?;
    Ok(value)
}

pub fn fields(payload: &Value) -> Result<&Map<String, Value>> {
    payload
        .get("fields")
        .and_then(Value::as_object)
        .context("canonical item has no fields object")
}


/// Whether a kind permits a field, asked of the kind alone.
///
/// The envelope carries `kind` in cleartext beside the ciphertext, so a reader
/// that only needs to know whether a name is permissible -- rather than
/// whether a value is present -- can answer without opening the item. That is
/// what lets the access-plane diagnosis walk every grant in the vault without
/// spawning one gpg per item, and lets it still answer when gpg is the thing
/// that is broken.
pub fn kind_allows_field(kind: &str, name: &str) -> bool {
    if name == "context" {
        return true;
    }
    allowed_fields(kind)
        .map(|allowed| allowed.contains(&name))
        .unwrap_or_else(|| exact_component(name))
}

/// Whether a kind's own field list NAMES this field.
///
/// Deliberately distinct from [`kind_allows_field`], which answers "is this
/// name permissible" and falls back to a syntactic check for any kind that
/// declares no list at all — so a `bundle` *allows* `totp_secret` without ever
/// declaring it. A diagnostic asking "does this row declare a seed field"
/// needs the declaration, not the absence of a prohibition; treating the two
/// as the same reported a bundle as a login row missing its seed.
pub fn kind_declares_field(kind: &str, name: &str) -> bool {
    allowed_fields(kind).is_some_and(|allowed| allowed.contains(&name))
}

pub fn allows_field(payload: &Value, name: &str) -> bool {
    if name == "context" {
        return true;
    }
    let Some(kind) = payload.get("kind").and_then(Value::as_str) else {
        return false;
    };
    kind_allows_field(kind, name)
}

pub fn field<'a>(payload: &'a Value, name: &str) -> Result<&'a Value> {
    if name == "context" {
        return payload
            .get("context")
            .context("canonical item has no context field");
    }
    fields(payload)?
        .get(name)
        .with_context(|| format!("canonical item has no field: {name}"))
}
