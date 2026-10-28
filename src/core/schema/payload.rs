// Building and checking one canonical payload: the fields a kind requires,
// the values it accepts, and reading one field back out.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use super::kinds::{declared, Declared, Field, Shape};
use super::IDENTITY_REFERENCE;
use super::{exact_component, ITEM_SCHEMA};

/// Whether `value` is the value `shape` declares.
fn holds(shape: Shape, value: &Value) -> bool {
    match shape {
        Shape::Text => value.is_string(),
        Shape::TextOrList => value.is_string() || value.is_array(),
        Shape::TextOrObject => value.is_string() || value.is_object(),
        Shape::Any => true,
    }
}

/// The fields of a kind that takes exactly `declared`: no other name, each
/// value the shape it declares, every required one present, and at least
/// one of each set the kind needs one of.
fn check_declared(kind: &str, declared: &[Field], fields: &Map<String, Value>) -> Result<()> {
    for (name, value) in fields {
        let Some(field) = declared.iter().find(|field| field.name == name.as_str()) else {
            bail!("field {name} is not allowed for {kind}");
        };
        if !holds(field.shape, value) {
            bail!("{kind} field {name} has an invalid value type");
        }
    }
    for field in declared {
        if field.required && !fields.contains_key(field.name) {
            bail!("{kind} payload requires fields.{}", field.name);
        }
        let Some(set) = field.one_of else {
            continue;
        };
        let members = declared.iter().filter(|member| member.one_of == Some(set));
        if !members.clone().any(|member| fields.contains_key(member.name)) {
            let named = members
                .map(|member| format!("fields.{}", member.name))
                .collect::<Vec<_>>()
                .join(", ");
            bail!("{kind} payload requires at least one {set}: {named}");
        }
    }
    Ok(())
}

pub fn validate_payload(payload: &Value, expected_kind: &str) -> Result<()> {
    let declared_fields = match declared(expected_kind) {
        Declared::Unknown => bail!("unsupported canonical item kind: {expected_kind}"),
        Declared::Open => None,
        Declared::Fields(fields) => Some(fields),
    };
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
    match declared_fields {
        Some(declared) => check_declared(expected_kind, declared, fields)?,
        None => {
            for name in fields.keys() {
                if !exact_component(name) {
                    bail!("invalid logical field name: {name}");
                }
            }
        }
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
    // `context.identity` is how a platform login says whose account it signs
    // in as. It names an `identity` item id, so it is checked here for shape
    // and in the vault write for existence: a reference to nothing would send
    // every later second-factor lookup to a row that is not there.
    if let Some(reference) = object
        .get("context")
        .and_then(|context| context.get(IDENTITY_REFERENCE))
    {
        let reference = reference
            .as_str()
            .with_context(|| format!("context.{IDENTITY_REFERENCE} must be an item id"))?;
        if !exact_component(reference) {
            bail!("context.{IDENTITY_REFERENCE} is not a valid item id: {reference}");
        }
        if expected_kind == "identity" {
            bail!("an identity cannot name another identity in context.{IDENTITY_REFERENCE}");
        }
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
    match declared(kind) {
        Declared::Fields(fields) => fields.iter().any(|field| field.name == name),
        Declared::Open | Declared::Unknown => exact_component(name),
    }
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
    matches!(declared(kind), Declared::Fields(fields) if fields.iter().any(|field| field.name == name))
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
