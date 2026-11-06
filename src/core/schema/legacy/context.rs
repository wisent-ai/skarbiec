// The fields a legacy item kept beside its secret (provider, account, the
// Weles request that wrote it), moved into the canonical item's context, and
// the warning an item carries when its legacy shape could not be kept as
// written.

use serde_json::{json, Map, Value};

pub(super) fn take_alias(source: &mut Map<String, Value>, aliases: &[&str]) -> Option<Value> {
    let value = aliases.iter().find_map(|name| source.get(*name).cloned());
    for name in aliases {
        source.remove(*name);
    }
    value.filter(|value| !value.is_null())
}

pub(super) fn text_alias(source: &mut Map<String, Value>, aliases: &[&str]) -> Option<Value> {
    take_alias(source, aliases).filter(Value::is_string)
}

/// The note a migrated item carries when its legacy shape could not become
/// its canonical kind as written, so the operator learns what was kept and why.
pub(super) fn warn(context: &mut Map<String, Value>, why: String) {
    let said = match context.get("import_warning").and_then(Value::as_str) {
        Some(earlier) => format!("{earlier}; {why}"),
        None => why,
    };
    context.insert("import_warning".to_string(), json!(said));
}

/// Move the field `name` from the item, or else its metadata, into context.
fn carry(
    source: &mut Map<String, Value>,
    metadata: &Map<String, Value>,
    context: &mut Map<String, Value>,
    name: &str,
) {
    if let Some(value) = take_alias(source, &[name]).or_else(|| metadata.get(name).cloned()) {
        context.insert(name.to_string(), value);
    }
}

pub(super) fn legacy_context(
    source: &mut Map<String, Value>,
    legacy_kind: &str,
) -> Map<String, Value> {
    let mut context = Map::new();
    let metadata = match source.remove("metadata") {
        Some(Value::Object(metadata)) => metadata,
        // An item without metadata carries no context of its own.
        Some(Value::Null) | None => Map::new(),
        Some(other) => {
            warn(
                &mut context,
                format!("legacy metadata was not an object and was kept whole: {other}"),
            );
            context.insert("legacy_metadata".to_string(), other);
            Map::new()
        }
    };
    context.extend(metadata.clone());
    context.insert("source_kind".to_string(), json!(legacy_kind));
    for (target, aliases) in [
        ("provider", &["provider"][..]),
        (
            "account_ref",
            &["account_ref", "account_identifier", "account_email"][..],
        ),
        ("tenant_ref", &["tenant_ref", "tenant_id"][..]),
        ("request_id", &["_weles_request_id", "request_id"][..]),
        ("operation", &["_weles_operation", "operation"][..]),
        ("session_label", &["session_label"][..]),
        ("login_method", &["login_method"][..]),
        ("name", &["name"][..]),
        ("login_url", &["login_url", "dashboard_url"][..]),
    ] {
        let value = take_alias(source, aliases)
            .or_else(|| aliases.iter().find_map(|name| metadata.get(*name).cloned()));
        for alias in aliases {
            context.remove(*alias);
        }
        if let Some(value) = value {
            context.insert(target.to_string(), value);
        }
    }
    carry(source, &metadata, &mut context, "domains");
    carry(source, &metadata, &mut context, "domain");
    context
}
