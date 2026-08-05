use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

pub const ITEM_SCHEMA: &str = "skarbiec.item.v2";

const LOGIN_FIELDS: &[&str] = &["username", "password", "totp_secret", "recovery_codes"];
const API_KEY_FIELDS: &[&str] = &["api_key", "api_user", "username", "client_ip"];
const ACCESS_KEY_FIELDS: &[&str] = &["access_key_id", "secret_access_key", "session_token"];
const TOKEN_FIELDS: &[&str] = &["token"];
const OAUTH_CLIENT_FIELDS: &[&str] = &["client_id", "client_secret"];
const PROXY_FIELDS: &[&str] = &["username", "password", "host", "ports", "zone"];
const KEY_PAIR_FIELDS: &[&str] = &[
    "private_key",
    "public_key",
    "passphrase",
    "key_id",
    "issuer_id",
    "team_id",
];
const CERTIFICATE_FIELDS: &[&str] = &["certificate", "private_key", "chain", "passphrase"];
const SERVICE_ACCOUNT_FIELDS: &[&str] = &["credential_json"];
const VALUE_FIELDS: &[&str] = &["value"];
const NOTE_FIELDS: &[&str] = &["value"];

pub fn supported_kind(kind: &str) -> bool {
    matches!(
        kind,
        "login"
            | "note"
            | "api-key"
            | "access-key"
            | "token"
            | "oauth-client"
            | "proxy"
            | "key-pair"
            | "certificate"
            | "service-account"
            | "bundle"
            | "stado-secret"
            | "internal-authority"
            | "credential-operation"
    )
}

fn exact_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= "128".parse().unwrap_or(usize::MAX)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn allowed_fields(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "note" => Some(NOTE_FIELDS),
        "login" => Some(LOGIN_FIELDS),
        "api-key" => Some(API_KEY_FIELDS),
        "access-key" => Some(ACCESS_KEY_FIELDS),
        "token" => Some(TOKEN_FIELDS),
        "oauth-client" => Some(OAUTH_CLIENT_FIELDS),
        "proxy" => Some(PROXY_FIELDS),
        "key-pair" => Some(KEY_PAIR_FIELDS),
        "certificate" => Some(CERTIFICATE_FIELDS),
        "service-account" => Some(SERVICE_ACCOUNT_FIELDS),
        "credential-operation" => Some(VALUE_FIELDS),
        _ => None,
    }
}

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
        "stado-secret" | "internal-authority" | "credential-operation" | "bundle"
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
        "credential-operation" => required(fields, &["value"], expected_kind)?,
        "stado-secret" | "internal-authority" | "bundle" => {}
        _ => unreachable!(),
    }
    if object.get("context").and_then(Value::as_object).is_none() {
        bail!("canonical item context must be an object");
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

pub fn allows_field(payload: &Value, name: &str) -> bool {
    if name == "context" {
        return true;
    }
    let Some(kind) = payload.get("kind").and_then(Value::as_str) else {
        return false;
    };
    allowed_fields(kind)
        .map(|allowed| allowed.contains(&name))
        .unwrap_or_else(|| exact_component(name))
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

fn take_alias(source: &mut Map<String, Value>, aliases: &[&str]) -> Option<Value> {
    let value = aliases.iter().find_map(|name| source.get(*name).cloned());
    for name in aliases {
        source.remove(*name);
    }
    value.filter(|value| !value.is_null())
}

fn text_alias(source: &mut Map<String, Value>, aliases: &[&str]) -> Option<Value> {
    take_alias(source, aliases).filter(Value::is_string)
}

fn legacy_context(source: &mut Map<String, Value>, legacy_kind: &str) -> Map<String, Value> {
    let metadata = source
        .remove("metadata")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    let mut context = metadata.clone();
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
    for name in ["domains", "domain"] {
        if let Some(value) = take_alias(source, &[name]).or_else(|| metadata.get(name).cloned()) {
            context.insert(name.to_string(), value);
        }
    }
    context
}

fn fallback_payload(fallback: Value, context: Map<String, Value>) -> Result<(String, Value)> {
    let mut fields = Map::new();
    fields.insert("value".to_string(), fallback);
    Ok((
        "stado-secret".to_string(),
        payload("stado-secret", fields, context)?,
    ))
}

pub fn migrate_legacy(legacy_kind: &str, legacy: Value) -> Result<(String, Value)> {
    if legacy.get("schema").and_then(Value::as_str) == Some(ITEM_SCHEMA) {
        let kind = legacy
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical payload has no kind")?
            .to_string();
        validate_payload(&legacy, &kind)?;
        return Ok((kind, legacy));
    }
    let fallback = legacy.clone();
    let mut source = legacy.as_object().cloned().unwrap_or_else(|| {
        let mut object = Map::new();
        object.insert("value".to_string(), legacy);
        object
    });
    source.remove("type");
    source.remove("category");
    source.remove("display_name");
    if let Some(metadata) = source.get("metadata").and_then(Value::as_object).cloned() {
        for name in ["totp_secret", "google_totp_secret", "recovery_codes"] {
            if !source.contains_key(name) {
                if let Some(value) = metadata.get(name) {
                    source.insert(name.to_string(), value.clone());
                }
            }
        }
    }
    let mut context = legacy_context(&mut source, legacy_kind);
    let normalized = match legacy_kind.trim().to_ascii_lowercase().replace('_', "-") {
        kind if kind == "credential-request" => "credential-operation".to_string(),
        kind => kind,
    };
    let has_login_field = source.keys().any(|name| {
        matches!(
            name.as_str(),
            "username"
                | "email"
                | "login-email"
                | "login_email"
                | "password"
                | "login-password"
                | "login_password"
        )
    });
    let mut fields = Map::new();
    let kind = if matches!(
        normalized.as_str(),
        "login" | "platform-admin" | "credential" | "ai-cli" | "google-sso" | "auth"
    ) && has_login_field
        && !source.contains_key("api_key")
        && !source.contains_key("NAMECHEAP_API_KEY")
    {
        if let Some(value) = text_alias(
            &mut source,
            &["username", "email", "login_email", "login-email"],
        ) {
            context
                .entry("account_ref".to_string())
                .or_insert_with(|| value.clone());
            fields.insert("username".to_string(), value);
        }
        if let Some(value) = text_alias(
            &mut source,
            &["password", "login_password", "login-password"],
        ) {
            fields.insert("password".to_string(), value);
        }
        if let Some(value) = text_alias(
            &mut source,
            &["totp_secret", "google_totp_secret", "totp-secret"],
        ) {
            fields.insert("totp_secret".to_string(), value);
        }
        if let Some(value) = take_alias(&mut source, &["recovery_codes", "recovery-codes"]) {
            fields.insert("recovery_codes".to_string(), value);
        }
        "login"
    } else if matches!(normalized.as_str(), "api" | "api-key" | "ai-cli")
        || (normalized == "credential" && source.contains_key("api_key"))
        || (normalized == "platform-admin" && source.contains_key("NAMECHEAP_API_KEY"))
    {
        if let Some(value) = text_alias(
            &mut source,
            &["api_key", "api-key", "api_token", "NAMECHEAP_API_KEY"],
        ) {
            fields.insert("api_key".to_string(), value);
        }
        if let Some(value) =
            text_alias(&mut source, &["api_user", "api-user", "NAMECHEAP_API_USER"])
        {
            fields.insert("api_user".to_string(), value);
        }
        if let Some(value) = text_alias(&mut source, &["username", "NAMECHEAP_USERNAME"]) {
            fields.insert("username".to_string(), value);
        }
        if let Some(value) = text_alias(
            &mut source,
            &["client_ip", "client-ip", "NAMECHEAP_CLIENT_IP"],
        ) {
            fields.insert("client_ip".to_string(), value);
        }
        "api-key"
    } else if normalized == "aws-credentials"
        || (normalized == "auth" && source.contains_key("access_key_id"))
    {
        if let Some(value) = text_alias(
            &mut source,
            &["access_key_id", "aws_access_key_id", "AWS_ACCESS_KEY_ID"],
        ) {
            fields.insert("access_key_id".to_string(), value);
        }
        if let Some(value) = text_alias(
            &mut source,
            &[
                "secret_access_key",
                "aws_secret_access_key",
                "AWS_SECRET_ACCESS_KEY",
            ],
        ) {
            fields.insert("secret_access_key".to_string(), value);
        }
        if let Some(value) = text_alias(
            &mut source,
            &["session_token", "aws_session_token", "AWS_SESSION_TOKEN"],
        ) {
            fields.insert("session_token".to_string(), value);
        }
        "access-key"
    } else if normalized == "proxy" {
        for name in PROXY_FIELDS {
            if let Some(value) = take_alias(&mut source, &[*name]) {
                fields.insert((*name).to_string(), value);
            }
        }
        "proxy"
    } else if matches!(normalized.as_str(), "key" | "ssh-key")
        || (normalized == "credential" && source.contains_key("p8"))
    {
        if let Some(value) = text_alias(
            &mut source,
            &["private_key", "private_key_pem", "key", "p8"],
        ) {
            fields.insert("private_key".to_string(), value);
        }
        if let Some(value) = text_alias(&mut source, &["public_key"]) {
            fields.insert("public_key".to_string(), value);
        }
        if let Some(value) = text_alias(&mut source, &["passphrase"]) {
            fields.insert("passphrase".to_string(), value);
        }
        for name in ["key_id", "issuer_id", "team_id"] {
            if let Some(value) = take_alias(&mut source, &[name]) {
                fields.insert(name.to_string(), value);
            }
        }
        for name in ["fingerprint", "key_type"] {
            if let Some(value) = take_alias(&mut source, &[name]) {
                context.insert(name.to_string(), value);
            }
        }
        "key-pair"
    } else if normalized == "token" || (normalized == "secret" && source.contains_key("token")) {
        if let Some(value) = text_alias(&mut source, &["token"]) {
            fields.insert("token".to_string(), value);
        }
        "token"
    } else if normalized == "oauth-client" {
        for name in OAUTH_CLIENT_FIELDS {
            if let Some(value) = text_alias(&mut source, &[*name]) {
                fields.insert((*name).to_string(), value);
            }
        }
        "oauth-client"
    } else if normalized == "certificate" {
        for name in CERTIFICATE_FIELDS {
            if let Some(value) = take_alias(&mut source, &[*name]) {
                fields.insert((*name).to_string(), value);
            }
        }
        "certificate"
    } else if normalized == "service-account" {
        let credential = take_alias(&mut source, &["credential_json", "service_account_json"])
            .unwrap_or_else(|| Value::Object(source.clone()));
        fields.insert("credential_json".to_string(), credential);
        "service-account"
    } else if normalized == "stado-secret" {
        fields = source.clone();
        "stado-secret"
    } else if normalized == "credential-operation" {
        fields.insert("value".to_string(), fallback.clone());
        "credential-operation"
    } else if normalized == "internal-authority" {
        for (field, aliases) in [
            ("url", &["url", "base_url"][..]),
            (
                "token",
                &["token", "api_token", "access_token", "worker_token"][..],
            ),
            ("service_role_key", &["service_role_key", "service_key"][..]),
            ("signing_secret", &["signing_secret", "signing_key"][..]),
            (
                "agent_auth_secret",
                &["agent_auth_secret", "auth_secret"][..],
            ),
            ("id", &["id", "agent_id"][..]),
            ("hmac_secret", &["hmac_secret"][..]),
        ] {
            if let Some(value) =
                take_alias(&mut source, aliases).or_else(|| take_alias(&mut context, aliases))
            {
                fields.insert(field.to_string(), value);
            }
        }
        fields.extend(source.clone());
        "internal-authority"
    } else if matches!(normalized.as_str(), "env" | "config" | "credential") {
        fields = source.clone();
        context.insert("profile".to_string(), json!(normalized));
        "bundle"
    } else {
        return fallback_payload(fallback, context);
    };
    match payload(kind, fields, context.clone()) {
        Ok(value) => Ok((kind.to_string(), value)),
        Err(_) => fallback_payload(fallback, context),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_requires_one_string_value() {
        let valid = json!({
            "schema": ITEM_SCHEMA,
            "kind": "note",
            "fields": {"value": "non-secret onboarding proof"},
            "context": {},
        });
        validate_payload(&valid, "note").expect("valid note");

        let missing = json!({
            "schema": ITEM_SCHEMA,
            "kind": "note",
            "fields": {"title": "not canonical"},
            "context": {},
        });
        assert!(validate_payload(&missing, "note").is_err());

        let non_string = json!({
            "schema": ITEM_SCHEMA,
            "kind": "note",
            "fields": {"value": true},
            "context": {},
        });
        assert!(validate_payload(&non_string, "note").is_err());
    }
}
