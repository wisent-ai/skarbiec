use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

pub const ITEM_SCHEMA: &str = "skarbiec.item.v2";

const LOGIN_FIELDS: &[&str] = &["username", "password", "totp_secret", "recovery_codes"];
// A fleet host's operating-system account is not a web login: it is consumed by
// the host-placement and host-repair readers, never by a login trajectory. Those
// readers iterate `login` items, so overloading `login` would hand a machine
// root account to a browser flow; `host-account` keeps the two sets disjoint.
const HOST_ACCOUNT_FIELDS: &[&str] = &["username", "password"];
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
            | "host-account"
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
            // The sealed directory contract. A separate kind from the
            // operation record because it is a separate family: an operation
            // record is one request and its outcome, a seal is the standing
            // statement of which principal an item speaks for. Both are
            // written by the credential lifecycle under the same managed
            // authority, so before this kind existed the only thing that told
            // them apart was how their ids happened to be spelled -- and an id
            // is a mutable name, not evidence. A reader that wants seals can
            // now ask for seals.
            | "credential-directory-seal"
    )
}

/// The bound an exact name carries throughout this crate: non-empty, no longer
/// than this many bytes, and free of the separators a name must never smuggle
/// into a resource string, a route table row or a journal line.
pub const MAX_NAME_CHARS: usize = 128;

pub fn exact_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.contains('\0')
        && !value.contains('\n')
        && !value.contains('\r')
}

/// One registered tag namespace, and the two shapes a namespace comes in.
///
/// The shapes are not interchangeable and flattening them into one prefix test
/// is what leaves the surface open. `brama:subscription` is the whole
/// statement — an item either is a subscription or is not — and
/// `brama:subscription:anything` is a different, unowned tag that a prefix test
/// would wave through. `brama:agent:` is the opposite: the prefix alone says
/// nothing, the agent name is the content, and a bare `brama:agent:` is a
/// declaration with its subject missing. So an exact namespace matches only
/// itself, and a valued namespace demands a value that clears the same bound
/// every other exact name in this crate clears.
enum TagNamespace {
    /// A tag that is the entire contract; it must match exactly.
    Exact(&'static str),
    /// A prefix whose value names what the role points at. `value` is the
    /// placeholder an operator reads back in a refusal, never part of the match.
    Valued {
        prefix: &'static str,
        value: &'static str,
    },
}

/// The registry. This is the authority: a namespace exists because it is here,
/// and the published table documents what this list already enforces.
///
/// Registering a namespace is adding a row here in the same commit that starts
/// writing it. Nothing else registers anything.
const TAG_NAMESPACES: &[TagNamespace] = &[
    TagNamespace::Exact("managed:weles"),
    TagNamespace::Exact("brama:subscription"),
    TagNamespace::Valued {
        prefix: "brama:agent:",
        value: "agent",
    },
    TagNamespace::Valued {
        prefix: "brama:provider:",
        value: "provider",
    },
    TagNamespace::Valued {
        prefix: "brama:id:",
        value: "id",
    },
    // Which login item a Codex subscription belongs to. `credential status
    // <id> reauth` treats an item as that subscription only when it carries
    // this tag alongside `brama:subscription` and `brama:provider:codex`
    // (`credential::status::named_subscription_present`), so the product reads
    // this namespace and decides on it. Leaving it unregistered meant the
    // binary demanded a tag it refused to let anyone write: every other tag
    // that workflow needs passed the gate and this one did not.
    TagNamespace::Valued {
        prefix: "brama:login:",
        value: "login",
    },
    TagNamespace::Exact("fleet:host-account"),
    TagNamespace::Valued {
        prefix: "fleet:target:",
        value: "name",
    },
    TagNamespace::Exact("fleet:tailnet-tls"),
    // Written by the credential lifecycle when it freezes an item, and read
    // back by `record_quarantined` to decide whether an item is frozen. The
    // product both writes and reads it, so it is a namespace this vault uses
    // and belongs here; describing it as a gap elsewhere is not the same as
    // closing it.
    TagNamespace::Exact("lifecycle:quarantined"),
];

impl TagNamespace {
    fn shown(&self) -> String {
        match self {
            TagNamespace::Exact(tag) => (*tag).to_string(),
            TagNamespace::Valued { prefix, value } => format!("{prefix}<{value}>"),
        }
    }
}

/// Why one tag is refused, or `Ok` if a registered namespace covers it.
///
/// A tag carrying no colon claims no namespace: it is an operator's own label,
/// governed by nobody and filtered on by nobody, and the registry has no
/// standing over it. This crate writes two of them itself — `onboarding` and
/// `challenge` — and refusing them would refuse the onboarding walkthrough and
/// the Apple challenge record. A colon is the claim, and a claim is what has to
/// be honoured.
fn tag_refusal(tag: &str) -> Result<(), String> {
    if !tag.contains(':') {
        return Ok(());
    }
    if TAG_NAMESPACES
        .iter()
        .any(|namespace| matches!(namespace, TagNamespace::Exact(exact) if tag == *exact))
    {
        return Ok(());
    }
    for namespace in TAG_NAMESPACES {
        let TagNamespace::Valued { prefix, value } = namespace else {
            continue;
        };
        let Some(carried) = tag.strip_prefix(prefix) else {
            continue;
        };
        if exact_token(carried, MAX_NAME_CHARS) {
            return Ok(());
        }
        return Err(format!(
            "claims the {prefix}<{value}> namespace without a usable {value}: the value must be 1 to {MAX_NAME_CHARS} bytes and carry no NUL, newline or carriage return"
        ));
    }
    Err("claims a namespace that is not registered".to_string())
}

/// The refusal an operator reads. It names the tag, says what is wrong with it,
/// and lists what is allowed, because a refusal that withholds the allowed set
/// only moves the guessing one step along.
fn tag_refused(tag: &str, reason: &str) -> String {
    let registered: Vec<String> = TAG_NAMESPACES.iter().map(TagNamespace::shown).collect();
    format!(
        "tag `{tag}` {reason}. Registered namespaces: {}. Register a namespace before anything writes it; a tag with no colon claims no namespace and stays the operator's own label.",
        registered.join(", ")
    )
}

/// Refuse a write that introduces a tag no registered namespace covers.
///
/// Only what this write introduces. A tag the item already carries is left
/// alone: writes deliberately preserve tags they do not mention, and re-reading
/// that preserved list through this gate would turn every unrelated rotation of
/// an already-tagged item into a refusal — which is the tag-loss failure the
/// preserving write was added to end, arriving by the other door. An
/// unregistered tag already in the vault is a migration to run, not a rotation
/// to break.
pub fn ensure_registered_tags(carried: &[Value], written: &[Value]) -> Result<()> {
    for tag in written.iter().filter_map(Value::as_str) {
        if carried.iter().any(|kept| kept.as_str() == Some(tag)) {
            continue;
        }
        if let Err(reason) = tag_refusal(tag) {
            bail!("{}", tag_refused(tag, &reason));
        }
    }
    Ok(())
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
        "host-account" => Some(HOST_ACCOUNT_FIELDS),
        "api-key" => Some(API_KEY_FIELDS),
        "access-key" => Some(ACCESS_KEY_FIELDS),
        "token" => Some(TOKEN_FIELDS),
        "oauth-client" => Some(OAUTH_CLIENT_FIELDS),
        "proxy" => Some(PROXY_FIELDS),
        "key-pair" => Some(KEY_PAIR_FIELDS),
        "certificate" => Some(CERTIFICATE_FIELDS),
        "service-account" => Some(SERVICE_ACCOUNT_FIELDS),
        "credential-operation" | "credential-directory-seal" => Some(VALUE_FIELDS),
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
