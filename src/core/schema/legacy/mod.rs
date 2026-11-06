// Reading an item written before this schema existed, and saying which
// canonical kind and payload it becomes. The legacy kind an item was written
// under is read through the declared `LegacyKind`, and an item whose legacy
// shape cannot become its kind as written is kept whole, its context's
// `import_warning` saying what was kept and why.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::kinds::names;
use super::payload::{payload, validate_payload};
use super::ITEM_SCHEMA;

mod context;
mod fields;
use context::{legacy_context, warn};

/// A legacy service account's credential document, under either name its
/// writers gave it; both at once is a record that cannot be read as one.
#[derive(Deserialize)]
struct LegacyServiceAccount {
    #[serde(alias = "service_account_json")]
    credential_json: Option<Value>,
}

/// Every kind a legacy item was written under, as its writers spelled it
/// (case-insensitive, `_` read as `-`). A kind no writer used is `Unknown`.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
enum LegacyKind {
    Login,
    PlatformAdmin,
    Credential,
    AiCli,
    GoogleSso,
    Auth,
    Api,
    ApiKey,
    AwsCredentials,
    Proxy,
    Key,
    SshKey,
    Token,
    Secret,
    OauthClient,
    Certificate,
    ServiceAccount,
    StadoSecret,
    #[serde(alias = "credential-request")]
    CredentialOperation,
    InternalAuthority,
    Env,
    Config,
    #[serde(other)]
    Unknown,
}

impl LegacyKind {
    /// The kind as spelled in the declaration above, for the bundle profile.
    fn spelled(written: &str) -> String {
        written.trim().to_ascii_lowercase().replace('_', "-")
    }

    /// The declared kind `written` names; a kind no writer used is `Unknown`
    /// through `other`, and a spelling serde cannot read as a kind is refused
    /// naming it rather than taken for an unknown one.
    fn read(written: &str) -> Result<Self> {
        serde_json::from_value(json!(Self::spelled(written)))
            .with_context(|| format!("legacy kind {written:?} cannot be read as a declared kind"))
    }
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
    let wrapped = !legacy.is_object();
    let mut source = match legacy {
        Value::Object(object) => object,
        other => Map::from_iter([("value".to_string(), other)]),
    };
    source.remove("type");
    source.remove("category");
    source.remove("display_name");
    if let Some(metadata) = source.get("metadata").and_then(Value::as_object).cloned() {
        fields::lift_metadata_secrets(&mut source, &metadata);
    }
    let mut context = legacy_context(&mut source, legacy_kind);
    if wrapped {
        warn(
            &mut context,
            "the legacy item was not an object; its whole value is kept as value".to_string(),
        );
    }
    let written = LegacyKind::read(legacy_kind)?;
    let has = |source: &Map<String, Value>, name: &str| source.contains_key(name);
    let login_like = matches!(
        written,
        LegacyKind::Login
            | LegacyKind::PlatformAdmin
            | LegacyKind::Credential
            | LegacyKind::AiCli
            | LegacyKind::GoogleSso
            | LegacyKind::Auth
    );
    let mut fields = Map::new();
    let kind = if login_like
        && fields::has_login_field(&source)
        && !has(&source, "api_key")
        && !has(&source, "NAMECHEAP_API_KEY")
    {
        fields::login(&mut source, &mut fields, &mut context);
        "login"
    } else if matches!(
        written,
        LegacyKind::Api | LegacyKind::ApiKey | LegacyKind::AiCli
    ) || (written == LegacyKind::Credential && has(&source, "api_key"))
        || (written == LegacyKind::PlatformAdmin && has(&source, "NAMECHEAP_API_KEY"))
    {
        fields::api_key(&mut source, &mut fields);
        "api-key"
    } else if written == LegacyKind::AwsCredentials
        || (written == LegacyKind::Auth && has(&source, "access_key_id"))
    {
        fields::access_key(&mut source, &mut fields);
        "access-key"
    } else if written == LegacyKind::Proxy {
        fields::named(&mut source, &mut fields, &names("proxy"), false);
        "proxy"
    } else if matches!(written, LegacyKind::Key | LegacyKind::SshKey)
        || (written == LegacyKind::Credential && has(&source, "p8"))
    {
        fields::key_pair(&mut source, &mut fields, &mut context);
        "key-pair"
    } else if written == LegacyKind::Token
        || (written == LegacyKind::Secret && has(&source, "token"))
    {
        fields::token(&mut source, &mut fields);
        "token"
    } else if written == LegacyKind::OauthClient {
        fields::named(&mut source, &mut fields, &names("oauth-client"), true);
        "oauth-client"
    } else if written == LegacyKind::Certificate {
        fields::named(&mut source, &mut fields, &names("certificate"), false);
        "certificate"
    } else if written == LegacyKind::ServiceAccount {
        let read = serde_json::from_value::<LegacyServiceAccount>(Value::Object(source.clone()));
        let whole = |context: &mut Map<String, Value>, why: String| {
            warn(
                context,
                format!("{why}; its whole record is kept as credential_json"),
            );
            Value::Object(source.clone())
        };
        let credential = match read {
            Ok(LegacyServiceAccount {
                credential_json: Some(credential),
            }) => credential,
            Ok(LegacyServiceAccount {
                credential_json: None,
            }) => whole(
                &mut context,
                "the legacy service account named no credential_json".to_string(),
            ),
            Err(error) => whole(
                &mut context,
                format!("the legacy service account's credential cannot be read ({error})"),
            ),
        };
        fields.insert("credential_json".to_string(), credential);
        "service-account"
    } else if written == LegacyKind::StadoSecret {
        fields = source.clone();
        "stado-secret"
    } else if written == LegacyKind::CredentialOperation {
        fields.insert("value".to_string(), fallback.clone());
        "credential-operation"
    } else if written == LegacyKind::InternalAuthority {
        fields::internal_authority(&mut source, &mut fields, &mut context);
        fields.extend(source.clone());
        "internal-authority"
    } else if matches!(
        written,
        LegacyKind::Env | LegacyKind::Config | LegacyKind::Credential
    ) {
        fields = source.clone();
        context.insert(
            "profile".to_string(),
            json!(LegacyKind::spelled(legacy_kind)),
        );
        "bundle"
    } else {
        warn(
            &mut context,
            format!("legacy kind {legacy_kind:?} has no canonical kind; the item is kept whole"),
        );
        return fallback_payload(fallback, context);
    };
    match payload(kind, fields, context.clone()) {
        Ok(value) => Ok((kind.to_string(), value)),
        Err(refusal) => {
            warn(
                &mut context,
                format!("the {kind} fields were refused ({refusal:#}); the item is kept whole"),
            );
            fallback_payload(fallback, context)
        }
    }
}
