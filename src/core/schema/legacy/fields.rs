// The canonical fields a legacy item's own fields become, by the names its
// writers used for each. Each alias set is the field's name in the legacy
// writers' records; the first one present is taken and every one removed.

use serde_json::{Map, Value};

use super::context::{take_alias, text_alias};

const USERNAME: &[&str] = &["username", "email", "login_email", "login-email"];
const PASSWORD: &[&str] = &["password", "login_password", "login-password"];

/// The secrets a legacy item kept in its metadata rather than beside the
/// rest of its fields, copied up unless the item holds them itself.
pub(super) fn lift_metadata_secrets(
    source: &mut Map<String, Value>,
    metadata: &Map<String, Value>,
) {
    lift(source, metadata, "totp_secret");
    lift(source, metadata, "google_totp_secret");
    lift(source, metadata, "recovery_codes");
}

fn lift(source: &mut Map<String, Value>, metadata: &Map<String, Value>, name: &str) {
    if !source.contains_key(name) {
        if let Some(value) = metadata.get(name) {
            source.insert(name.to_string(), value.clone());
        }
    }
}

/// Whether the item holds a username or a password under any name its
/// writers used.
pub(super) fn has_login_field(source: &Map<String, Value>) -> bool {
    USERNAME
        .iter()
        .chain(PASSWORD)
        .any(|name| source.contains_key(*name))
}

fn put(fields: &mut Map<String, Value>, target: &str, value: Option<Value>) {
    if let Some(value) = value {
        fields.insert(target.to_string(), value);
    }
}

pub(super) fn login(
    source: &mut Map<String, Value>,
    fields: &mut Map<String, Value>,
    context: &mut Map<String, Value>,
) {
    if let Some(value) = text_alias(source, USERNAME) {
        context
            .entry("account_ref".to_string())
            .or_insert_with(|| value.clone());
        fields.insert("username".to_string(), value);
    }
    put(fields, "password", text_alias(source, PASSWORD));
    put(
        fields,
        "totp_secret",
        text_alias(
            source,
            &["totp_secret", "google_totp_secret", "totp-secret"],
        ),
    );
    put(
        fields,
        "recovery_codes",
        take_alias(source, &["recovery_codes", "recovery-codes"]),
    );
}

pub(super) fn api_key(source: &mut Map<String, Value>, fields: &mut Map<String, Value>) {
    put(
        fields,
        "api_key",
        text_alias(
            source,
            &["api_key", "api-key", "api_token", "NAMECHEAP_API_KEY"],
        ),
    );
    put(
        fields,
        "api_user",
        text_alias(source, &["api_user", "api-user", "NAMECHEAP_API_USER"]),
    );
    put(
        fields,
        "username",
        text_alias(source, &["username", "NAMECHEAP_USERNAME"]),
    );
    put(
        fields,
        "client_ip",
        text_alias(source, &["client_ip", "client-ip", "NAMECHEAP_CLIENT_IP"]),
    );
}

pub(super) fn access_key(source: &mut Map<String, Value>, fields: &mut Map<String, Value>) {
    put(
        fields,
        "access_key_id",
        text_alias(
            source,
            &["access_key_id", "aws_access_key_id", "AWS_ACCESS_KEY_ID"],
        ),
    );
    put(
        fields,
        "secret_access_key",
        text_alias(
            source,
            &[
                "secret_access_key",
                "aws_secret_access_key",
                "AWS_SECRET_ACCESS_KEY",
            ],
        ),
    );
    put(
        fields,
        "session_token",
        text_alias(
            source,
            &["session_token", "aws_session_token", "AWS_SESSION_TOKEN"],
        ),
    );
}

pub(super) fn key_pair(
    source: &mut Map<String, Value>,
    fields: &mut Map<String, Value>,
    context: &mut Map<String, Value>,
) {
    put(
        fields,
        "private_key",
        text_alias(source, &["private_key", "private_key_pem", "key", "p8"]),
    );
    put(fields, "public_key", text_alias(source, &["public_key"]));
    put(fields, "passphrase", text_alias(source, &["passphrase"]));
    put(fields, "key_id", take_alias(source, &["key_id"]));
    put(fields, "issuer_id", take_alias(source, &["issuer_id"]));
    put(fields, "team_id", take_alias(source, &["team_id"]));
    put(context, "fingerprint", take_alias(source, &["fingerprint"]));
    put(context, "key_type", take_alias(source, &["key_type"]));
}

pub(super) fn token(source: &mut Map<String, Value>, fields: &mut Map<String, Value>) {
    put(fields, "token", text_alias(source, &["token"]));
}

/// Fields the canonical kind names itself, moved under the same names;
/// `text` keeps only text values.
pub(super) fn named(
    source: &mut Map<String, Value>,
    fields: &mut Map<String, Value>,
    names: &[&str],
    text: bool,
) {
    for name in names {
        let value = if text {
            text_alias(source, &[*name])
        } else {
            take_alias(source, &[*name])
        };
        put(fields, name, value);
    }
}

pub(super) fn internal_authority(
    source: &mut Map<String, Value>,
    fields: &mut Map<String, Value>,
    context: &mut Map<String, Value>,
) {
    let mut moved = |target: &str, aliases: &[&str]| {
        let value = take_alias(source, aliases).or_else(|| take_alias(context, aliases));
        put(fields, target, value);
    };
    moved("url", &["url", "base_url"]);
    moved(
        "token",
        &["token", "api_token", "access_token", "worker_token"],
    );
    moved("service_role_key", &["service_role_key", "service_key"]);
    moved("signing_secret", &["signing_secret", "signing_key"]);
    moved("agent_auth_secret", &["agent_auth_secret", "auth_secret"]);
    moved("id", &["id", "agent_id"]);
    moved("hmac_secret", &["hmac_secret"]);
}
