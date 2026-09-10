// Which item kinds exist and which field names each one declares. A reader
// can answer both from the cleartext envelope, without opening the item.

const LOGIN_FIELDS: &[&str] = &["username", "password", "totp_secret", "recovery_codes"];
// A fleet host's operating-system account is not a web login: it is consumed by
// the host-placement and host-repair readers, never by a login trajectory. Those
// readers iterate `login` items, so overloading `login` would hand a machine
// root account to a browser flow; `host-account` keeps the two sets disjoint.
const HOST_ACCOUNT_FIELDS: &[&str] = &["username", "password"];
const API_KEY_FIELDS: &[&str] = &["api_key", "api_user", "username", "client_ip"];
const ACCESS_KEY_FIELDS: &[&str] = &["access_key_id", "secret_access_key", "session_token"];
const TOKEN_FIELDS: &[&str] = &["token"];
pub(super) const OAUTH_CLIENT_FIELDS: &[&str] = &["client_id", "client_secret"];
pub(super) const PROXY_FIELDS: &[&str] = &["username", "password", "host", "ports", "zone"];
const KEY_PAIR_FIELDS: &[&str] = &[
    "private_key",
    "public_key",
    "passphrase",
    "key_id",
    "issuer_id",
    "team_id",
];
pub(super) const CERTIFICATE_FIELDS: &[&str] =
    &["certificate", "private_key", "chain", "passphrase"];
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

pub(super) fn allowed_fields(kind: &str) -> Option<&'static [&'static str]> {
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
