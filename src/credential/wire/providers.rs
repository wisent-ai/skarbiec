// Which provider a credential belongs to, what it may be called, and the one
// field a lifecycle writes for it.

use anyhow::{bail, Result};
use serde_json::Value;

use super::super::{
    ACCOUNT_PROVIDER, EXPECTATION_MISMATCH, IDENTITY_OPERATIONS, IDENTITY_PROVIDER,
};

// The one field a provider's credential contract writes. `provider_contract`
// decides the whole contract per operation; this is the field half of it on
// its own, so eligibility and the operation itself can never disagree about
// which name a lifecycle would write.
pub(in crate::credential) fn contract_field(provider: &str) -> &'static str {
    match provider {
        IDENTITY_PROVIDER | ACCOUNT_PROVIDER => "password",
        _ => "api_key",
    }
}

// The field one operation's contract writes for one provider. Subscription
// reauth signs a human login in, so the item it names carries that account's
// password; every other operation keeps the provider's own mapping. Eligibility
// and the operation read this one answer, so a report can never contradict the
// operation it describes.
pub(in crate::credential) fn operation_contract_field(
    operation: &str,
    provider: &str,
) -> &'static str {
    if operation == "reauth" {
        return "password";
    }
    contract_field(provider)
}

// A provider Skarbiec holds no named contract for. There is no list of them:
// acquire registers the account through Weles and the credential lands in the
// canonical vault like any other, so the only thing decided here is the shape
// of the slug and the one field it writes.
pub(in crate::credential) fn generic_provider(provider: &str) -> bool {
    !matches!(provider, IDENTITY_PROVIDER | ACCOUNT_PROVIDER)
}

// The exact slug shape a generic provider must have to name its own item. The
// slug becomes the item id, so it is held to an identifier's shape and not
// merely to `exact_name`'s character set.
pub(in crate::credential) const GENERIC_PROVIDER_SHAPE: &str = "^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$: 3 to 40 characters, lowercase ASCII letters, digits and '-', starting and ending with a letter or a digit";

pub(in crate::credential) fn generic_provider_slug(provider: &str) -> bool {
    let minimum: usize = "3".parse().unwrap_or_default();
    let maximum: usize = "40".parse().unwrap_or_default();
    let bytes = provider.as_bytes();
    let edge = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    (minimum..=maximum).contains(&bytes.len())
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && bytes.iter().all(|byte| edge(byte) || *byte == b'-')
}

// The item a generic provider's credential lands in when the caller named
// none: exactly the slug. A caller asking for a credential nobody holds yet
// has one name for it -- the provider's -- so Skarbiec registers it under that
// name instead of demanding one it would have to invent.
pub(in crate::credential) fn generic_credential_id(provider: &str) -> Result<&str> {
    if !generic_provider_slug(provider) {
        bail!(
            "provider {provider} cannot name its own item: a generic provider slug must match {GENERIC_PROVIDER_SHAPE}"
        );
    }
    Ok(provider)
}

// The one shape a declared signup origin may have. It travels to Weles, which
// echoes back the origin it actually captured at, and the managed write is
// refused unless the two are the same string: a path, a query, userinfo or a
// second host would let the declaration and the capture disagree about where
// the account was registered.
pub(in crate::credential) const SIGNUP_ORIGIN_SHAPE: &str = "https://<host>[:<port>]: an absolute https origin, lowercase host, no userinfo, path, query or fragment";

fn signup_origin_shaped(value: &str) -> bool {
    let maximum: usize = "512".parse().unwrap_or_default();
    let port_digits: usize = "5".parse().unwrap_or_default();
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if value.len() > maximum || authority.is_empty() {
        return false;
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let label = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-';
    let host_bytes = host.as_bytes();
    host_bytes.first().is_some_and(label)
        && host_bytes.last().is_some_and(label)
        && host
            .split('.')
            .all(|part| !part.is_empty() && part.as_bytes().iter().all(label))
        && port.is_none_or(|port| {
            !port.is_empty()
                && port.len() <= port_digits
                && port.bytes().all(|byte| byte.is_ascii_digit())
        })
}

// The signup origin a caller declares for a generic provider's acquisition.
// Only that one case has an account to register, so only that one case may
// declare where it is registered: a named provider's credential already exists
// at an origin its sealed contract or its account address decides.
pub(in crate::credential) fn declared_signup_origin(
    operation: &str,
    provider: &str,
    value: Option<&String>,
) -> Result<Option<String>> {
    let Some(value) = value.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if operation != "acquire" || !generic_provider(provider) {
        bail!(
            "--signup-origin is accepted only by credential acquire for a generic provider; {provider} registers no new account here"
        );
    }
    if !signup_origin_shaped(&value) {
        bail!("--signup-origin must be {SIGNUP_ORIGIN_SHAPE}");
    }
    Ok(Some(value))
}

// One exact provider contract per credential: the sealed directory block, the
// canonical field, and the permitted operations are decided together.
pub(in crate::credential) fn provider_contract(
    operation: &str,
    provider: &str,
    credential_id: &str,
    account: Option<&str>,
    directory: Option<&Value>,
) -> Result<&'static str> {
    if operation == "reauth" {
        if provider != "codex" {
            bail!("subscription reauth currently supports only provider codex");
        }
        if directory.is_some() || account.is_some() {
            bail!("codex subscription reauth takes its account identity from the named login item");
        }
        return Ok("password");
    }
    if let Some(sealed) = directory
        .and_then(|block| block.get("provider"))
        .and_then(Value::as_str)
    {
        if sealed != provider {
            bail!(
                "{EXPECTATION_MISMATCH}: {credential_id} is sealed for provider {sealed}, not {provider}"
            );
        }
    }
    match provider {
        IDENTITY_PROVIDER => {
            if directory.is_none() {
                bail!(
                    "{credential_id} has no sealed directory contract; run credential seal-directory {credential_id} --provider {IDENTITY_PROVIDER} --tenant <uuid> --object-id <uuid> --account-upn <email> before any lifecycle operation"
                );
            }
            if account.is_some() {
                bail!(
                    "--account is not accepted for {IDENTITY_PROVIDER}: the account address is part of the sealed directory contract"
                );
            }
            if !IDENTITY_OPERATIONS.contains(&operation) {
                bail!(
                    "{IDENTITY_PROVIDER} supports only adopt, rotate, verify, or reset; refusing {operation}"
                );
            }
            Ok(contract_field(provider))
        }
        ACCOUNT_PROVIDER => {
            if account.is_none() {
                bail!("{ACCOUNT_PROVIDER} credential operations require --account <email>");
            }
            if operation == "reset" {
                bail!("reset requires a directory provider; {ACCOUNT_PROVIDER} cannot reset an unknown current password");
            }
            Ok(contract_field(provider))
        }
        other => {
            if directory.is_some() {
                bail!(
                    "a sealed directory contract is only meaningful for {IDENTITY_PROVIDER}; {credential_id} names {other}"
                );
            }
            if operation == "reset" {
                bail!("provider {other} has no credential reset contract");
            }
            // An item named after its provider is that provider's generic
            // registration: the slug is the identifier the credential lands
            // under, so it is held to the slug shape before anything is
            // written beneath it.
            if credential_id == other && !generic_provider_slug(other) {
                bail!(
                    "provider {other} cannot name its own item: a generic provider slug must match {GENERIC_PROVIDER_SHAPE}"
                );
            }
            Ok(contract_field(provider))
        }
    }
}
