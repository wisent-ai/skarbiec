// The names a legacy grant may carry: which actions exist, which resource
// strings are exact, how a glob matches an item id, and which field a legacy
// name resolves to.

use anyhow::{bail, Result};

pub(super) fn exact_resource(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

pub(super) fn glob_matches(pattern: &str, value: &str) -> bool {
    let (mut pattern_index, mut value_index, mut star, mut retry) =
        (usize::MIN, usize::MIN, None, usize::MIN);
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index = pattern_index.saturating_add(std::iter::once(()).count());
            value_index = value_index.saturating_add(std::iter::once(()).count());
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star = Some(pattern_index);
            pattern_index = pattern_index.saturating_add(std::iter::once(()).count());
            retry = value_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index.saturating_add(std::iter::once(()).count());
            retry = retry.saturating_add(std::iter::once(()).count());
            value_index = retry;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index = pattern_index.saturating_add(std::iter::once(()).count());
    }
    pattern_index == pattern.len()
}

pub(super) fn canonical_field(name: &str, fields: &[String]) -> Result<String> {
    if name == "metadata" {
        return Ok("context".to_string());
    }
    if fields.iter().any(|field| field == name) {
        return Ok(name.to_string());
    }
    let aliases: &[&str] = match name {
        "email" | "login_email" | "login-email" => &["username"],
        "login_password" | "login-password" => &["password"],
        "google_totp_secret" | "totp-secret" => &["totp_secret"],
        "api_token" | "api-token" => &["api_key", "token"],
        "key_id" | "key-id" => &["access_key_id"],
        "secret_key" | "secret-key" => &["secret_access_key"],
        _ => &[],
    };
    let matches: Vec<&str> = aliases
        .iter()
        .copied()
        .filter(|alias| fields.iter().any(|field| field == alias))
        .collect();
    match matches.as_slice() {
        [field] => Ok((*field).to_string()),
        [] => bail!("legacy capability field has no canonical target: {name}"),
        _ => bail!("legacy capability field is ambiguous: {name}"),
    }
}

pub(super) fn future_contract_field(item: &str, requested: Option<&str>) -> Option<&'static str> {
    let microsoft_password = item.starts_with("weles-microsoft-") && item.ends_with("-password");
    if microsoft_password
        && requested
            .is_none_or(|field| matches!(field, "password" | "login_password" | "login-password"))
    {
        Some("password")
    } else {
        None
    }
}

pub(super) fn supported_action(action: &str) -> bool {
    matches!(
        action,
        "read"
            | "stage"
            | "rotate"
            | "verify"
            | "share"
            | "trash"
            | "purge"
            | "admin"
            | "acquire"
            | "revoke"
            | "sync"
            | "enroll"
            | "donate"
    )
}
