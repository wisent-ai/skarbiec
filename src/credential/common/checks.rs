// Reading one value out of an untrusted JSON object and refusing anything
// that is not the exact shape the contract names.

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub(in crate::credential) fn safe_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.chars().any(char::is_control))
        .map(str::to_string)
}

pub(in crate::credential) fn present(value: &Value, key: &str) -> bool {
    value.get(key).is_some_and(|found| !found.is_null())
}

pub(in crate::credential) fn checked_enum(
    value: &Value,
    key: &str,
    allowed: &[&str],
) -> Result<Option<String>> {
    if !present(value, key) {
        return Ok(None);
    }
    let text = safe_string(value, key)
        .filter(|text| allowed.contains(&text.as_str()))
        .with_context(|| format!("Weles response {key} is not an accepted value"))?;
    Ok(Some(text))
}

pub(in crate::credential) fn checked_bool(value: &Value, key: &str) -> Result<Option<bool>> {
    if !present(value, key) {
        return Ok(None);
    }
    let flag = value
        .get(key)
        .and_then(Value::as_bool)
        .with_context(|| format!("Weles response {key} must be a boolean"))?;
    Ok(Some(flag))
}

pub(in crate::credential) fn checked_code(value: &Value) -> Result<Option<String>> {
    if !present(value, "code") {
        return Ok(None);
    }
    let text =
        safe_string(value, "code").context("Weles response code is not a single-line string")?;
    let shaped = text.starts_with(|first: char| first.is_ascii_uppercase())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    if !shaped {
        bail!("Weles response code must be an uppercase machine-readable identifier");
    }
    Ok(Some(text))
}

/// The longest name a host can carry: DNS names are at most 255 octets.
/// <https://www.rfc-editor.org/rfc/rfc1035#section-2.3.4>
pub(in crate::credential) const HOST_NAME_MAX: usize = 255;

/// Whether `host` is a single-line host name within [`HOST_NAME_MAX`].
pub(in crate::credential) fn bounded_host(host: &str) -> bool {
    !host.is_empty() && host.len() <= HOST_NAME_MAX
}

pub(in crate::credential) fn checked_host(value: &Value) -> Result<Option<String>> {
    if !present(value, "executionHost") {
        return Ok(None);
    }
    let host = safe_string(value, "executionHost")
        .filter(|host| bounded_host(host))
        .with_context(|| {
            format!("Weles response executionHost must be a single-line host name of at most {HOST_NAME_MAX} characters")
        })?;
    Ok(Some(host))
}

pub(in crate::credential) fn checked_uuid(value: &Value, key: &str) -> Result<Option<String>> {
    if !present(value, key) {
        return Ok(None);
    }
    let text =
        safe_string(value, key).with_context(|| format!("Weles response {key} is not a string"))?;
    if !uuid_shaped(&text) {
        bail!("Weles response {key} must be a lowercase 8-4-4-4-12 hexadecimal UUID");
    }
    Ok(Some(text))
}

/// The hexadecimal digits of a SHA-256 digest, two for each of its bytes.
/// <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>
const SHA256_HEX_DIGITS: usize = 64;

pub(in crate::credential) fn hex_digest(value: &str) -> bool {
    value.len() == SHA256_HEX_DIGITS && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The whole-second stamp a Weles timestamp names: the shape
/// `clock::now_iso` writes and `clock::is_iso` checks, which every stored
/// stamp has, with an optional fraction of a second before its `Z`. Two
/// answers compare as text in time order because both carry that shape;
/// anything else is `None`.
pub(in crate::credential) fn zulu_seconds(value: &str) -> Option<String> {
    let body = value.strip_suffix('Z')?;
    let seconds = match body.split_once('.') {
        Some((seconds, fraction))
            if !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            seconds
        }
        Some(_) => return None,
        None => body,
    };
    let stamp = format!("{seconds}Z");
    crate::core::clock::is_iso(&stamp).then_some(stamp)
}

/// The only timestamp shape Skarbiec writes or accepts (see [`zulu_seconds`]).
pub(in crate::credential) fn timestamp_shaped(value: &str) -> bool {
    zulu_seconds(value).is_some()
}

pub(in crate::credential) fn checked_timestamp(value: &Value, key: &str) -> Result<Option<String>> {
    if !present(value, key) {
        return Ok(None);
    }
    let text = safe_string(value, key)
        .filter(|text| timestamp_shaped(text))
        .with_context(|| format!("Weles response {key} must be an ISO 8601 zulu timestamp"))?;
    Ok(Some(text))
}

/// The hexadecimal digits of each hyphen-separated group of a UUID.
/// <https://www.rfc-editor.org/rfc/rfc9562#section-4>
const UUID_GROUP_DIGITS: &[usize] = &[8, 4, 4, 4, 12];

/// Whether `value` is a UUID written in lowercase hexadecimal groups.
pub(in crate::credential) fn uuid_shaped(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == UUID_GROUP_DIGITS.len()
        && groups.iter().zip(UUID_GROUP_DIGITS).all(|(group, digits)| {
            group.len() == *digits
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}
