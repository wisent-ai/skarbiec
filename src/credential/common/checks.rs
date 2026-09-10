// Reading one value out of an untrusted JSON object and refusing anything
// that is not the exact shape the contract names.

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub(in crate::credential) fn safe_string(value: &Value, key: &str) -> Option<String> {
    let max: usize = "512".parse().ok()?;
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| text.len() <= max && !text.chars().any(char::is_control))
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
    let text = safe_string(value, "code").context("Weles response code is not a bounded string")?;
    let max: usize = "64".parse()?;
    let shaped = text.len() <= max
        && text.starts_with(|first: char| first.is_ascii_uppercase())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    if !shaped {
        bail!("Weles response code must be an uppercase machine-readable identifier");
    }
    Ok(Some(text))
}

pub(in crate::credential) fn checked_host(value: &Value) -> Result<Option<String>> {
    if !present(value, "executionHost") {
        return Ok(None);
    }
    let max: usize = "128".parse()?;
    let host = safe_string(value, "executionHost")
        .filter(|host| !host.is_empty() && host.len() <= max)
        .context("Weles response executionHost must be a bounded single-line host name")?;
    Ok(Some(host))
}

pub(in crate::credential) fn checked_uuid(value: &Value, key: &str) -> Result<Option<String>> {
    if !present(value, key) {
        return Ok(None);
    }
    let text =
        safe_string(value, key).with_context(|| format!("Weles response {key} is not a string"))?;
    if !uuid_shaped(&text)? {
        bail!("Weles response {key} must be a lowercase 8-4-4-4-12 hexadecimal UUID");
    }
    Ok(Some(text))
}

pub(in crate::credential) fn hex_digest(value: &str) -> Result<bool> {
    let width: usize = "64".parse()?;
    Ok(value.len() == width && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

// The only timestamp shape Skarbiec writes or accepts: zulu seconds, with an
// optional fraction, so two stamps compare as text.
pub(in crate::credential) fn timestamp_shaped(value: &str) -> bool {
    let Some((date, rest)) = value.split_once('T') else {
        return false;
    };
    let Some(time) = rest.strip_suffix('Z') else {
        return false;
    };
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (time, None),
    };
    let date_widths = ["4", "2", "2"];
    let clock_widths = ["2", "2", "2"];
    let date_groups: Vec<&str> = date.split('-').collect();
    let clock_groups: Vec<&str> = clock.split(':').collect();
    let digits = |group: &&str, width: &&str| {
        width
            .parse::<usize>()
            .is_ok_and(|width| group.len() == width)
            && group.bytes().all(|byte| byte.is_ascii_digit())
    };
    let fraction_max: usize = "6".parse().unwrap_or_default();
    date_groups.len() == date_widths.len()
        && clock_groups.len() == clock_widths.len()
        && date_groups
            .iter()
            .zip(date_widths.iter())
            .all(|(group, width)| digits(group, width))
        && clock_groups
            .iter()
            .zip(clock_widths.iter())
            .all(|(group, width)| digits(group, width))
        && fraction.is_none_or(|fraction| {
            !fraction.is_empty()
                && fraction.len() <= fraction_max
                && fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
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

pub(in crate::credential) fn zulu_seconds(value: &str) -> String {
    value
        .trim_end_matches('Z')
        .split('.')
        .next()
        .unwrap_or_default()
        .to_string()
}

pub(in crate::credential) fn uuid_shaped(value: &str) -> Result<bool> {
    let expected = ["8", "4", "4", "4", "12"];
    let groups: Vec<&str> = value.split('-').collect();
    Ok(groups.len() == expected.len()
        && groups.iter().zip(expected.iter()).all(|(group, width)| {
            width
                .parse::<usize>()
                .is_ok_and(|width| group.len() == width)
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        }))
}
