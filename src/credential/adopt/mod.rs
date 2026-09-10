// adopt: the operator's password arrives on stdin, is staged against one exact
// request id and writer, and stays unreadable to every other caller until the
// provider confirms it.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::Read;

use crate::core::vault::Vault;

use super::state::context_block;

mod reads;
mod staging;

pub(crate) use reads::{candidate_hidden, managed_read};
pub(super) use staging::{stage_adopted_candidate, trash_adopted_item, AdoptStaging};

// How adopt holds the operator-supplied candidate until Weles confirms it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AdoptShape {
    // The item already exists under Weles management: the candidate is a
    // staged pending revision, exactly like rotate stages one.
    Staged,
    // The item does not exist yet. An item can only enter managed state at
    // creation, so adopt creates it and stays out of `managed` until the
    // provider confirms.
    Created,
}

impl AdoptShape {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Created => "created",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self> {
        match value {
            "staged" => Ok(Self::Staged),
            "created" => Ok(Self::Created),
            other => bail!("credential adopt record has an unsupported staging shape: {other}"),
        }
    }
}

// What an acquisition read may return for one exact item and field.
pub(crate) enum ManagedRead {
    // The active revision, as always.
    Current,
    // The adopt candidate staged for this exact operation and consumer.
    Staged(Value),
    // An adopt candidate is the current revision and this caller is not the
    // verification path that may read it.
    Refused,
}

// The operator's password arrives on stdin and nowhere else: never argv, never
// an endpoint body, never a log line. The read buffer is zeroed before return.
pub(super) fn read_password_stdin() -> Result<String> {
    let max: usize = "512".parse()?;
    let extra: u64 = "1".parse()?;
    let mut raw = Vec::new();
    std::io::stdin()
        .lock()
        .take(u64::try_from(max)?.saturating_add(extra))
        .read_to_end(&mut raw)?;
    if raw.len() > max {
        raw.fill(u8::MIN);
        bail!("adopted password must be at most {max} bytes");
    }
    let end = raw
        .iter()
        .rposition(|byte| !matches!(byte, b'\n' | b'\r'))
        .map(|index| index.saturating_add(std::iter::once(()).count()))
        .unwrap_or_default();
    let decoded = String::from_utf8(raw[..end].to_vec());
    raw.fill(u8::MIN);
    let candidate = decoded.map_err(|error| {
        let mut bytes = error.into_bytes();
        bytes.fill(u8::MIN);
        anyhow::Error::msg("adopted password must be valid UTF-8")
    })?;
    if candidate.is_empty() || candidate.chars().any(char::is_control) {
        let mut bytes = candidate.into_bytes();
        bytes.fill(u8::MIN);
        bail!("adopted password must be one non-empty line without control characters");
    }
    Ok(candidate)
}

// Overwrite the operator's password buffer once it has been staged.
pub(super) fn zeroize(candidate: String) {
    let mut bytes = candidate.into_bytes();
    bytes.fill(u8::MIN);
}

pub(super) fn adopt_candidate_kind(field: &str) -> Result<&'static str> {
    match field {
        "password" => Ok("login"),
        "api_key" => Ok("api-key"),
        other => bail!("credential adopt has no canonical item kind for field {other}"),
    }
}

pub(super) fn adopt_shape_of(request: &Value) -> Result<AdoptShape> {
    AdoptShape::parse(
        request
            .get("adopt_shape")
            .and_then(Value::as_str)
            .context("credential adopt record has no staging shape")?,
    )
}

pub(super) fn lifecycle_request(vault: &Vault, credential_id: &str) -> Option<String> {
    context_block(vault, credential_id, "lifecycle")
        .as_ref()
        .and_then(|block| block.get("request_id"))
        .and_then(Value::as_str)
        .map(str::to_string)
}
