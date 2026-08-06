// adopt: the operator's password arrives on stdin, is staged against one exact
// request id and writer, and stays unreadable to every other caller until the
// provider confirms it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::io::Read;
use std::path::Path;

use crate::core::vault::{ManagedWrite, Vault};
use crate::core::{crypto, inbox, schema};
use crate::runtime::audit;

use super::common::now_iso;
use super::state::{
    context_block, item_revision, live_item_exists, pending_matches_request, request_item_id,
    store_context,
};
use super::wire::{request_payload, WIRE_VERSION};
use super::STATE_ADOPTING;

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

// Everything one adopt staging is bound to. Grouped so the staging call names
// one contract instead of a positional list.
pub(super) struct AdoptStaging<'a> {
    pub(super) shape: AdoptShape,
    pub(super) credential_id: &'a str,
    pub(super) field: &'a str,
    pub(super) consumer: &'a str,
    pub(super) request_id: &'a str,
    pub(super) account: Option<&'a str>,
    pub(super) directory: Option<&'a Value>,
}

// The candidate lands exactly where the rest of the lifecycle expects a staged
// value, bound to this request id and this exact writer. Returns the baseline
// revision the wire will carry.
pub(super) fn stage_adopted_candidate(
    vault_path: &Path,
    staging: &AdoptStaging<'_>,
    candidate: &str,
) -> Result<u64> {
    let AdoptStaging {
        shape,
        credential_id,
        field,
        consumer,
        request_id,
        account,
        directory,
    } = *staging;
    let mut vault = Vault::open(vault_path.to_path_buf())?;
    let stamp = now_iso();
    match shape {
        AdoptShape::Staged => {
            if lifecycle_request(&vault, credential_id).as_deref() != Some(request_id) {
                store_context(
                    &mut vault,
                    credential_id,
                    &[(
                        "lifecycle",
                        json!({
                            "state": STATE_ADOPTING,
                            "candidate": "pending",
                            "operation": "adopt",
                            "request_id": request_id,
                            "updated_at": stamp,
                        }),
                    )],
                )?;
            }
            // The lifecycle marker is its own revision, so the candidate is
            // staged against exactly the revision the wire reports.
            let baseline = item_revision(&vault, credential_id)
                .context("adopted item has no current revision")?;
            vault.stage_managed_field(
                credential_id,
                field,
                Value::String(candidate.to_string()),
                baseline,
                ManagedWrite {
                    controller: "weles",
                    writer: consumer,
                    operation_id: Some(request_id),
                },
            )?;
            Ok(baseline)
        }
        AdoptShape::Created => {
            if live_item_exists(&vault, credential_id) {
                if lifecycle_request(&vault, credential_id).as_deref() != Some(request_id) {
                    bail!("{credential_id} exists but was not created by this adopt request");
                }
                return item_revision(&vault, credential_id)
                    .context("adopted item has no current revision");
            }
            let kind = adopt_candidate_kind(field)?;
            let account_ref = account.or_else(|| {
                directory
                    .and_then(|block| block.get("account_upn"))
                    .and_then(Value::as_str)
            });
            let mut fields = Map::new();
            if kind == "login" {
                let username = account_ref.context(
                    "credential adopt needs the account address of a login item; seal the directory contract or pass --account",
                )?;
                fields.insert("username".to_string(), json!(username));
            }
            fields.insert(field.to_string(), Value::String(candidate.to_string()));
            let mut context = Map::new();
            context.insert("operation".to_string(), json!("adopt"));
            context.insert("request_id".to_string(), json!(request_id));
            if let Some(account_ref) = account_ref {
                context.insert("account_ref".to_string(), json!(account_ref));
            }
            if let Some(directory) = directory {
                context.insert("directory".to_string(), directory.clone());
            }
            context.insert(
                "lifecycle".to_string(),
                json!({
                    "state": STATE_ADOPTING,
                    "candidate": "current",
                    "operation": "adopt",
                    "request_id": request_id,
                    "created": true,
                    "updated_at": stamp,
                }),
            );
            let payload = schema::payload(kind, fields, context)?;
            vault.set_managed_item(
                credential_id,
                kind,
                &payload,
                &[],
                &["managed:weles".to_string()],
                ManagedWrite {
                    controller: "weles",
                    writer: consumer,
                    operation_id: Some(request_id),
                },
            )?;
            item_revision(&vault, credential_id).context("adopted item has no current revision")
        }
    }
}

// Only the item this exact adopt created may be trashed on failure.
pub(super) fn trash_adopted_item(
    vault: &mut Vault,
    credential_id: &str,
    request_id: &str,
    writer: &str,
) -> Result<()> {
    let entry = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(credential_id))
        .cloned()
        .with_context(|| format!("adopted item disappeared: {credential_id}"))?;
    let lifecycle = context_block(vault, credential_id, "lifecycle").unwrap_or_default();
    let first_revision: u64 = "1".parse()?;
    let created_here = lifecycle.get("created").and_then(Value::as_bool) == Some(true)
        && lifecycle.get("request_id").and_then(Value::as_str) == Some(request_id)
        && lifecycle.get("state").and_then(Value::as_str) == Some(STATE_ADOPTING);
    let untouched_since_creation = entry.get("revision").and_then(Value::as_u64)
        == Some(first_revision)
        && entry
            .get("current")
            .and_then(|current| current.get("operation_id"))
            .and_then(Value::as_str)
            == Some(request_id)
        && entry
            .get("history")
            .and_then(Value::as_array)
            .is_none_or(|history| history.is_empty());
    if !created_here || !untouched_since_creation {
        bail!(
            "refusing to trash {credential_id}: it is not the item this adopt request created; resolve it by hand"
        );
    }
    vault.trash_managed_item(credential_id, "weles", writer)?;
    audit::append_sync(
        "credential-adopt-rolled-back",
        &json!({"credential": credential_id, "request_id": request_id}),
    )
}

pub(super) fn staged_field_value(
    vault: &Vault,
    credential_id: &str,
    field: &str,
) -> Result<Option<Value>> {
    let Some(pending) = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(credential_id))
        .and_then(|item| item.get("pending"))
        .cloned()
    else {
        return Ok(None);
    };
    let kind = pending
        .get("kind")
        .and_then(Value::as_str)
        .context("staged revision has no kind")?;
    let cipher = pending
        .get("ciphertext")
        .and_then(Value::as_str)
        .context("staged revision has no ciphertext")?;
    let plain = crypto::decrypt(cipher)?;
    let payload: Value =
        serde_json::from_str(&plain).context("decrypted staged revision is not JSON")?;
    schema::validate_payload(&payload, kind)?;
    Ok(Some(schema::field(&payload, field)?.clone()))
}

// What an acquisition read may return. The adopt candidate is readable only by
// the exact verification path: an active adopt for this item, that request id,
// that field, and that presenting consumer. Outside that window a candidate
// sitting as the current revision is unreadable.
pub(crate) fn managed_read(
    vault: &Vault,
    credential_id: &str,
    field: &str,
    consumer: &str,
) -> Result<ManagedRead> {
    let lifecycle = context_block(vault, credential_id, "lifecycle").unwrap_or_default();
    let adopting = lifecycle.get("state").and_then(Value::as_str) == Some(STATE_ADOPTING);
    let candidate_is_current =
        lifecycle.get("candidate").and_then(Value::as_str) == Some("current");
    let record = vault
        .get_item(&request_item_id(credential_id))
        .and_then(request_payload)
        .ok()
        .filter(|request| {
            request.get("version").and_then(Value::as_str) == Some(WIRE_VERSION)
                && request.get("operation").and_then(Value::as_str) == Some("adopt")
                && request.get("credential_id").and_then(Value::as_str) == Some(credential_id)
                && request.get("field").and_then(Value::as_str) == Some(field)
                && request.get("consumer").and_then(Value::as_str) == Some(consumer)
                && matches!(
                    request.get("status").and_then(Value::as_str),
                    Some("submitting" | "pending" | "needs_human_approval")
                )
        });
    if let Some(record) = record.as_ref() {
        let request_id = record
            .get("request_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if pending_matches_request(vault, credential_id, request_id, field, consumer) {
            if let Some(value) = staged_field_value(vault, credential_id, field)? {
                return Ok(ManagedRead::Staged(value));
            }
        }
        let created_candidate = adopting
            && candidate_is_current
            && lifecycle.get("request_id").and_then(Value::as_str) == Some(request_id)
            && inbox::written_by(vault, credential_id).as_deref() == Some(consumer);
        if created_candidate {
            return Ok(ManagedRead::Current);
        }
    }
    if adopting && candidate_is_current {
        return Ok(ManagedRead::Refused);
    }
    Ok(ManagedRead::Current)
}

// True when this caller may not see the item's current value because an
// unconfirmed adopt candidate is sitting in it. A read that cannot be judged
// is hidden too.
pub(crate) fn candidate_hidden(
    vault: &Vault,
    credential_id: &str,
    field: &str,
    consumer: &str,
) -> bool {
    !matches!(
        managed_read(vault, credential_id, field, consumer),
        Ok(ManagedRead::Current) | Ok(ManagedRead::Staged(_))
    )
}
