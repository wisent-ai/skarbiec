// Staging the password an operator supplied: the shape the adopt started
// with, the candidate it writes, and the item it removes if the adopt fails.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::path::Path;

use crate::core::vault::{ManagedWrite, Vault};
use crate::core::schema;
use crate::runtime::audit;

use super::super::common::now_iso;
use super::super::state::{
    context_block, item_revision, live_item_exists, store_context,
};
use super::super::STATE_ADOPTING;
use super::{adopt_candidate_kind, lifecycle_request, AdoptShape};

// Everything one adopt staging is bound to. Grouped so the staging call names
// one contract instead of a positional list.
pub(in crate::credential) struct AdoptStaging<'a> {
    pub(in crate::credential) shape: AdoptShape,
    pub(in crate::credential) credential_id: &'a str,
    pub(in crate::credential) field: &'a str,
    pub(in crate::credential) consumer: &'a str,
    pub(in crate::credential) request_id: &'a str,
    pub(in crate::credential) account: Option<&'a str>,
    pub(in crate::credential) directory: Option<&'a Value>,
}

// The candidate lands exactly where the rest of the lifecycle expects a staged
// value, bound to this request id and this exact writer. Returns the baseline
// revision the wire will carry.
pub(in crate::credential) fn stage_adopted_candidate(
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
pub(in crate::credential) fn trash_adopted_item(
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
