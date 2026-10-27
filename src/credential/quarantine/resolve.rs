// The operator path back out of quarantine: one confirmed decision about the
// staged candidate, recorded with who made it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::access::grant;
use crate::core::vault::Vault;
use crate::runtime::audit;

use super::super::common::{
    acquire_credential_operation_lock, client_identity, exact_name, now_iso,
};
use super::super::state::{
    context_block_checked, live_item_exists, pending_matches_request, quarantine_active,
    request_item_id, store_context, update_request,
};
use super::super::wire::request_payload;
use super::super::{QUARANTINE_CONFIRMATION, STATE_UNMANAGED};
use super::freeze::mark_quarantine_tag;

pub(in crate::credential) fn resolve_quarantine(
    vault_path: &Path,
    flags: &HashMap<String, String>,
    args: &[String],
) -> Result<Value> {
    let allowed = ["confirm", "staged", "as", "token-file", "local"];
    let usage = format!(
        "usage: credential quarantine resolve <item-id> --confirm '{QUARANTINE_CONFIRMATION}' [--staged keep|activate|discard] --as <consumer> --token-file <path>"
    );
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let credential_id = args.first().context(usage.clone())?;
    exact_name("credential item id", credential_id)?;
    if flags.get("confirm").map(String::as_str) != Some(QUARANTINE_CONFIRMATION) {
        bail!("{usage}");
    }
    // Without --staged the candidate is kept as it is.
    let decision = match flags.get("staged") {
        Some(name) => Staged::parse(name).context("--staged must be keep, activate, or discard")?,
        None => Staged::Keep,
    };
    let staged_decision = decision.as_str();
    let _lock = acquire_credential_operation_lock(vault_path)?;
    let mut vault = Vault::open(vault_path.to_path_buf())?;
    if !quarantine_active(&vault, credential_id) {
        bail!("{credential_id} is not quarantined");
    }
    let (consumer, token) = client_identity(flags)?;
    // The item may not exist yet (a quarantined acquire), in which case the
    // operation record is the only resource an admin capability can name.
    let admin_target = if live_item_exists(&vault, credential_id) {
        credential_id.to_string()
    } else {
        request_item_id(credential_id)
    };
    let admin = crate::access::actions::Action::Admin.as_str();
    if !grant::token_allows_action(&vault, &consumer, &token, admin, &admin_target)? {
        bail!("{consumer} holds no admin capability for {admin_target}");
    }
    let request_item = request_item_id(credential_id);
    // No record means nothing is staged; a record that exists but cannot be
    // read is refused, never read as nothing staged.
    let record = if live_item_exists(&vault, &request_item) {
        let read = vault.get_item(&request_item).and_then(request_payload);
        Some(read.with_context(|| {
            format!("{request_item} cannot be read, so whether a value is staged cannot be checked")
        })?)
    } else {
        None
    };
    // A record states the request, field and writer of the value it staged;
    // one that leaves any of them out is refused, never read as nothing staged.
    let request: Option<(String, String, String)> = match record.as_ref() {
        None => None,
        Some(record) => {
            let stated = |name: &str| -> Result<String> {
                record
                    .get(name)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .with_context(|| {
                        format!("{request_item} states no {name}, so the value it staged cannot be identified")
                    })
            };
            Some((stated("request_id")?, stated("field")?, stated("consumer")?))
        }
    };
    let request_id = request
        .as_ref()
        .map(|(request_id, _, _)| request_id.clone());
    let staged = request.as_ref().filter(|(request_id, field, writer)| {
        pending_matches_request(&vault, credential_id, request_id, field, writer)
    });
    match (staged, decision) {
        (Some((request_id, field, writer)), Staged::Activate) => {
            vault.activate_staged_revision(credential_id, request_id, field, writer)?;
        }
        (Some((request_id, field, writer)), Staged::Discard) => {
            vault.discard_staged_revision(credential_id, request_id, field, writer)?;
        }
        (_, Staged::Keep) => {}
        (None, _) => {
            bail!("{credential_id} has no staged revision belonging to the quarantined operation")
        }
    }
    let resolved_at = now_iso();
    if live_item_exists(&vault, credential_id) {
        mark_quarantine_tag(&mut vault, credential_id, false)?;
        let has_staged = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(credential_id))
            .and_then(|item| item.get("pending"))
            .is_some();
        if !has_staged {
            // The resolved record keeps the quarantine it replaced; one that cannot
            // be read is refused rather than recorded as none.
            let previous = context_block_checked(&vault, credential_id, "quarantine")?;
            store_context(
                &mut vault,
                credential_id,
                &[
                    (
                        "quarantine",
                        json!({
                            "state": "resolved",
                            "resolved_at": resolved_at,
                            "resolved_by": consumer,
                            "staged_decision": staged_decision,
                            "previous": previous,
                        }),
                    ),
                    (
                        // Knowing the password again is an explicit act: the
                        // item returns to unmanaged until adopt or verify
                        // proves the value.
                        "lifecycle",
                        json!({
                            "state": STATE_UNMANAGED,
                            "operation": "resolve-quarantine",
                            "request_id": request_id,
                            "updated_at": resolved_at,
                        }),
                    ),
                ],
            )?;
        }
    }
    if let Some(record) = record.as_ref() {
        update_request(
            vault_path,
            &request_item,
            record,
            "quarantine_resolved",
            None,
        )?;
    }
    audit::append_sync(
        "credential-quarantine-resolved",
        &json!({
            "credential": credential_id,
            "request_id": request_id,
            "resolved_by": consumer,
            "staged_decision": staged_decision,
        }),
    )?;
    Ok(json!({
        "ok": true,
        "status": STATE_UNMANAGED,
        "credential": credential_id,
        "staged_decision": staged_decision,
        "resolved_at": resolved_at,
    }))
}

/// What `--staged` decides about the quarantined operation's staged candidate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Staged {
    /// Leave the candidate staged.
    Keep,
    /// Make the candidate the current value.
    Activate,
    /// Drop the candidate.
    Discard,
}

impl Staged {
    const ALL: &'static [Staged] = &[Staged::Keep, Staged::Activate, Staged::Discard];

    fn as_str(self) -> &'static str {
        match self {
            Staged::Keep => "keep",
            Staged::Activate => "activate",
            Staged::Discard => "discard",
        }
    }

    fn parse(name: &str) -> Option<Staged> {
        Self::ALL
            .iter()
            .copied()
            .find(|choice| choice.as_str() == name)
    }
}
