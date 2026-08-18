// Whether one item may enter the directory credential lifecycle at all: the
// canonical-field contract enforced before an operation starts, and the
// blocker list `credential status` reports.
//
// The field an item carries is the field its registered consumers already
// read. A lifecycle that wrote a different name would leave the password the
// provider now accepts in a key nobody resolves, so a mismatch is refused by
// name. There is no alias from one field to another and no automatic
// migration: two names for one credential is the ambiguity being removed, not
// a case to paper over.

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::core::inbox;
use crate::core::schema;
use crate::core::vault::Vault;

use super::state::{live_item_exists, quarantine_active};
use super::wire::operation_contract_field;
use super::FIELD_CONTRACT_MISMATCH;

// Why an item is not eligible. Each reason is a stable code; the detail beside
// it names the exact values an operator has to act on.
pub(super) const BLOCKER_LEGACY_ENVELOPE: &str = "legacy_envelope";
pub(super) const BLOCKER_NONCANONICAL_FIELD: &str = "noncanonical_field";
pub(super) const BLOCKER_NO_DIRECTORY_CONTRACT: &str = "no_directory_contract";
pub(super) const BLOCKER_QUARANTINED: &str = "quarantined";

fn blocker(reason: &str, detail: String) -> Value {
    json!({"reason": reason, "detail": detail})
}

// A live item still on the pre-v2 envelope. Its payload cannot be read or
// rewritten at all, so no lifecycle operation can reach it.
fn legacy_envelope(vault: &Vault, credential_id: &str) -> bool {
    let Some(item) = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(credential_id))
    else {
        return false;
    };
    item.get("format").and_then(Value::as_u64) != Some(crate::core::vault::current_envelope())
}

// The fields the item actually carries, sorted, or None when the payload
// cannot be read: no item, a legacy envelope, or a key this operator does not
// hold. An unreadable payload is never treated as a matching one.
fn item_fields(vault: &Vault, credential_id: &str) -> Option<Vec<String>> {
    let payload = vault.get_item(credential_id).ok()?;
    let mut names: Vec<String> = schema::fields(&payload).ok()?.keys().cloned().collect();
    names.sort();
    Some(names)
}

// The one field this provider's contract writes, refused unless the managed
// item already carries exactly that name. Only a managed item is judged here:
// an item outside Weles management is refused for a more fundamental reason
// than its field names, and one it cannot be talked out of.
pub(super) fn enforce_field_contract(
    vault: &Vault,
    credential_id: &str,
    provider: &str,
    required: &str,
) -> Result<()> {
    if !inbox::managed_by_weles(vault, credential_id) {
        return Ok(());
    }
    // No readable payload means no item to contradict the contract: acquire
    // and adopt create one, and a legacy envelope is refused by the envelope
    // guards themselves.
    let Some(fields) = item_fields(vault, credential_id) else {
        return Ok(());
    };
    if fields.iter().any(|name| name == required) {
        return Ok(());
    }
    let carried = fields.join(", ");
    bail!(
        "{FIELD_CONTRACT_MISMATCH}: {credential_id} carries {carried} and no {required}, but the {provider} credential contract writes {required}. Skarbiec adds no alias and writes no second field beside {carried}: migrate the item to {required} as an explicit operator decision before any lifecycle operation"
    );
}

// Every reason this item cannot enter the directory credential lifecycle, in
// one pass. One `credential status` answers the whole question, so the list is
// never cut short at the first reason an operator would have hit.
pub(super) fn lifecycle_blockers(
    vault: &Vault,
    credential_id: &str,
    provider: Option<&str>,
    directory: Option<&Value>,
    operation: Option<&str>,
) -> Vec<Value> {
    let mut blockers = Vec::new();
    let sealed_provider = directory
        .and_then(|block| block.get("provider"))
        .and_then(Value::as_str);
    if live_item_exists(vault, credential_id) {
        if legacy_envelope(vault, credential_id) {
            blockers.push(blocker(
                BLOCKER_LEGACY_ENVELOPE,
                format!(
                    "{credential_id} still uses the pre-v2 envelope; run migrate-v2 before any lifecycle operation"
                ),
            ));
        // A legacy envelope hides the payload, so the field cannot be judged
        // until that envelope is gone. It is the blocker to clear first, not a
        // reason to stop listing the others.
        } else if let Some(required) = provider
            .or(sealed_provider)
            .map(|provider| operation_contract_field(operation.unwrap_or_default(), provider))
        {
            if let Some(fields) = item_fields(vault, credential_id) {
                if !fields.iter().any(|name| name == required) {
                    let carried = fields.join(", ");
                    blockers.push(blocker(
                        BLOCKER_NONCANONICAL_FIELD,
                        format!(
                            "{credential_id} carries {carried}, not the {required} its provider contract writes; migrating it is an explicit operator decision"
                        ),
                    ));
                }
            }
        }
    }
    // A contract that cannot be resolved to one block — absent, or two copies
    // that disagree — is no contract to run a directory lifecycle against.
    // Subscription reauth names a login item, which no directory holds and no
    // seal describes; demanding one would report a blocker the operation does
    // not have.
    if directory.is_none() && operation != Some("reauth") {
        blockers.push(blocker(
            BLOCKER_NO_DIRECTORY_CONTRACT,
            format!(
                "{credential_id} has no sealed directory block; seal it with credential seal-directory before any lifecycle operation"
            ),
        ));
    }
    if quarantine_active(vault, credential_id) {
        blockers.push(blocker(
            BLOCKER_QUARANTINED,
            format!(
                "{credential_id} is quarantined until credential resolve-quarantine settles it"
            ),
        ));
    }
    blockers
}
