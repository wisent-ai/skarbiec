// Credential lifecycle against the canonical Skarbiec.
//
// The directory identity of an item (provider, tenant, principal object id,
// account UPN) is a sealed item contract, written once by `credential
// seal-directory` and changed only by `credential reseal`. No lifecycle call
// carries it: Skarbiec reads it from the item and puts it on the wire, so no
// caller can rotate one principal's password while naming another. The
// `--expect-*` flags are a cross-check only, refused before anything is
// submitted.
//
// Every `credential` command is a thin client of the canonical Skarbiec
// (`POST /v1/credential/operations`) unless `--local` names this vault file.

mod adopt;
mod client;
mod common;
mod directory;
mod eligibility;
mod lifecycle;
mod quarantine;
mod receipt;
mod serve;
mod state;
mod status;
mod wire;

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

pub(crate) use adopt::{candidate_hidden, managed_read, ManagedRead};
pub(crate) use serve::{
    endpoint_item, exact_credential_item, status_from_endpoint, submit_from_endpoint,
};
pub(crate) use state::{authorize_managed_write, lifecycle_owned_item};

use client::{declare_canonical_endpoint, remote_operation, remote_resume, remote_status};

pub(crate) use client::canonical_endpoint_report;
use directory::seal_directory;
use lifecycle::{resume, start_operation};
use quarantine::resolve_quarantine;
use status::status;
use wire::WIRE_VERSION;

const REQUEST_WRITER: &str = "skarbiec-credential-lifecycle";
const REQUEST_KIND: &str = "credential-operation";

// Every credential operation, in the order a lifecycle uses them.
pub(crate) const OPERATIONS: &[&str] = &["acquire", "adopt", "rotate", "reset", "verify", "remove"];

// Providers whose password lifecycle is bound to one exact directory identity.
const IDENTITY_PROVIDER: &str = "microsoft_entra";

// Provider bound to one exact consumer account address only.
const ACCOUNT_PROVIDER: &str = "microsoft";
const IDENTITY_OPERATIONS: &[&str] = &["adopt", "rotate", "verify", "reset"];

/// Where a Skarbiec serves when nobody said otherwise: `serve` binds this port
/// by default, so it is the only address a fresh machine can be told to use
/// without guessing.
const LOCAL_CANONICAL_ENDPOINT: &str = "http://127.0.0.1:8787";

// Operations the canonical endpoint accepts. adopt is missing on purpose: the
// current password is read from operator stdin and never travels.
const REMOTE_OPERATIONS: &[&str] = &["acquire", "rotate", "reset", "verify", "remove"];

// Lifecycle state of one credential item.
const STATE_UNMANAGED: &str = "unmanaged";
const STATE_MANAGED: &str = "managed";

// adopt has taken the operator's password but the provider has not confirmed it.
const STATE_ADOPTING: &str = "adopting";
const STATE_QUARANTINED: &str = "quarantined";

const ITEM_STATES: &[&str] = &[
    STATE_UNMANAGED,
    STATE_MANAGED,
    STATE_ADOPTING,
    STATE_QUARANTINED,
];

// Envelope marker for a frozen item: unlike the canonical context it can be
// written without re-encrypting a payload that carries a staged candidate.
pub(super) const QUARANTINE_TAG: &str = "lifecycle:quarantined";

// `credential resolve-quarantine --confirm` demands this exact sentence.
pub(super) const QUARANTINE_CONFIRMATION: &str =
    "I know which password this provider account accepts";

pub(super) const EXPECTATION_MISMATCH: &str = "DIRECTORY_EXPECTATION_MISMATCH";

// An item whose canonical field is not the field the provider contract writes
// is not migrated silently: it is refused by name.
pub(super) const FIELD_CONTRACT_MISMATCH: &str = "CREDENTIAL_FIELD_CONTRACT_MISMATCH";

pub(super) const RESPONSE_STATUSES: &[&str] = &[
    "operation_plan",
    "operation_queued",
    "operation_completed",
    "needs_configuration",
    "needs_human_approval",
    "unsupported_operation",
    "operation_failed",
    "unsupported_secret",
];

pub(super) const RESPONSE_PHASES: &[&str] = &[
    "admission",
    "placement",
    "credential_read",
    "entra_sign_in",
    "identity_verification",
    "password_change",
    "fresh_login_verification",
    "skarbiec_stage",
    "skarbiec_commit",
    "rollback",
];

pub(super) const ROLLBACK_STATUSES: &[&str] = &["none", "completed", "failed", "unknown"];

// What the operation did to the password the provider accepts. `unknown` is
// never retried: it quarantines the item.
pub(super) const PROVIDER_EFFECTS: &[&str] = &["none", "changed", "unknown"];

// Request states that end a `credential status --follow` watch.
pub(super) const TERMINAL_STATUSES: &[&str] = &[
    "completed",
    "operation_failed",
    "needs_human_approval",
    "inconsistent",
    "unsupported_operation",
    "unsupported_secret",
    "needs_configuration",
    "quarantined",
    "approval_expired",
    "quarantine_resolved",
];

pub(crate) const CREDENTIAL_OPERATIONS_PATH: &str = "/v1/credential/operations";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
    vault_path: &Path,
) -> Result<Option<Value>> {
    if command != "credential" {
        return Ok(None);
    }
    let subcommand = positionals.first().map(String::as_str).unwrap_or("help");
    let args = positionals
        .get(std::iter::once(()).count()..)
        .unwrap_or_default();
    // The canonical Skarbiec is the default target: `--local` is the only way
    // to act on this vault file directly.
    let local = flags.get("local").is_some_and(|value| value == "true");
    let mut client_flags = flags.clone();
    client_flags.remove("local");
    let value = match subcommand {
        // Administrative commands hold the vault file and the operator's own
        // secrets: they exist only in local mode.
        "seal-directory" | "reseal" | "resolve-quarantine" | "adopt" if !local => {
            bail!(
                "credential {subcommand} runs against the vault file it owns; rerun it with --local on the canonical Skarbiec host"
            );
        }
        "seal-directory" => seal_directory(vault_path, &client_flags, args, false)?,
        "reseal" => seal_directory(vault_path, &client_flags, args, true)?,
        "resolve-quarantine" => resolve_quarantine(vault_path, &client_flags, args)?,
        "adopt" => start_operation("adopt", vault_path, &client_flags, args)?,
        operation @ ("acquire" | "rotate" | "reset" | "verify" | "remove" | "reauth") => {
            if local {
                start_operation(operation, vault_path, &client_flags, args)?
            } else {
                remote_operation(operation, &client_flags, args)?
            }
        }
        "resume" => {
            if local {
                resume(vault_path, &client_flags, args)?
            } else {
                remote_resume(&client_flags, args)?
            }
        }
        "status" => {
            if local {
                status(vault_path, &client_flags, args)?
            } else {
                remote_status(&client_flags, args)?
            }
        }
        // Not gated on `--local`: this declares where the canonical Skarbiec
        // is, so requiring a working canonical Skarbiec to run it would be a
        // lock whose key is inside the box.
        "declare-endpoint" => {
            let endpoint = args
                .first()
                .map(String::as_str)
                .or_else(|| flags.get("url").map(String::as_str))
                .unwrap_or(LOCAL_CANONICAL_ENDPOINT);
            declare_canonical_endpoint(endpoint)?
        }
        "help" => json!({
            "commands": [
                "credential seal-directory",
                "credential reseal",
                "credential acquire",
                "credential adopt",
                "credential rotate",
                "credential reset",
                "credential verify",
                "credential remove",
                "credential reauth",
                "credential resume",
                "credential resolve-quarantine",
                "credential status",
                "credential declare-endpoint"
            ],
            "usage": "credential <acquire|rotate|reset|verify|remove|reauth> <item-id> --provider <provider> --consumer <consumer> [--purpose <purpose>] [--account <email>] [--signup-origin https://<host>] [--expect-tenant <uuid>] [--expect-object-id <uuid>] [--expect-upn <email>] --as <caller> --token-file <path>; reauth accepts a named login item and delegates browser authentication to Weles while Skarbiec remains the operation owner; an item named after a generic provider slug acquires that provider's api_key with no sealed contract; credential adopt <item-id> --provider <provider> --consumer <consumer> --password-stdin --local; credential seal-directory <item-id> --provider <provider> --tenant <uuid> --object-id <uuid> --account-upn <email> --local; credential reseal <item-id> ... --as <consumer> --token-file <path> --local; credential resume <item-id> --approval <id> --resume-token <token>; credential resolve-quarantine <item-id> --confirm '<phrase>' --as <consumer> --token-file <path> --local; credential status <item-id> [--follow]; credential declare-endpoint …",
            "wire": WIRE_VERSION,
            "item_states": ITEM_STATES,
            "provider_effects": PROVIDER_EFFECTS,
        }),
        other => bail!("unknown credential command: {other}"),
    };
    Ok(Some(value))
}
