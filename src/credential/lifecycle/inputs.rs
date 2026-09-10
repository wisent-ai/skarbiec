// What an operator asked for, once: the flags a credential operation accepts,
// and the item contract that decides the rest.
//
// Directory identity and the canonical field are read from the item, never
// taken as arguments, so a caller cannot name a field the item does not carry.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::core::vault::Vault;

use super::super::common::{email_address, exact_name, purpose};
use super::super::directory::{cross_check_expectations, resolved_directory, wire_directory};
use super::super::eligibility::enforce_field_contract;
use super::super::state::refuse_quarantined;
use super::super::wire::{
    declared_signup_origin, generic_credential_id, generic_provider, provider_contract,
};

/// One validated submission: every value the operation needs, resolved once.
pub(super) struct Submission<'a> {
    pub(super) operation: &'a str,
    pub(super) credential_id: &'a str,
    pub(super) provider: &'a str,
    pub(super) consumer: &'a str,
    pub(super) purpose: String,
    pub(super) account: Option<String>,
    pub(super) signup_origin: Option<String>,
    pub(super) dry_run: bool,
    pub(super) directory: Option<Value>,
    pub(super) field: &'static str,
    pub(super) wire_block: Option<Value>,
}

pub(super) fn read_submission<'a>(
    operation: &'a str,
    vault_path: &Path,
    flags: &'a HashMap<String, String>,
    args: &'a [String],
) -> Result<Submission<'a>> {
    let allowed = [
        "provider",
        "consumer",
        "purpose",
        "account",
        "expect-tenant",
        "expect-object-id",
        "expect-upn",
        "password-stdin",
        "dry-run",
        "signup-origin",
        "local",
    ];
    // Only acquire may leave the item id out: it is the one operation that can
    // name a credential nobody holds yet, and a generic provider already names
    // it.
    let item_argument = if operation == "acquire" {
        "[<item-id>]"
    } else {
        "<item-id>"
    };
    let usage = format!(
        "usage: credential {operation} {item_argument} --provider <provider> --consumer <consumer> [--account <email>] [--signup-origin https://<host>] [--expect-tenant <uuid>] [--expect-object-id <uuid>] [--expect-upn <email>] [--purpose <purpose>] [--dry-run]; a generic provider's item id defaults to its slug"
    );
    if flags.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{usage}");
    }
    let password_stdin = flags
        .get("password-stdin")
        .is_some_and(|value| value == "true");
    if operation == "adopt" && !password_stdin {
        bail!(
            "credential adopt requires --password-stdin: the current password is read from stdin and never from argv"
        );
    }
    if operation != "adopt" && password_stdin {
        bail!("--password-stdin is accepted only by credential adopt");
    }
    let provider = flags.get("provider").context("--provider is required")?;
    exact_name("provider", provider, "128".parse()?)?;
    let credential_id = match args.first() {
        Some(named) => named.as_str(),
        None if operation == "acquire" && generic_provider(provider) => {
            generic_credential_id(provider)?
        }
        None => bail!("{usage}"),
    };
    let consumer = flags.get("consumer").context("--consumer is required")?;
    exact_name("credential item id", credential_id, "200".parse()?)?;
    exact_name("consumer", consumer, "200".parse()?)?;
    let purpose = purpose(flags.get("purpose"), consumer)?;
    let account = email_address("--account", flags.get("account"))?;
    // Where the account this acquisition registers is signed up. Weles echoes
    // the origin it captured at, and the managed write is refused unless the
    // two agree, so the declaration is recorded before anything is submitted.
    let signup_origin = declared_signup_origin(operation, provider, flags.get("signup-origin"))?;
    let dry_run = flags.get("dry-run").is_some_and(|value| value == "true");
    if operation == "adopt" && dry_run {
        bail!("credential adopt stages an operator-supplied password and has no dry run");
    }

    // Directory identity and the canonical field are both item contract: read
    // them, cross-check them, never take either as an argument.
    let (directory, field) = {
        let vault = Vault::open(vault_path.to_path_buf())?;
        refuse_quarantined(&vault, credential_id, operation)?;
        let directory = resolved_directory(&vault, credential_id)?;
        cross_check_expectations(flags, credential_id, directory.as_ref())?;
        let field = provider_contract(
            operation,
            provider,
            credential_id,
            account.as_deref(),
            directory.as_ref(),
        )?;
        // The item's own field decides whether it is eligible at all. A
        // provider contract that writes another name is refused here, before
        // the operation lock, the record, or the bridge.
        enforce_field_contract(&vault, credential_id, provider, field)?;
        (directory, field)
    };
    let wire_block = match directory.as_ref() {
        Some(sealed) => Some(wire_directory(sealed)?),
        None => None,
    };

    Ok(Submission {
        operation,
        credential_id,
        provider,
        consumer,
        purpose,
        account,
        signup_origin,
        dry_run,
        directory,
        field,
        wire_block,
    })
}
