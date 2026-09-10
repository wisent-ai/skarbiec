// skarbiec — self-contained vault for sensitive values (Rust).
// Per-recipient gpg encryption, versioned items, trash/restore, generator.
// Access/runtime/net layers are wired in sibling modules. No numeric literals:
// counts/lengths arrive from argv via parse(), never as source constants.

mod access;
mod bonds;
mod browser;
mod cli;
mod core;
mod credential;
mod native_host;
mod net;
mod onboarding;
mod runtime;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

use cli::args::{emit, parse_args};
use cli::items::{cmd_backfill_item_uids, cmd_rename, cmd_retag, cmd_set, cmd_set_json};
use cli::reads::{
    cmd_delete, cmd_get, cmd_list, cmd_purge, cmd_reclaim, cmd_restore, cmd_restore_version,
};
use cli::tools::{cmd_export, cmd_generate, cmd_version};
use core::{crypto, items, vault::Vault};

/// One definition of "which vault": the core layer owns it (including the
/// request-scoped override the loopback operator API sets), and this crate
/// root keeps only the re-export its own commands already call.
fn vault_path() -> PathBuf {
    core::vault_path()
}

pub(crate) fn cmd_init(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let owner = positionals
        .first()
        .or_else(|| flags.get("owner"))
        .map(String::as_str)
        .context("usage: init <owner-uid>")?;
    let recovery_uid = format!("skarbiec-recovery <{owner}>");
    let owner_fpr = match crypto::fingerprint_for(owner)? {
        Some(fpr) => fpr,
        None => crypto::generate_key(owner)?,
    };
    let recovery_fpr = match crypto::fingerprint_for(&recovery_uid)? {
        Some(fpr) => fpr,
        None => crypto::generate_key(&recovery_uid)?,
    };
    let vault = Vault::create(vault_path(), owner, &owner_fpr, &recovery_fpr)?;
    Ok(
        json!({"ok": true, "vault": vault.path.display().to_string(), "owner_fpr": owner_fpr, "recovery_fpr": recovery_fpr}),
    )
}

fn main() -> Result<()> {
    let mut argv = std::env::args();
    argv.next();
    let command = argv.next().unwrap_or_else(|| "help".to_string());
    let rest: Vec<String> = argv.collect();
    let (flags, positionals) = parse_args(&rest);

    match command.as_str() {
        "version" | "--version" | "-V" => emit(&cmd_version()?),
        "status" => emit(&core::items::status_json()?),
        "doctor" => emit(&runtime::doctor::report()?),
        "recover-daemons" => emit(&runtime::doctor::recover_daemons()?),
        "vaults" => emit(&runtime::vaults::inventory()?),
        "init" => emit(&cmd_init(&flags, &positionals)?),
        "set" => cmd_set(&flags, &positionals),
        "get" => cmd_get(&flags, &positionals),
        "set-json" => cmd_set_json(&flags, &positionals),
        "list" => emit(&cmd_list(&flags)?),
        "retag" => cmd_retag(&flags, &positionals),
        "rename" => cmd_rename(&positionals),
        "backfill-item-uids" => cmd_backfill_item_uids(),
        "delete" => emit(&cmd_delete(&positionals)?),
        "reclaim" => emit(&cmd_reclaim(&positionals)?),
        "restore" => emit(&cmd_restore(&positionals)?),
        "purge" => emit(&cmd_purge(&positionals)?),
        "restore-version" => cmd_restore_version(&positionals),
        "generate" => cmd_generate(&flags),
        "import" => emit(&core::importer::run(&flags, &positionals)?),
        "migrate" => emit(&items::migrate_vault(&flags)?),
        "migrate-v2" => emit(&items::migrate_v2(&flags)?),
        "export" => cmd_export(&flags, &positionals),
        "onboarding" => emit(&onboarding::run(&flags)?),
        // The advertised list is the contract: a command that is dispatchable but
        // absent here is private, and no caller can be told to rely on it. The
        // release classifier compares exactly this surface, so `version` had to
        // arrive here as well as in the dispatcher before docs could point at it.
        "help" => emit(
            &json!({"groups": ["grant","route","credential"], "commands": ["status","doctor","recover-daemons","vaults","init","set","set-json","get","list","retag","rename","backfill-item-uids","delete","reclaim","restore","purge","restore-version","generate","import","migrate","migrate-v2","add-user","rotate-owner","share","revoke","users","export-key","grant","acquisition-request","acquisition-read","key-doctor","recovery-status","recovery-drill","emergency-grant","emergency-cancel","emergency-list","emergency-activate","policy-set","policy-get","policy-check-length","audit","audit-query","audit-epoch-start","verify-chain","route","totp","totp-seed-state","breach-check","sync-init","sync-push","sync-pull","pull","donate","donations","donation-accept","donation-reject","enroll","sync-daemon","sync-status","bond-add","bond-list","bond-remove","capability-serve","credential","apple-challenge-put","version"]}),
        ),
        "mcp" => net::mcp::serve(),
        "native-host" => native_host::run(),
        "browser-host-install" => emit(&browser::install_host(&flags)?),
        other => {
            if let Some(v) = credential::dispatch(other, &flags, &positionals, &vault_path())? {
                emit(&v)
            } else if let Some(v) = access::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = runtime::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = net::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = bonds::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else if let Some(v) = core::inbox::dispatch(other, &flags, &positionals)? {
                emit(&v)
            } else {
                bail!("unknown command: {other}")
            }
        }
    }
}
