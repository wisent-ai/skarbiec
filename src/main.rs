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

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

use cli::args::{emit, parse_args, OrUsage, Usage};
use cli::items::{cmd_rename, cmd_retag, cmd_set_json};
use cli::reads::{
    cmd_delete, cmd_duplicates, cmd_get, cmd_list, cmd_purge, cmd_reclaim, cmd_restore,
    cmd_restore_version,
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
        .or_usage("usage: init <owner-uid>")?;
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

/// Prints a failure the way `anyhow` always did (`Error: ` and its causes)
/// and exits with the documented status: 2 for a usage error, 1 otherwise.
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:?}");
            cli::args::exit_code(&error)
        }
    }
}

fn run() -> Result<()> {
    let mut argv = std::env::args();
    argv.next();
    let command = argv.next().unwrap_or_else(|| "help".to_string());
    let mut rest: Vec<String> = argv.collect();
    // `--text` renders any result for a person instead of as JSON; it is
    // taken out here so the flag parser never pairs it with the next word.
    cli::args::take_text_switch(&mut rest);
    // `--help` and `-h` ask for help at every level and never run the command
    // they follow: `skarbiec purge <id> --help` used to purge, because the flag
    // parser took `--help` for one more option. Help is text for a person;
    // `skarbiec help` is the same inventory as JSON for machines.
    if matches!(command.as_str(), "--help" | "-h") {
        cli::help::print_overview();
        return Ok(());
    }
    if rest.iter().any(|word| word == "--help" || word == "-h") {
        if cli::help::is_group(&command) {
            rest = vec!["help".to_string()];
        } else if command != "help" && command != "import" {
            // `import --help` is answered by the importer with its own usage,
            // formats and limits; every other command is answered here.
            return cli::help::print_command(&command);
        }
    }
    let (flags, positionals) = parse_args(&rest);

    match command.as_str() {
        "version" | "--version" | "-V" => emit(&cmd_version()?),
        "status" => emit(&core::items::status_json()?),
        "doctor" => emit(&runtime::doctor::report(flags.get("tail").map(String::as_str))?),
        "recover-daemons" => {
            // Exit 0 only when the daemons were replaced: the receipt is
            // printed either way, and a failed recovery fails the command
            // with gpgconf's own cause, so a caller never reads success.
            let receipt = runtime::doctor::recover_daemons()?;
            emit(&receipt)?;
            if receipt["recovered"] != json!(true) {
                bail!(
                    "recover-daemons: the GnuPG daemons were not replaced: {}",
                    receipt["detail"]
                        .as_str()
                        .unwrap_or("no cause was reported")
                );
            }
            Ok(())
        }
        "vaults" => emit(&runtime::vaults::inventory()?),
        "init" => emit(&cmd_init(&flags, &positionals)?),
        "get" => cmd_get(&flags, &positionals),
        "set-json" => cmd_set_json(&flags, &positionals),
        "list" => emit(&cmd_list(&flags)?),
        "duplicates" => emit(&cmd_duplicates()?),
        "retag" => cmd_retag(&flags, &positionals),
        "rename" => cmd_rename(&positionals),
        "delete" => emit(&cmd_delete(&positionals)?),
        "reclaim" => emit(&cmd_reclaim(&positionals)?),
        "restore" => emit(&cmd_restore(&positionals)?),
        "purge" => emit(&cmd_purge(
            &positionals,
            cli::args::flag_set(&flags, "yes"),
        )?),
        "restore-version" => cmd_restore_version(&positionals),
        "generate" => cmd_generate(&flags),
        "import" => emit(&core::importer::run(&flags, &positionals)?),
        "migrate" => emit(&items::migrate_vault(&flags)?),
        "upgrade" => emit(&items::upgrade(&flags)?),
        "export" => cmd_export(&flags, &positionals),
        "onboarding" => emit(&onboarding::run(&flags)?),
        "help" => emit(&cli::help::listing()),
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
                Err(Usage(format!(
                    "unknown command: {other}; `skarbiec --help` lists every command"
                ))
                .into())
            }
        }
    }
}
