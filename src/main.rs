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

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

use cli::args::{emit, parse_args, OrUsage, Usage};
use cli::generate::cmd_generate;
use cli::items::{cmd_retag, cmd_set_json};
use cli::list::cmd_list;
use cli::reads::{
    cmd_delete, cmd_duplicates, cmd_get, cmd_history, cmd_purge, cmd_readers, cmd_reclaim,
    cmd_restore,
};
use cli::rename::cmd_rename;
use cli::tools::{cmd_export, cmd_tags, cmd_version};
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
    // Refused before any key is made: an init a client host or an existing
    // vault refuses must not leave new keys in the keyring.
    let path = vault_path();
    Vault::creatable(&path)?;
    let recovery_uid = format!("skarbiec-recovery <{owner}>");
    let owner_fpr = match crypto::fingerprint_for(owner)? {
        Some(fpr) => fpr,
        None => crypto::generate_key(owner)?,
    };
    let recovery_fpr = match crypto::fingerprint_for(&recovery_uid)? {
        Some(fpr) => fpr,
        None => crypto::generate_key(&recovery_uid)?,
    };
    let vault = Vault::create(path, owner, &owner_fpr, &recovery_fpr)?;
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
    // Docker runs a credential helper by the program name
    // docker-credential-skarbiec, linked to this binary by `helper setup
    // docker`; started under that name, the words are Docker's protocol.
    let started_as = argv.next();
    let program = started_as
        .as_deref()
        .map(std::path::Path::new)
        .and_then(std::path::Path::file_name);
    if program.and_then(std::ffi::OsStr::to_str) == Some(runtime::dockercred::PROGRAM) {
        return runtime::dockercred::run(&argv.collect::<Vec<_>>());
    }
    // Terraform runs terraform-credentials-skarbiec from its plugin directory,
    // linked by `helper setup terraform`, with the action and the host.
    if program.and_then(std::ffi::OsStr::to_str) == Some(runtime::tfcred::PROGRAM) {
        return runtime::tfcred::run(&argv.collect::<Vec<_>>());
    }
    // `skarbiec` with no command is a request for the command list.
    let command = match argv.next() {
        Some(command) => command,
        None => "help".to_string(),
    };
    // A browser starts the native-messaging host the manifest names with
    // its own arguments, never a command of ours.
    if browser::launched(&command)? {
        return native_host::run();
    }
    let mut rest: Vec<String> = argv.collect();
    // `exec` hands every word after `--` to the program it runs untouched,
    // `--help` and `--text` included, so it is taken before either is read
    // here; `--help` before the `--` still asks for its help.
    if command == "exec" {
        let ours = match rest.iter().position(|word| word == "--") {
            Some(split) => &rest[..split],
            None => &rest[..],
        };
        if ours.iter().any(|word| word == "--help" || word == "-h") {
            return cli::help::print_command(&command);
        }
        return runtime::exec::run(&rest);
    }
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
        } else if command != "help" && !cli::help::answers_own_help(&command) {
            // A command the help table declares as answering `--help`
            // itself (the importer, with its formats and limits) is handed
            // the flag; every other command is answered here.
            return cli::help::print_command(&command);
        }
    }
    let (mut flags, positionals) = parse_args(&rest);
    // `--fence T` lets this invocation's writes pass a write fence armed for
    // transaction T (a vault move's own steps); every command takes it, so it
    // is taken out before any command sees its flags.
    if let Some(transaction) = flags.remove("fence") {
        core::vault::fence::pass(&transaction);
    }
    if net::owner::dispatch(&command, &flags, &positionals)? {
        return Ok(());
    }

    match command.as_str() {
        "version" | "--version" | "-V" => emit(&cmd_version()?),
        "status" => emit(&core::items::status_json()?),
        "doctor" => {
            if cli::args::flag_set(&flags, "alert") {
                emit(&runtime::doctor::report_alerting(
                    flags.get("tail").map(String::as_str),
                )?)
            } else {
                emit(&runtime::doctor::report(
                    flags.get("tail").map(String::as_str),
                )?)
            }
        }
        "vaults" => emit(&runtime::vaults::inventory()?),
        "fence" => emit(&core::vault::fence::command(&flags, &positionals)?),
        "init" => emit(&cmd_init(&flags, &positionals)?),
        "get" => cmd_get(&flags, &positionals),
        "set" => cmd_set_json(&flags, &positionals),
        "list" => emit(&cmd_list(&flags)?),
        "duplicates" => emit(&cmd_duplicates()?),
        "readers" => emit(&cmd_readers(&positionals)?),
        "history" => emit(&cmd_history(&flags, &positionals)?),
        "tags" => emit(&cmd_tags(&flags)?),
        "retag" => cmd_retag(&flags, &positionals),
        "rename" => cmd_rename(&flags, &positionals),
        "delete" => match cli::bulk::delete_set(&flags) {
            Some(answer) => emit(&answer?),
            None => emit(&cmd_delete(&positionals)?),
        },
        "merge" => emit(&cli::merge::merge_value(&positionals)?),
        "copy" => emit(&cli::copy::copy_value(&flags, &positionals)?),
        "reclaim" => emit(&cmd_reclaim(&positionals)?),
        "restore" => match flags.get("tag") {
            Some(tag) => emit(&cli::bulk::restore_tagged(&flags, tag)?),
            None => emit(&cmd_restore(
                &positionals,
                flags.get("at").map(String::as_str),
            )?),
        },
        "purge" => match (flags.get("trashed-before"), flags.get("versions-before")) {
            (Some(before), _) => emit(&cli::tools::cmd_purge_trash(&flags, &positionals, before)?),
            (None, Some(before)) => {
                emit(&cli::prune::purge_versions(&flags, &positionals, before)?)
            }
            (None, None) => emit(&cmd_purge(
                &positionals,
                cli::args::flag_set(&flags, "yes"),
            )?),
        },
        "generate" => cmd_generate(&flags),
        "agent" => match cli::args::verb(&command, &positionals, "agent", "enrol") {
            Some(rest) => emit(&access::agent::enrol(rest)?),
            None => Err(Usage(format!(
                "agent {} is not a form of agent; usage: agent enrol <agent>",
                positionals.join(" ")
            ))
            .into()),
        },
        "import" => emit(&core::importer::run(&flags, &positionals)?),
        "migrate" => emit(&items::migrate_vault(&flags)?),
        "upgrade" => emit(&items::upgrade(&flags)?),
        "export" => cmd_export(&flags, &positionals),
        "onboarding" => emit(&onboarding::run(&flags)?),
        "help" => emit(&cli::help::listing()),
        // The script itself, not JSON: a shell sources it as printed. bash's
        // is the one completion has always printed; fish is asked for by name.
        "completion" => {
            let script = match flags.get("shell").map(String::as_str) {
                None => cli::help::bash_script(),
                Some("bash") => cli::help::bash_script(),
                Some("fish") => cli::help::fish_script(),
                Some(other) => {
                    return Err(Usage(format!("completion --shell {other}: skarbiec writes bash and fish completion; zsh loads the bash one")).into())
                }
            };
            print!("{script}");
            Ok(())
        }
        "mcp" => net::mcp::serve(&positionals),
        "browser" => browser::command(&flags, &positionals),
        // `helper answer <tool>` is the tool's protocol, answered on standard
        // output in the tool's own words; the rest answer as every command does.
        "helper" => match runtime::helper::command(&flags, &positionals)? {
            Some(answer) => emit(&answer),
            None => Ok(()),
        },
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
            } else if let Some(usage) = cli::help::usage_of(other) {
                Err(Usage(format!(
                    "{other} {} is not a form of {other}; usage: {usage}",
                    positionals.join(" ")
                ))
                .into())
            } else {
                Err(Usage(format!(
                    "unknown command: {other}; `skarbiec --help` lists every command"
                ))
                .into())
            }
        }
    }
}
