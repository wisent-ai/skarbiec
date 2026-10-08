// Bond operations: the `bond` group (add, edit, list, remove), the enroll
// client that registers a replica's key with a
// source serve, one pull of every bond this vault pulls (run by
// `skarbiec maintain`), and the sync-status report.
//
// | part | what it owns |
// |---|---|
// | `config` | adding, listing and removing a bond in the vault |
// | `enroll` | registering this replica's key with a source serve |
// | `sync` | one pull per pulled bond, and the status report |
//
// Every part opens with `use super::*;`, so the list below is this
// module's single import list.

pub(crate) use anyhow::{Context, Result};
pub(crate) use serde_json::{json, Value};
pub(crate) use std::collections::HashMap;

pub(crate) use crate::core::{crypto, vault::Vault, vault_path};

mod config;
mod enroll;
mod sync;

pub(crate) use config::*;
pub(crate) use enroll::*;
pub(crate) use sync::*;

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "bond" => group(flags, positionals),
        // The operator route reads the list by its whole leaf name.
        "bond list" => cmd_bond_list().map(Some),
        "enroll" => cmd_enroll(flags).map(Some),
        "sync-status" => cmd_sync_status(flags).map(Some),
        _ => Ok(None),
    }
}

/// The `bond` group: the subcommand is the first positional and each leaf
/// reads the rest, so a leaf takes exactly the arguments its former
/// hyphenated verb took.
fn group(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Option<Value>> {
    let Some((subcommand, positionals)) = positionals.split_first() else {
        return Err(crate::cli::args::Usage(
            "bond needs a subcommand (add, edit, list or remove); `skarbiec bond help` lists them"
                .to_string(),
        )
        .into());
    };
    match subcommand.as_str() {
        "add" => cmd_bond_add(flags, positionals).map(Some),
        "edit" => cmd_bond_edit(flags, positionals).map(Some),
        "list" => cmd_bond_list().map(Some),
        "remove" => cmd_bond_remove(positionals).map(Some),
        "help" => Ok(Some(json!({
            "commands": [
                "bond add <name> --mode <replica|hub|p2p|git> --role <source|replica|consumer|peer> --channel <serve|git|file>:<address> [--peers <fpr,...>] [--interval <seconds>] [--token-file <path> [--consumer <name>]]",
                "bond edit <name> [--mode …] [--role …] [--channel …] [--peers …] [--interval …] [--token-file … [--consumer …]]",
                "bond list",
                "bond remove <name>",
            ],
            "usage": "A bond is one stored replication relationship of this vault. bond add creates one and refuses a name already configured, naming its mode and role; bond edit changes the flags it is given and keeps the rest, and the result passes the checks bond add applies; bond list prints every stored bond; bond remove deletes one.",
        }))),
        other => Err(crate::cli::args::Usage(format!(
            "unknown bond command: {other}; `skarbiec bond --help` lists them"
        ))
        .into()),
    }
}
