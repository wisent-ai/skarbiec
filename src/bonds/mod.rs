// Bond operations: the bond configuration commands (bond-add/bond-list/
// bond-remove), the enroll client that registers a replica's key with a
// source serve, the replication components `serve` runs for every bond this
// vault pulls, and the sync-status report. There is no separate sync daemon
// and no unit to create: the host's one `skarbiec serve` process replicates.
//
// | part | what it owns |
// |---|---|
// | `config` | adding, listing and removing a bond in the vault |
// | `enroll` | registering this replica's key with a source serve |
// | `sync` | the replication component `serve` runs, and the status report |
//
// Every part opens with `use super::*;`, so the list below is this
// module's single import list.

pub(crate) use anyhow::{Context, Result};
pub(crate) use serde_json::{json, Value};
pub(crate) use std::collections::HashMap;
pub(crate) use std::thread;
pub(crate) use std::time::Duration;

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
        "bond-add" => cmd_bond_add(flags, positionals).map(Some),
        "bond-list" | "bonds" => cmd_bond_list().map(Some),
        "bond-remove" => cmd_bond_remove(positionals).map(Some),
        "enroll" => cmd_enroll(flags).map(Some),
        "sync-status" => cmd_sync_status(flags).map(Some),
        _ => Ok(None),
    }
}
