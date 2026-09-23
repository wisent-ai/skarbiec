//! The loopback ports the retired units answered on, kept beside the vault.
//!
//! The one process learns those ports from its predecessors' running
//! processes, which exist only until the first take-over. Any start after
//! that, whether an upgrade, a crash or a reboot, found no predecessor and
//! stopped answering on them while consumers still dialled them: on
//! lukasz-macbook `~/.stado/forwards/skarbiec.local` names 8787 and Stado's
//! `agent_skarbiec_url` names 8799. The record makes every later start of the
//! declared unit answer where the first one did.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::core::vault_path;

/// `<vault>.inherited-ports.json`, beside the vault's other side state.
fn record() -> PathBuf {
    let vault = vault_path();
    let mut name = vault.file_name().map(ToOwned::to_owned).unwrap_or_default();
    name.push(".inherited-ports.json");
    vault.with_file_name(name)
}

/// The ports the record holds and whether it exists. A host the previous
/// release converged kept no record, and its journal's `unit-retired` entries
/// name the ports instead.
pub(super) fn remembered() -> (BTreeSet<u16>, bool) {
    match std::fs::read(record()) {
        Ok(bytes) => (serde_json::from_slice(&bytes).unwrap_or_default(), true),
        Err(_) => (crate::runtime::audit::retired_ports(), false),
    }
}

/// Keep `ports` for the next start, replacing the record in one rename.
pub(super) fn remember(ports: &BTreeSet<u16>) -> Result<()> {
    let path = record();
    let staged = path.with_extension("json.staged");
    std::fs::write(&staged, serde_json::to_vec(ports)?)
        .with_context(|| format!("write {}", staged.display()))?;
    std::fs::rename(&staged, &path).with_context(|| format!("replace {}", path.display()))
}
