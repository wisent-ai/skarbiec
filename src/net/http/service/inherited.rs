//! The loopback ports the retired units answered on, kept beside the vault.
//!
//! The one process learns those ports from its predecessors' running
//! processes, which exist only until the first take-over. Any start after
//! that, whether an upgrade, a crash or a reboot, would find no predecessor
//! and stop answering on them while consumers still dial them — a forward
//! marker and a Stado setting can each name a different inherited port. The
//! record makes every later start of the
//! declared unit answer where the first one did.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::core::vault_path;

/// `<vault>.inherited-ports.json`, beside the vault's other side state. A
/// vault path that names no file has no place beside it, and is refused.
fn record() -> Result<PathBuf> {
    let vault = vault_path();
    let mut name = vault
        .file_name()
        .with_context(|| {
            format!(
                "vault path {} names no file, so the inherited ports record has no place beside it",
                vault.display()
            )
        })?
        .to_owned();
    name.push(".inherited-ports.json");
    Ok(vault.with_file_name(name))
}

/// The ports the record holds and whether it exists. A host the previous
/// release converged kept no record, and its journal's `unit-retired` entries
/// name the ports instead. A record that exists and cannot be read or parsed
/// is an error naming it, because rewriting it from a partial set would stop
/// the ports consumers still dial from answering.
pub(super) fn remembered() -> Result<(BTreeSet<u16>, bool)> {
    let path = record()?;
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(|ports| (ports, true))
            .with_context(|| format!("{} is not a list of ports", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok((crate::runtime::audit::retired_ports()?, false))
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Keep `ports` for the next start, replacing the record in one rename.
pub(super) fn remember(ports: &BTreeSet<u16>) -> Result<()> {
    let path = record()?;
    let staged = path.with_extension("json.staged");
    std::fs::write(&staged, serde_json::to_vec(ports)?)
        .with_context(|| format!("write {}", staged.display()))?;
    std::fs::rename(&staged, &path).with_context(|| format!("replace {}", path.display()))
}
