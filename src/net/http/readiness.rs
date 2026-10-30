// What `/health` and `/readyz` prove. `/health`: the audit journal is
// writable and the vault document opens, decrypting nothing. `/readyz`:
// that, and one deterministic canary item still opens with the key material
// on this host. Both run in this process; neither waits on another program.

use anyhow::{Context, Result};
use serde_json::Value;

use super::load;
use crate::core::vault::Vault;

/// The items `/health` opens to prove the key material is still usable.
///
/// Deterministic (lowest and highest id among live items, then every item
/// `SKARBIEC_READINESS_ITEMS` names) so repeated probes exercise the same
/// ciphertext and a passing probe means the same thing every time. Only the
/// ids are returned; the caller decrypts and drops the values. A configured
/// item this vault does not hold is the error naming it, so the probe never
/// proves less than the operator asked for without saying so.
fn canary_item_ids(vault: &Vault) -> Result<Vec<String>> {
    let mut ids: Vec<String> = vault
        .list(false)
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    ids.sort();
    let mut canaries: Vec<String> = Vec::new();
    for id in [ids.first(), ids.last()].into_iter().flatten() {
        if !canaries.contains(id) {
            canaries.push(id.clone());
        }
    }
    let configured = crate::core::env::text("SKARBIEC_READINESS_ITEMS")?;
    for item in configured
        .iter()
        .flat_map(|list| list.split(','))
        .map(str::trim)
    {
        if item.is_empty() || canaries.iter().any(|canary| canary == item) {
            continue;
        }
        if !ids.iter().any(|id| id == item) {
            anyhow::bail!("SKARBIEC_READINESS_ITEMS names {item}, which this vault does not hold");
        }
        canaries.push(item.to_string());
    }
    Ok(canaries)
}

/// What `/health` proves: the audit journal takes an entry and the vault
/// document opens. Nothing is decrypted.
pub(super) fn health_check() -> Result<()> {
    crate::runtime::audit::probe().context("audit journal is not writable")?;
    load().context("vault is unreadable")?;
    Ok(())
}

/// What `/readyz` proves: that, and every canary item opens with the keys
/// this host holds.
pub(super) fn readiness_check() -> Result<Vec<String>> {
    crate::runtime::audit::probe().context("audit journal is not writable")?;
    let vault = load().context("vault is unreadable")?;
    let canaries = canary_item_ids(&vault)?;
    for id in &canaries {
        vault
            .get_item(id)
            .with_context(|| format!("stored item {id} cannot be decrypted"))?;
    }
    Ok(canaries)
}
