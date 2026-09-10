// What `/health` proves: the audit journal is writable and one deterministic
// canary item still opens with the key material on this host.

use anyhow::{Context, Result};
use serde_json::Value;

use super::load;
use crate::core::vault::Vault;

/// The item `/health` opens to prove the key material is still usable.
///
/// Deterministic (lowest id among live items) so repeated probes exercise the
/// same ciphertext and a passing probe means the same thing every time. Only
/// the id is returned; the caller decrypts and drops the value.
fn canary_item_ids(vault: &Vault) -> Vec<String> {
    let mut ids: Vec<String> = vault
        .list(false)
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    ids.sort();
    let mut canaries = Vec::new();
    if let Some(first) = ids.first() {
        canaries.push(first.clone());
    }
    if let Some(last) = ids.last() {
        if !canaries.contains(last) {
            canaries.push(last.clone());
        }
    }
    for configured in std::env::var("SKARBIEC_READINESS_ITEMS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if ids.iter().any(|item| item == configured)
            && !canaries.iter().any(|item| item == configured)
        {
            canaries.push(configured.to_string());
        }
    }
    canaries
}

pub(super) fn readiness_check() -> Result<Vec<String>> {
    crate::runtime::audit::probe().context("audit journal is not writable")?;
    let vault = load().context("vault is unreadable")?;
    let canaries = canary_item_ids(&vault);
    for id in &canaries {
        vault
            .get_item(id)
            .with_context(|| format!("stored item {id} cannot be decrypted"))?;
    }
    Ok(canaries)
}

pub(super) fn start_readiness_monitor() -> Result<()> {
    let seconds = std::env::var("SKARBIEC_READINESS_INTERVAL_SECONDS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(60);
    std::thread::Builder::new()
        .name("skarbiec-readiness".to_string())
        .spawn(move || loop {
            if let Err(error) = readiness_check() {
                eprintln!("skarbiec readiness monitor: {error:#}");
            }
            std::thread::sleep(std::time::Duration::from_secs(seconds));
        })
        .context("spawn Skarbiec readiness monitor")?;
    Ok(())
}
