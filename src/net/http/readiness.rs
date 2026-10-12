// What `/health` proves: the audit journal is writable and one deterministic
// canary item still opens with the key material on this host. The monitor
// that re-proves it also keeps the GnuPG daemons under their memory ceiling,
// because a keyboxd nobody recycles is what took the vault's host down.

use anyhow::{Context, Result};
use serde_json::{json, Value};

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

/// What `/health` proves, or the one thing it will not wait for.
///
/// The canary decrypt runs `gpg`, and a `gpg` whose keyring lock another
/// process holds waits on that lock for as long as the holder keeps it, so a
/// `/health` that decrypted behind a held lock accepted its connection and
/// never answered: every reader through the resolver, and every hook judge
/// that needs a credential, stalled with no cause to act on. The lock files
/// name their holder, so when a `gpg` child of this process is in flight and
/// a keyring lock is held, the check answers with the holders — pid, host,
/// what it runs, since when — instead of becoming one more waiter behind it.
/// A `gpg` child that asked gpg-agent for its key and heard nothing is the
/// same wedge seen from inside this process: when every child in flight is
/// in that state the check answers with those children — pid, arguments,
/// since when, the status they stopped at — and the repair to run, instead
/// of decrypting a canary behind them. Nothing here is a clock: a held lock
/// and a silent agent are measured states of the host.
pub(super) fn readiness_check() -> Result<Vec<String>> {
    crate::runtime::audit::probe().context("audit journal is not writable")?;
    let vault = load().context("vault is unreadable")?;
    let (_, gpg_in_flight) = crate::core::crypto::executor_status();
    if let Some(in_flight) = std::num::NonZeroUsize::new(gpg_in_flight) {
        let holders = crate::core::crypto::keyring_lock_holders();
        if !holders.is_empty() {
            anyhow::bail!(
                "{in_flight} gpg run(s) of this vault are in flight and the keyring lock is \
                 held, so a decrypt would queue behind it: {}",
                holders.join("; ")
            );
        }
    }
    if let Some(refusal) = crate::core::crypto::agent_refusal() {
        anyhow::bail!("{refusal}");
    }
    let canaries = canary_item_ids(&vault);
    for id in &canaries {
        vault
            .get_item(id)
            .with_context(|| format!("stored item {id} cannot be decrypted"))?;
    }
    Ok(canaries)
}

/// One pass of the daemon memory ceiling, spoken to the log and the journal
/// only when it changed something or could not measure: a monitor that
/// prints every healthy minute buries the line that matters. The journal row
/// names the daemons and their sizes, nothing secret, so `audit --op` can
/// answer when and why the daemons were replaced.
fn daemon_ceiling_pass() -> Result<()> {
    match crate::core::crypto::recycle_oversized_daemons()
        .context("skarbiec maintain: GnuPG daemon ceiling")?
    {
        recycle if recycle.recycled => {
            let over_limit = recycle.over_limit.join(", ");
            eprintln!(
                "skarbiec maintain: replaced GnuPG daemons over the {} ceiling: {over_limit}",
                crate::core::crypto::human_size(recycle.limit_bytes)
            );
            crate::runtime::audit::append(
                "daemon-recycle",
                &json!({
                    "limit_bytes": recycle.limit_bytes,
                    "over_limit": recycle.over_limit,
                }),
            )
            .context("skarbiec maintain: journal the daemon recycle")?;
        }
        _ => {}
    }
    Ok(())
}

/// One maintenance pass: the GnuPG daemon ceiling, then the readiness proof.
/// `skarbiec maintain` runs it once; a Stado schedule pinned to the vault host
/// decides how often. A failed proof is the command's error.
pub(crate) fn maintenance_pass() -> Result<Vec<String>> {
    let ceiling = daemon_ceiling_pass();
    let readiness = readiness_check();
    match (ceiling, readiness) {
        (Ok(()), Ok(canaries)) => Ok(canaries),
        (Err(error), Ok(_)) | (Ok(()), Err(error)) => Err(error),
        (Err(ceiling), Err(readiness)) => {
            anyhow::bail!("{ceiling:#}; readiness proof: {readiness:#}")
        }
    }
}
