// What `/health` proves: the audit journal is writable and one deterministic
// canary item still opens with the key material on this host. The monitor
// that re-proves it also keeps the GnuPG daemons under their memory ceiling,
// because a keyboxd nobody recycles is what took the vault's host down.

use anyhow::{Context, Result};
use serde_json::{json, Value};

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

/// What `/health` proves, or the one thing it will not wait for.
///
/// The canary decrypt runs `gpg`, and a `gpg` whose keyring lock another
/// process holds waits on that lock for as long as the holder keeps it, so a
/// `/health` that decrypted behind a held lock would accept its connection
/// and never answer, leaving every reader with no cause to act on. The lock files
/// name their holder, so when a `gpg` child of this process is in flight and
/// a keyring lock is held, the check answers with the holders — pid, host,
/// what it runs, since when — instead of becoming one more waiter behind it.
/// A `gpg` child that stood where gpg waits on the daemons (asking gpg-agent
/// for its key, or opening the keyring) through a whole maintenance pass
/// interval is the same wedge seen from inside this process: when every
/// child in flight is in that state the check answers with those children —
/// pid, arguments, since when, where they stopped — and the repair to run,
/// instead of decrypting a canary behind them. Nothing here is a clock: a
/// held lock and a run that stood a pass interval are measured states of
/// the host.
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
    let canaries = canary_item_ids(&vault)?;
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

/// One pass of the wedge the readiness proof refuses on: every `gpg` run of
/// this account in flight stands where gpg waits on the daemons (at
/// `ENC_TO`, asking gpg-agent for its key, or before any status, opening the
/// keyring) and stood there the same way when the previous pass looked, or
/// stands behind the keyring lock such a run holds. That is the state
/// `keyring recover` exists for, and the refusal tells the reader to run
/// this pass, so the pass replaces the daemons and ends those runs, and the
/// reads behind them answer, rather than refusing again and leaving every
/// credential read standing until gpg gives up on its lock. Each pass
/// records the runs it sees at those points, so the next one can tell a run
/// that stood a whole pass interval from a healthy decrypt caught on its
/// way. The keyring's locks are read first, so the pass knows which run
/// holds them. The daemons are replaced, and the journal row names why and
/// what each held, so `audit --op` answers when and why it happened.
fn agent_wedge_pass() -> Result<Vec<String>> {
    let holders = crate::core::crypto::keyring_lock_holders();
    let decided = crate::core::crypto::agent_refusal();
    let noted = crate::core::crypto::note_agent_waits().map_err(|why| {
        anyhow::anyhow!("skarbiec maintain: record the gpg runs standing where gpg waits: {why}")
    });
    let Some(refusal) = decided else {
        return noted;
    };
    let refusal = match holders.is_empty() {
        true => refusal,
        false => format!("{refusal}; keyring locks: {}", holders.join("; ")),
    };
    let before = crate::core::crypto::recover_daemons()
        .with_context(|| format!("skarbiec maintain: recover the daemons behind: {refusal}"))?;
    let replaced: Vec<String> = before
        .iter()
        .map(|footprint| footprint.describe())
        .collect();
    eprintln!(
        "skarbiec maintain: replaced the GnuPG daemons ({}) because {refusal}",
        replaced.join(", ")
    );
    crate::runtime::audit::append(
        "daemon-recover",
        &json!({ "reason": refusal, "replaced": replaced }),
    )
    .context("skarbiec maintain: journal the daemon recovery")?;
    noted
}

/// One maintenance pass: the GnuPG daemon ceiling, the daemons every waiting
/// run stands behind, then the readiness proof. `skarbiec maintain` runs it
/// once; a Stado schedule pinned to the vault host decides how often. A
/// failed proof is the command's error, with every failed step's reason.
/// While a run this pass saw at a waiting point for the first time is in
/// flight, the proof's canary decrypt is not run: if that run waits on a
/// wedged agent or keyring the canary would wait behind it and this pass
/// would never end, and only the next pass can tell; the proof is reported
/// deferred, naming the runs.
pub(crate) fn maintenance_pass() -> Result<Vec<String>> {
    let ceiling = daemon_ceiling_pass();
    let wedge = agent_wedge_pass();
    // The canary decrypt runs only when the wedge pass could say that no run
    // in flight waits where it would queue behind it.
    let readiness = match &wedge {
        Err(error) => Err(anyhow::anyhow!(
            "not run: the wedge pass failed ({error:#}), so whether a canary decrypt would wait \
             behind a wedged run cannot be told"
        )),
        Ok(first_sighted) if first_sighted.is_empty() => readiness_check(),
        Ok(first_sighted) => Err(anyhow::anyhow!(
            "deferred to the next pass, which tells whether these runs wait on the GnuPG daemons: {}",
            first_sighted.join("; ")
        )),
    };
    let repairs: Vec<anyhow::Error> =
        [ceiling, wedge.map(|_wedge_report| ())].into_iter().filter_map(Result::err).collect();
    if repairs.is_empty() {
        return readiness;
    }
    let mut reasons: Vec<String> = repairs.iter().map(|error| format!("{error:#}")).collect();
    if let Err(error) = readiness {
        reasons.push(format!("readiness proof: {error:#}"));
    }
    anyhow::bail!("{}", reasons.join("; "))
}
