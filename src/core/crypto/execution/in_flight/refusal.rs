//! Whether a new `gpg` run would queue behind wedged daemons right now.

use super::published::PublishedRun;
use super::stood::{self, Stood};
use super::{everyone, sentences, stands_at_agent};

/// Why each run among `all` that has written no status cannot open the
/// keyring, by pid: a keyring lock names a run that stands waiting on the
/// agent as its holder, or the keyboxd database lock is kept by a process
/// that no longer serves the keyboxd socket
/// (`lock_holder::orphaned_database_holder`). Such a run waits as surely as
/// the holder does. Empty when neither holds; a lock that cannot be read is
/// the error, since whether the runs wait cannot then be told.
fn held_back(
    all: &[(String, PublishedRun)],
    stood: &[Stood],
) -> Result<Vec<(u32, String)>, String> {
    let quiet: Vec<u32> = all
        .iter()
        .filter(|(_, run)| run.last_status.is_none())
        .map(|(_, run)| run.pid)
        .collect();
    if quiet.is_empty() {
        return Ok(Vec::new());
    }
    let holders: Vec<u32> = super::super::lock_holder::recorded_holder_pids()?
        .into_iter()
        .filter(|holder| {
            all.iter()
                .any(|(_, run)| run.pid == *holder && stands_at_agent(run, stood))
        })
        .collect();
    let why = if holders.is_empty() {
        match super::super::lock_holder::orphaned_database_holder()? {
            Some(orphaned) => orphaned,
            None => return Ok(Vec::new()),
        }
    } else {
        "the keyring lock it needs is held by a run that waits on gpg-agent".to_owned()
    };
    Ok(quiet
        .into_iter()
        .filter(|pid| !holders.contains(pid))
        .map(|pid| (pid, why.clone()))
        .collect())
}

/// Why a `gpg` run would queue behind wedged daemons right now, when it
/// would: every child in flight, in this process and in every other Skarbiec
/// process of this account, stands where gpg waits on the daemons (at
/// `ENC_TO`, or before any status, and still there the same way when the
/// last maintenance pass looked), or has written no status while it is held
/// back from the keyring ([`held_back`]). A child that is progressing (any
/// other last status, or a waiting point no pass has seen it stand at while
/// nothing holds it back) means the daemons may answer, and a new run joins
/// the queue as usual. A keyring lock or a pass record that cannot be read
/// while children are in flight is refused with its cause: a run now could
/// not be told from one that waits.
pub fn agent_refusal() -> Option<String> {
    let (all, _) = everyone();
    if all.is_empty() {
        return None;
    }
    let untold = |why: String| {
        Some(format!(
            "{} gpg run(s) of this account are in flight and whether they wait on the GnuPG \
             daemons cannot be told: {why}",
            all.len()
        ))
    };
    let stood = match stood::last_pass() {
        Ok(stood) => stood,
        Err(why) => return untold(why),
    };
    let blocked = match held_back(&all, &stood) {
        Ok(blocked) => blocked,
        Err(why) => return untold(why),
    };
    let reason = |run: &PublishedRun| {
        blocked
            .iter()
            .find(|(pid, _)| *pid == run.pid)
            .map(|(_, why)| why)
    };
    if !all
        .iter()
        .all(|(_, run)| stands_at_agent(run, &stood) || reason(run).is_some())
    {
        return None;
    }
    let mut waits = sentences(&all, &stood);
    waits.extend(
        all.iter()
            .filter(|(_, run)| !stands_at_agent(run, &stood))
            .filter_map(|(owner, run)| {
                reason(run).map(|why| {
                    format!(
                        "gpg {} (pid {}, of {owner}) since {} has written no status: {why}",
                        run.verb, run.pid, run.started
                    )
                })
            }),
    );
    Some(format!(
        "{} gpg run(s) of this account are in flight and every one waits on the GnuPG daemons, \
         on gpg-agent directly or behind a keyring lock it cannot take, so a run now would wait \
         behind the same daemons: {}. Recover them with `skarbiec maintain`",
        waits.len(),
        waits.join("; ")
    ))
}
