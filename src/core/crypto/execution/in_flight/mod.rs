//! Every `gpg` child this process runs now, with the last machine status
//! line it wrote (`--status-fd`), so a run that has gone quiet can be named
//! by where it stopped instead of being waited for in silence.
//!
//! gpg waits on something outside itself at two points. Before it writes
//! any status it opens the keyring, and waits there while another process
//! holds the keyring lock or keyboxd does not answer (`gpg: Note:
//! database_open … waiting for lock (held by <pid>)`, and tens of minutes
//! later `keydb_search failed: Operation timed out`). A decrypt then
//! announces the key it needs (`[GNUPG:] ENC_TO …`) and asks gpg-agent for
//! it, and waits there while the agent does not answer. A run stopped at
//! either point holds its request's connection for as long as the cause
//! stands. The runs of every other Skarbiec process of this account are
//! read too (`published`): they wait on the same keyring and agent.
//!
//! Every healthy decrypt passes both points on its way to an answer, so one
//! sighting cannot tell a wedge from progress about to arrive. A run counts
//! as waiting only once the last maintenance pass saw it at the same point,
//! the same child with the same last status (`stood`); the pass interval is
//! the measurement, and the readiness check, a new decrypt and the daemon
//! recovery read it. The recovery ends such runs with the daemons, so the
//! read that waited answers or refuses with gpg's own words instead of
//! standing until gpg gives up.

mod published;
mod refusal;
mod stood;

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

use published::PublishedRun;
pub use refusal::agent_refusal;
use stood::Stood;

/// The status keyword gpg writes once it has read the key a message is
/// encrypted to and before it asks the agent to use it.
const ASKING_THE_AGENT: &str = "ENC_TO";
/// The prefix of every machine status line gpg writes on its status fd.
const STATUS_PREFIX: &str = "[GNUPG:] ";

/// One running `gpg` child, keyed by its pid: a pid is one child for as
/// long as the child lives, and the entry leaves with it.
struct Run {
    verb: String,
    started: String,
    last_status: Option<String>,
}

static RUNS: LazyLock<Mutex<BTreeMap<u32, Run>>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The register. A thread that panicked while holding it left a whole entry
/// or none, so the poisoned lock is taken over rather than refusing every
/// later reader of what is in flight.
fn runs() -> MutexGuard<'static, BTreeMap<u32, Run>> {
    match RUNS.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Publish this process's runs as they stand in `held`.
fn publish(held: &BTreeMap<u32, Run>) {
    let listed: Vec<PublishedRun> = held
        .iter()
        .map(|(pid, run)| PublishedRun {
            pid: *pid,
            verb: run.verb.clone(),
            started: run.started.clone(),
            last_status: run.last_status.clone(),
        })
        .collect();
    published::publish(&listed);
}

/// The register's entry for one child, removed when dropped.
pub(super) struct Registered(u32);

impl Drop for Registered {
    fn drop(&mut self) {
        let mut held = runs();
        held.remove(&self.0);
        publish(&held);
    }
}

/// Register the `gpg` child `pid` that `verb` (its first non-option
/// argument) runs.
pub(super) fn register(pid: u32, verb: &str) -> Registered {
    let mut held = runs();
    held.insert(
        pid,
        Run {
            verb: verb.to_owned(),
            started: crate::core::clock::now_iso(),
            last_status: None,
        },
    );
    publish(&held);
    Registered(pid)
}

/// Note one line of the child's stderr; a machine status line updates the
/// run's last status, any other line is prose and changes nothing.
pub(super) fn noted(registered: &Registered, line: &str) {
    let Some(status) = line.strip_prefix(STATUS_PREFIX) else {
        return;
    };
    let keyword = match status.split_whitespace().next() {
        Some(keyword) => keyword,
        None => status,
    };
    let mut held = runs();
    if let Some(run) = held.get_mut(&registered.0) {
        run.last_status = Some(keyword.to_owned());
    }
    publish(&held);
}

/// Whether a run with `last_status` stands at a point where gpg waits on
/// something outside itself: opening the keyring before any status, or at
/// `ENC_TO`, asking gpg-agent for its key.
fn at_waiting_point(last_status: Option<&str>) -> bool {
    match last_status {
        None => true,
        Some(status) => status == ASKING_THE_AGENT,
    }
}

/// How many of this process's `gpg` children stand at a waiting point and
/// stood there, the same way, when the last maintenance pass looked. A pass
/// record that cannot be read counts none as standing, so a recovery waits
/// for them as for any progressing run, and says why on stderr.
pub(super) fn waiting_on_agent() -> usize {
    let stood = match stood::last_pass() {
        Ok(stood) => stood,
        Err(why) => {
            eprintln!("skarbiec: no gpg run is counted as waiting on the GnuPG daemons: {why}");
            Vec::new()
        }
    };
    runs()
        .iter()
        .filter(|(pid, run)| {
            at_waiting_point(run.last_status.as_deref())
                && stood.iter().any(|seen| seen.matches(**pid, &run.started, &run.last_status))
        })
        .count()
}

/// One sentence per `gpg` child that stood at a waiting point through the
/// last pass interval, this process's and every other Skarbiec process's of
/// this account: its pid, whose it is, what it runs, since when and where it
/// stopped. Empty when none stood; a published file or a pass record that
/// cannot be read is said as one more sentence.
pub fn agent_waits() -> Vec<String> {
    let (all, unreadable) = everyone();
    let mut waits = match stood::last_pass() {
        Ok(stood) => sentences(&all, &stood),
        Err(why) => vec![why],
    };
    waits.extend(unreadable);
    waits
}

/// Whether a published run stands at a waiting point and the last pass saw
/// it there the same way.
fn stands_at_agent(run: &PublishedRun, stood: &[Stood]) -> bool {
    at_waiting_point(run.last_status.as_deref()) && stood.iter().any(|seen| seen.is(run))
}

/// Where a run at a waiting point stopped, and what it waits on there.
fn waiting_on(run: &PublishedRun) -> (String, &'static str) {
    match run.last_status.as_deref() {
        Some(status) => (
            format!("stopped at status {status}"),
            "it asked gpg-agent for its key and the agent has not answered",
        ),
        None => (
            "has written no status".to_owned(),
            "it has not opened the keyring, whose lock another process holds or whose keyboxd \
             does not answer",
        ),
    }
}

fn sentences(all: &[(String, PublishedRun)], stood: &[Stood]) -> Vec<String> {
    all.iter()
        .filter(|(_, run)| stands_at_agent(run, stood))
        .map(|(owner, run)| {
            let (at, what) = waiting_on(run);
            format!(
                "gpg {} (pid {}, of {owner}) since {} {at} and was still there when the last \
                 maintenance pass looked: {what}",
                run.verb, run.pid, run.started
            )
        })
        .collect()
}

/// Record, for the next maintenance pass, every run of this account that
/// stands at a waiting point now, and answer the ones the last pass had not
/// seen there the same way, one sentence each: whether those wait on the
/// GnuPG daemons only the next pass can tell. A pass record or a published
/// file that could not be read is the error, the latter after the record is
/// written.
pub fn note_agent_waits() -> Result<Vec<String>, String> {
    let (all, unreadable) = everyone();
    let before = stood::last_pass()?;
    let waiting: Vec<&(String, PublishedRun)> = all
        .iter()
        .filter(|(_, run)| at_waiting_point(run.last_status.as_deref()))
        .collect();
    let seen: Vec<Stood> = waiting.iter().map(|(_, run)| Stood::of(run)).collect();
    stood::record(&seen)?;
    if let Some(why) = unreadable {
        return Err(why);
    }
    Ok(waiting
        .iter()
        .filter(|(_, run)| !before.iter().any(|seen| seen.is(run)))
        .map(|(owner, run)| {
            let (at, _) = waiting_on(run);
            format!("gpg {} (pid {}, of {owner}) since {} {at}", run.verb, run.pid, run.started)
        })
        .collect())
}

/// Every `gpg` run of this account now, each with whose it is (`this
/// process` or `skarbiec process <pid>`), and the published file that could
/// not be read, when one could not.
fn everyone() -> (Vec<(String, PublishedRun)>, Option<String>) {
    let mut all: Vec<(String, PublishedRun)> = runs()
        .iter()
        .map(|(pid, run)| {
            (
                "this process".to_owned(),
                PublishedRun {
                    pid: *pid,
                    verb: run.verb.clone(),
                    started: run.started.clone(),
                    last_status: run.last_status.clone(),
                },
            )
        })
        .collect();
    match published::others() {
        Ok(others) => {
            all.extend(
                others
                    .into_iter()
                    .map(|(process, run)| (format!("skarbiec process {process}"), run)),
            );
            (all, None)
        }
        Err(unreadable) => (all, Some(unreadable)),
    }
}
