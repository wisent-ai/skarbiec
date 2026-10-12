//! Every `gpg` child this process runs now, with the last machine status
//! line it wrote (`--status-fd`), so a run that has gone quiet can be named
//! by where it stopped instead of being waited for in silence.
//!
//! A decrypt announces the key it needs (`[GNUPG:] ENC_TO …`) and then asks
//! gpg-agent for it; when the agent, or the keyboxd behind it, does not
//! answer, that is the last line the child ever writes, and the request
//! thread holds its connection for as long as the daemons stay wedged.
//! Nothing here is a clock: a run whose last status is `ENC_TO` is measured
//! as waiting on the agent, whatever the time, and that measurement is what
//! the readiness check, a new decrypt and the daemon recovery read.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

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

/// The register's entry for one child, removed when dropped.
pub(super) struct Registered(u32);

impl Drop for Registered {
    fn drop(&mut self) {
        runs().remove(&self.0);
    }
}

/// Register the `gpg` child `pid` that `verb` (its first non-option
/// argument) runs.
pub(super) fn register(pid: u32, verb: &str) -> Registered {
    runs().insert(
        pid,
        Run {
            verb: verb.to_owned(),
            started: crate::core::clock::now_iso(),
            last_status: None,
        },
    );
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
    if let Some(run) = runs().get_mut(&registered.0) {
        run.last_status = Some(keyword.to_owned());
    }
}

/// Whether `run` has asked the agent for a key and heard nothing since.
fn waits_on_agent(run: &Run) -> bool {
    run.last_status.as_deref() == Some(ASKING_THE_AGENT)
}

/// How many `gpg` children run now and have asked the agent for a key
/// without an answer.
pub(super) fn waiting_on_agent() -> usize {
    runs().values().filter(|run| waits_on_agent(run)).count()
}

/// One sentence per `gpg` child waiting on the agent: its pid, what it runs,
/// since when and the status it stopped at. Empty when none waits.
pub fn agent_waits() -> Vec<String> {
    runs()
        .iter()
        .filter(|(_, run)| waits_on_agent(run))
        .map(|(pid, run)| {
            format!(
                "gpg {} (pid {pid}) since {} stopped at status {ASKING_THE_AGENT}: it asked \
                 gpg-agent for its key and the agent has not answered",
                run.verb, run.started
            )
        })
        .collect()
}

/// Why a `gpg` run would queue behind wedged daemons right now, when it
/// would: every child in flight is waiting on the agent. A child that is
/// progressing (any other last status, or none yet) means the daemons answer,
/// and a new run joins the queue as usual.
pub fn agent_refusal() -> Option<String> {
    let held = runs();
    if held.is_empty() || !held.values().all(waits_on_agent) {
        return None;
    }
    drop(held);
    let waits = agent_waits();
    Some(format!(
        "{} gpg run(s) of this vault are in flight and every one has asked gpg-agent for its key \
         without an answer, so a run now would wait behind the same daemons: {}. Recover them \
         with `skarbiec maintain`",
        waits.len(),
        waits.join("; ")
    ))
}
