//! The `gpg` runs the last maintenance pass saw stopped where gpg waits on
//! something outside itself: at `ENC_TO`, asking gpg-agent for its key, or
//! before any status line, opening the keyring (a lock another process
//! holds, a keyboxd that does not answer).
//!
//! Every healthy decrypt passes both points on its way to an answer, so a
//! run seen at one once may move a moment later: it cannot be told from one
//! that will never move. A run still there, the same child started at the
//! same time with the same last status, when the next `skarbiec maintain`
//! pass looks again has stood through a whole pass interval, the period the
//! Stado schedule that runs the pass declares: that is the measurement a
//! wedge is decided by, not a clock of ours. Each pass records what it saw
//! here, and a new decrypt, the readiness check and the daemon recovery
//! count a run as waiting only when the last pass saw it the same way.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::published::{directory, PublishedRun};

/// One run a pass saw stopped at a waiting point: the child's pid and when
/// it started, so a later child that reuses the pid is not the same run, and
/// the status it stood at (none when it had written none), so a run that
/// moved on between passes is not taken for one that stood.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Stood {
    pub(super) pid: u32,
    pub(super) started: String,
    pub(super) last_status: Option<String>,
}

impl Stood {
    pub(super) fn of(run: &PublishedRun) -> Self {
        Self { pid: run.pid, started: run.started.clone(), last_status: run.last_status.clone() }
    }

    pub(super) fn is(&self, run: &PublishedRun) -> bool {
        self.matches(run.pid, &run.started, &run.last_status)
    }

    /// The one rule for whether a run is the one this pass saw: the same
    /// child, started at the same time, at the same last status.
    pub(super) fn matches(&self, pid: u32, started: &str, last_status: &Option<String>) -> bool {
        self.pid == pid && self.started == started && &self.last_status == last_status
    }
}

fn path() -> PathBuf {
    directory().join("stood.json")
}

/// What the last pass saw; none before any pass has recorded one. A record
/// that cannot be read or parsed is the error naming it.
pub(super) fn last_pass() -> Result<Vec<Stood>, String> {
    let path = path();
    let body = match std::fs::read(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{} cannot be read: {error}", path.display())),
    };
    serde_json::from_slice(&body)
        .map_err(|error| format!("{} is not a list of gpg runs: {error}", path.display()))
}

/// Record the runs this pass sees stopped at a waiting point, replacing what
/// the last pass saw.
pub(super) fn record(seen: &[Stood]) -> Result<(), String> {
    let path = path();
    let written = (|| -> anyhow::Result<()> {
        let mode = crate::core::vault::private_file_mode()?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(mode | u32::from(libc::S_IXUSR))
            .create(directory())?;
        let staged = path.with_extension("json.staged");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&staged)?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec(seen)?)?;
        std::fs::rename(&staged, &path)?;
        Ok(())
    })();
    written.map_err(|error| format!("{} cannot be written: {error:#}", path.display()))
}
