//! The `gpg` runs of every Skarbiec process of this account, published so
//! one process can see another's.
//!
//! Each process keeps its register in memory, and gpg-agent is one per
//! account: the service's request threads, a `skarbiec list` Brama spawns for
//! every vault read and an operator's shell all wait on the same agent. A
//! process that had never run a child of its own saw nothing waiting, spawned
//! one more gpg into the wedge and stood with it, so its caller waited without
//! end with no sentence to act on. Every process therefore writes its runs to
//! its own file under `~/.local/state/skarbiec/gpg-in-flight/<pid>.json` on
//! every change, removes it when none runs, and reads the others' files before
//! it runs gpg. A file whose process no longer runs is not read: the process
//! table says so, and nothing here is a clock.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One `gpg` child as its process publishes it.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PublishedRun {
    pub(super) pid: u32,
    pub(super) verb: String,
    pub(super) started: String,
    pub(super) last_status: Option<String>,
}

pub(super) fn directory() -> PathBuf {
    crate::core::home_dir().join(".local/state/skarbiec/gpg-in-flight")
}

fn file_of(process: u32) -> PathBuf {
    directory().join(format!("{process}.json"))
}

/// Write this process's runs, or remove its file when none runs. A file that
/// cannot be written is said on stderr: the decrypt it describes goes on.
pub(super) fn publish(runs: &[PublishedRun]) {
    let own = file_of(std::process::id());
    if runs.is_empty() {
        match std::fs::remove_file(&own) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "skarbiec: the finished gpg runs of this process stay published in {}: {error}",
                own.display()
            ),
        }
        return;
    }
    if let Err(error) = write(&own, runs) {
        eprintln!(
            "skarbiec: the gpg runs of this process are not published to {}: {error:#}",
            own.display()
        );
    }
}

fn write(own: &std::path::Path, runs: &[PublishedRun]) -> anyhow::Result<()> {
    let mode = crate::core::vault::private_file_mode()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode | libc::S_IXUSR as u32)
        .create(directory())?;
    let staged = own.with_extension("json.staged");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&staged)?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec(runs)?)?;
    std::fs::rename(&staged, own)?;
    Ok(())
}

/// Every other process's published runs, each with its process, for the
/// processes that still run. A file that cannot be read is named instead of
/// skipped: nobody can then say what that process waits on.
pub(super) fn others() -> Result<Vec<(u32, PublishedRun)>, String> {
    let listed = match std::fs::read_dir(directory()) {
        Ok(listed) => listed,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "the published gpg runs in {} cannot be listed: {error}",
                directory().display()
            ))
        }
    };
    let own = std::process::id();
    let mut found = Vec::new();
    for entry in listed {
        let path = entry
            .map_err(|error| format!("{}: {error}", directory().display()))?
            .path();
        let Some(stem) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        // Only a `<pid>.json` names a process's published runs.
        let Ok(process) = stem.parse::<u32>() else {
            continue;
        };
        if process == own {
            continue;
        }
        // A process that ended without removing its file (killed with its
        // gpg in flight) waits on nothing; its file goes with it.
        if !runs(process)? {
            if let Err(error) = std::fs::remove_file(&path) {
                eprintln!(
                    "skarbiec: the gpg runs of ended process {process} stay published in {}: {error}",
                    path.display()
                );
            }
            continue;
        }
        let body = std::fs::read(&path)
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let published: Vec<PublishedRun> = serde_json::from_slice(&body)
            .map_err(|error| format!("{} is not a list of gpg runs: {error}", path.display()))?;
        found.extend(published.into_iter().map(|run| (process, run)));
    }
    Ok(found)
}

/// Whether `process` runs now, as the process table says: `ps -p` names it,
/// or exits non-zero because no such process runs. A `ps` that cannot be run
/// is the error itself, so no live process's published runs are removed as
/// if it had ended.
fn runs(process: u32) -> Result<bool, String> {
    match super::super::run_once("ps", &["-o", "pid=", "-p", &process.to_string()], None) {
        Ok(_) => Ok(true),
        Err(error) if error.downcast_ref::<super::super::ToolExit>().is_some() => Ok(false),
        Err(error) => Err(format!(
            "whether skarbiec process {process} still runs cannot be read: {error:#}"
        )),
    }
}
