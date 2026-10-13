//! The `gpg` children a daemon recovery strands. A child a Skarbiec process
//! started against the daemons being replaced keeps waiting on them, holding
//! its caller's request thread and the crypto slot it ran in, so the vault
//! stays unhealthy after the daemons are back. They are found in the process
//! table, not in a register: a serve of an older release publishes none, and
//! a child stuck on the key database rather than on the agent reports a
//! status the register would not name. Every process whose parent runs this
//! very Skarbiec executable (as the parent's kernel-bound identity says), and
//! which itself runs a configured GnuPG executable, is taken before the
//! daemons are stopped and ended after them: its caller is answered with the
//! child's failure and its slot is given back, and the next run meets fresh
//! daemons. This process's own children are left to it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::{gnupg_programs, Identity};

/// The executable a live process runs, canonical, through its kernel-bound
/// identity.
fn executable_of(pid: u32) -> Result<PathBuf, String> {
    let raw = libc::pid_t::try_from(pid).map_err(|error| format!("pid {pid}: {error}"))?;
    let mut identity = Identity::open(raw)?;
    let program = identity.executable()?;
    std::fs::canonicalize(&program).map_err(|error| {
        format!(
            "could not establish executable {}: {error}",
            program.display()
        )
    })
}

/// Every process now whose parent, other than this process, runs this
/// Skarbiec executable: the children a recovery is to end once the daemons
/// they ran against are stopped.
pub(in crate::core::crypto::execution) fn of_skarbiec() -> Result<Vec<u32>, String> {
    let own = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|error| format!("this process's own executable cannot be read: {error}"))?;
    let table = super::super::run_once("ps", &["-axo", "pid=,ppid="], None)
        .map_err(|error| format!("the process table could not be read: {error:#}"))?;
    let mut parents: BTreeMap<u32, bool> = BTreeMap::new();
    let mut children = Vec::new();
    for row in table.lines() {
        let mut words = row.split_whitespace();
        let (Some(Ok(pid)), Some(Ok(parent))) = (
            words.next().map(str::parse::<u32>),
            words.next().map(str::parse::<u32>),
        ) else {
            continue;
        };
        if parent == std::process::id() {
            continue;
        }
        let runs_skarbiec = *parents
            .entry(parent)
            .or_insert_with(|| executable_of(parent).is_ok_and(|program| program == own));
        if runs_skarbiec {
            children.push(pid);
        }
    }
    Ok(children)
}

/// End each child in `pids` that runs a configured GnuPG executable, one
/// sentence per child ended or left alone.
pub(in crate::core::crypto::execution) fn end_stranded(pids: &[u32]) -> Vec<String> {
    if pids.is_empty() {
        return Vec::new();
    }
    let gnupg = match gnupg_programs() {
        Ok(gnupg) => gnupg,
        Err(why) => {
            return vec![format!(
                "left {} child(ren) of Skarbiec alone: {why}",
                pids.len()
            )]
        }
    };
    pids.iter()
        .map(|&pid| {
            let Ok(raw) = libc::pid_t::try_from(pid) else {
                return format!("left child {pid} alone: it is not a process id");
            };
            let mut identity = match Identity::open(raw) {
                Ok(identity) => identity,
                Err(why) => return format!("left child {pid} alone: {why}"),
            };
            let program = match identity.executable().and_then(|program| {
                std::fs::canonicalize(&program).map_err(|error| {
                    format!(
                        "could not establish executable {}: {error}",
                        program.display()
                    )
                })
            }) {
                Ok(program) => program,
                Err(why) => return format!("left child {pid} alone: {why}"),
            };
            if !gnupg.contains(&program) {
                return format!(
                    "left child {pid} alone: it runs {}, not a configured GnuPG executable",
                    program.display()
                );
            }
            match identity.terminate() {
                Ok(()) => format!(
                    "sent TERM to gpg child {pid} ({}), started against the replaced daemons",
                    program.display()
                ),
                Err(error) => format!("could not end gpg child {pid}: {error}"),
            }
        })
        .collect()
}
