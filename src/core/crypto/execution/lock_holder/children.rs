//! The `gpg` children a daemon recovery strands. A child that asked
//! gpg-agent for its key before the daemons were replaced keeps waiting on
//! the agent it asked, which no longer answers: on a vault host several
//! hundred such children of `skarbiec serve` stood for hours after the
//! daemons were replaced, each holding the request thread and the crypto
//! slot it ran in, and the vault stayed unhealthy. After the daemons are
//! stopped every child the published register shows waiting on the agent is
//! ended, through the same kernel-bound identity the lock release uses and
//! only when it runs a configured GnuPG executable: its caller is answered
//! with the child's failure and its slot is given back, and the next run
//! meets fresh daemons.

use super::{gnupg_programs, Identity};

/// End each child in `pids`, one sentence per child ended or left alone.
pub(in crate::core::crypto::execution) fn end_stranded(pids: &[u32]) -> Vec<String> {
    if pids.is_empty() {
        return Vec::new();
    }
    let gnupg = match gnupg_programs() {
        Ok(gnupg) => gnupg,
        Err(why) => {
            return vec![format!(
                "left {} gpg child(ren) waiting on the replaced agent alone: {why}",
                pids.len()
            )]
        }
    };
    pids.iter()
        .map(|&pid| {
            let Ok(raw) = libc::pid_t::try_from(pid) else {
                return format!("left gpg child {pid} alone: it is not a process id");
            };
            let mut identity = match Identity::open(raw) {
                Ok(identity) => identity,
                Err(why) => return format!("left gpg child {pid} alone: {why}"),
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
                Err(why) => return format!("left gpg child {pid} alone: {why}"),
            };
            if !gnupg.contains(&program) {
                return format!(
                    "left pid {pid} alone: it runs {}, not a configured GnuPG executable",
                    program.display()
                );
            }
            match identity.terminate() {
                Ok(()) => format!(
                    "sent TERM to gpg child {pid} ({}), which waited on the replaced agent",
                    program.display()
                ),
                Err(error) => format!("could not end gpg child {pid}: {error}"),
            }
        })
        .collect()
}
