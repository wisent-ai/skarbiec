// The GnuPG daemon repairs a caller asks for outside a failed read: on
// demand, and when a daemon outgrows its memory ceiling. Both drain the gpg
// capacity first and advance the recovery generation.

use anyhow::Result;

use super::footprint::{daemon_footprints, daemon_memory_limit_bytes, DaemonFootprint};
use super::in_flight;
use super::limits::{GPG_LIMIT, GPG_RECOVERY_GENERATION};
use super::recovery::recover_gpg_daemons;

/// The recovery generation after `generation`, wrapping at the end of `u64`:
/// a reader compares generations only for equality, so a wrap stays a change.
pub(super) fn next_generation(generation: u64) -> u64 {
    generation.wrapping_add(std::num::NonZeroU64::MIN.get())
}

/// Put the GnuPG daemons back into a usable state on demand.
///
/// The same repair [`super::run`] performs after a recoverable failure,
/// reachable without one. A long-lived reader — the HTTP server, a browser
/// host, an agent — holds no gpg state of its own, so a keyboxd that wedges
/// under it is repaired for every one of them by the next `gpg` finding fresh
/// daemons.
///
/// The receipt carries what each daemon held before it was replaced, so an
/// operator reading it learns whether the repair met a wedge or a bloat. A
/// footprint that cannot be measured is said on stderr and the receipt holds
/// none: the measurement is the receipt, and the repair still runs.
pub fn recover_daemons() -> Result<Vec<DaemonFootprint>> {
    let before = match daemon_footprints() {
        Ok(before) => before,
        Err(error) => {
            eprintln!("skarbiec: the GnuPG daemons were not measured before recovery: {error:#}");
            Vec::new()
        }
    };
    recover_exclusively()?;
    Ok(before)
}

/// What one pass of the memory ceiling found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonRecycle {
    pub limit_bytes: u64,
    pub footprints: Vec<DaemonFootprint>,
    /// The daemons that stood above the ceiling, in the words the log carries.
    pub over_limit: Vec<String>,
    pub recycled: bool,
}

/// Replace the GnuPG daemons when one of them holds more than the ceiling.
///
/// This is the pass the readiness monitor runs between its checks. A daemon
/// under the ceiling is left alone: killing daemons costs every reader the
/// next `gpg` start, and the point is to stop a keyboxd from growing, not to
/// churn a healthy one. Above the ceiling the repair is the same serialized
/// one a failed read earns, so no live decryption is beside it, and the retry
/// generation advances so a `gpg` that loses its socket to this pass retries
/// once instead of recovering a second time.
pub fn recycle_oversized_daemons() -> Result<DaemonRecycle> {
    let limit_bytes = daemon_memory_limit_bytes()?;
    let footprints = daemon_footprints()?;
    let over_limit: Vec<String> = footprints
        .iter()
        .filter(|footprint| footprint.bytes > limit_bytes)
        .map(DaemonFootprint::describe)
        .collect();
    let recycled = !over_limit.is_empty();
    if recycled {
        recover_exclusively()?;
    }
    Ok(DaemonRecycle {
        limit_bytes,
        footprints,
        over_limit,
        recycled,
    })
}

/// The daemon repair with the gpg capacity drained first: killing daemons
/// beside a live decryption is what reports `Broken pipe` to a caller that
/// asked for a credential. The generation advances because a recovery was
/// attempted, the same rule [`super::run`] applies to its own. A generation
/// lock a panicking holder poisoned is taken over: the counter is one number
/// replaced whole, so nothing half-written can be behind it.
fn recover_exclusively() -> Result<()> {
    let mut generation = match GPG_RECOVERY_GENERATION.lock() {
        Ok(generation) => generation,
        Err(poisoned) => poisoned.into_inner(),
    };
    let outcome = {
        let _exclusive = GPG_LIMIT.acquire_exclusive(in_flight::waiting_on_agent);
        recover_gpg_daemons()
    };
    *generation = next_generation(*generation);
    outcome
}
