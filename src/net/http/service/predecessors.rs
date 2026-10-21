//! The Skarbiec units a host ran beside the one Skarbiec process, and how that
//! process takes over their work when launchd starts it as its declared unit.
//!
//! A host kept up to five Skarbiec processes: this service, a second `serve`
//! for the control plane, the keychain launcher's `serve`, a `serve` of the
//! retired Weles-only vault, and the removed `sync-daemon`. Started as
//! `com.wisent.skarbiec`, the one process records the replica
//! daemon's bearer file and consumer on its bond, notes the loopback ports
//! every predecessor was listening on, boots each unit out and removes its
//! launch agent, and then listens on those ports itself: a consumer still
//! dialling an old port reaches the one process, and no install finds a plist
//! to load again. The ports are kept beside the vault, so every later start of
//! the declared unit answers on them too. Only a unit whose launch agent is in
//! this user's `~/Library/LaunchAgents` is retired, and a test or an operator
//! running `serve` by hand retires nothing.

use std::collections::BTreeSet;

/// The one unit the fleet runs Skarbiec under, as the Stado catalog names it.
pub(crate) const DECLARED_UNIT: &str = "com.wisent.skarbiec";

/// Units whose work runs inside the one process: the catalog's retired units
/// of Skarbiec, in the same order. The capability broker was a second
/// Skarbiec serving only its capability socket under another account.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PREDECESSORS: &[&str] = &[
    "com.wisent.compute.service.skarbiec-replica-sync",
    "com.wisent.compute.service.skarbiec-control-plane",
    "com.wisent.always-on.skarbiec",
    "com.wisent.compute.service.com.wisent.skarbiec-weles",
    "com.wisent.skarbiec-capability-broker",
];

/// Whether launchd started this process as the fleet's declared unit; a serve
/// run by hand or by a test is not.
pub(super) fn declared() -> bool {
    std::env::var("XPC_SERVICE_NAME").is_ok_and(|label| label == DECLARED_UNIT)
}

/// Retire every predecessor present on this host when this process is the
/// declared unit, and return the loopback ports it answers on in their place:
/// the ones retired now and the ones earlier starts inherited.
pub(crate) fn take_over() -> BTreeSet<u16> {
    if !declared() {
        return BTreeSet::new();
    }
    // A record that cannot be read is left exactly as it is: this start
    // answers on the ports the journal and launchd name, and says why, but
    // never replaces the record with that partial set.
    let (mut ports, recorded, rewritable) = match super::inherited::remembered() {
        Ok((ports, recorded)) => (ports, recorded, true),
        Err(error) => {
            eprintln!(
                "skarbiec serve: the inherited ports record cannot be read, so it is left as it is and this start answers only on the ports the journal and the retired units name: {error:#}"
            );
            let journal = match crate::runtime::audit::retired_ports() {
                Ok(ports) => ports,
                Err(journal_error) => {
                    eprintln!(
                        "skarbiec serve: the journal cannot name the retired units' ports either, so this start answers only on the ports retired now: {journal_error:#}"
                    );
                    BTreeSet::new()
                }
            };
            (journal, true, false)
        }
    };
    let retired = launchd::take_over();
    let grown = !retired.is_subset(&ports);
    ports.extend(retired);
    if rewritable && (grown || !recorded) {
        if let Err(error) = super::inherited::remember(&ports) {
            eprintln!(
                "skarbiec serve: answering on the retired units' ports {ports:?}, but they are not kept for the next start: {error:#}"
            );
        }
    }
    ports
}

#[cfg(target_os = "macos")]
mod launchd;

#[cfg(not(target_os = "macos"))]
mod launchd {
    pub(super) fn take_over() -> std::collections::BTreeSet<u16> {
        std::collections::BTreeSet::new()
    }
}
