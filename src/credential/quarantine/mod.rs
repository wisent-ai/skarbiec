// Quarantine: freezing an item when nobody can say which password the
// provider accepts, keeping the staged candidate that may now be live, and
// the operator path back out.

mod freeze;
mod resolve;

pub(super) use freeze::{enforce_provider_effect, enforce_retry_barrier, quarantine_credential};
pub(super) use resolve::resolve_quarantine;
