// The thin client of the canonical Skarbiec: the endpoint comes from one
// owner-controlled Stado forward file, the bearer from an owner-only file, and
// the only hop is a loopback request.

mod endpoint;
mod remote;

pub(crate) use endpoint::canonical_endpoint_report;
pub(super) use endpoint::declare_canonical_endpoint;
pub(super) use remote::{remote_operation, remote_resume, remote_status};

// Canonical Skarbiec discovery: one Stado forward file, never an environment URL.
pub(super) const FORWARDS_DIR_ENV: &str = "STADO_FORWARDS_DIR";
pub(super) const CANONICAL_FORWARD: &str = "skarbiec.local";
pub(super) const ENDPOINT_UNRESOLVED: &str = "SKARBIEC_ENDPOINT_UNRESOLVED";
pub(super) const ENDPOINT_TLS_UNSUPPORTED: &str = "SKARBIEC_ENDPOINT_TLS_UNSUPPORTED";
pub(super) const DIRECTORY_STALE: &str = "SERVICE_DIRECTORY_STALE";
pub(super) const LOOPBACK: &str = "127.0.0.1";
