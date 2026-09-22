// The GnuPG daemons every read goes through, and what they hold.
//
// This check exists because the number it reports was invisible: `ps` said
// keyboxd held 327 MiB while the kernel had 15 GiB of it compressed and
// swapped, and the host it lived on refused placement for memory pressure
// nobody could attribute. The check reads the same physical footprint the
// ceiling acts on, so an operator sees the daemon the service is about to
// replace, or the one a service that is not running would have replaced.

use serde_json::Value;

use crate::core::crypto::{
    daemon_footprints, daemon_memory_limit_bytes, human_size, DAEMON_MEMORY_LIMIT_SETTING,
};

use super::{check, FAIL, PASS};

/// The daemons of this keyring against their memory ceiling.
///
/// A daemon over the ceiling is a failure with the daemon, its size and the
/// setting that names the ceiling, because the repair is either the running
/// service's next readiness pass or `recover-daemons`, and both are named.
/// No daemon running is a pass: `gpg` starts them on the next read.
pub(super) fn daemons_check() -> Value {
    let limit_bytes = daemon_memory_limit_bytes();
    let limit = human_size(limit_bytes);
    match daemon_footprints() {
        Ok(footprints) if footprints.is_empty() => check(
            "gpg_daemons",
            PASS,
            format!("no GnuPG daemon is running; ceiling {limit} ({DAEMON_MEMORY_LIMIT_SETTING})"),
        ),
        Ok(footprints) => {
            let described: Vec<String> = footprints.iter().map(|f| f.describe()).collect();
            let over: Vec<&String> = footprints
                .iter()
                .zip(&described)
                .filter(|(footprint, _)| footprint.bytes > limit_bytes)
                .map(|(_, description)| description)
                .collect();
            if over.is_empty() {
                check(
                    "gpg_daemons",
                    PASS,
                    format!("{}; ceiling {limit}", described.join(", ")),
                )
            } else {
                check(
                    "gpg_daemons",
                    FAIL,
                    format!(
                        "over the {limit} ceiling ({DAEMON_MEMORY_LIMIT_SETTING}): {}; the running \
                         service replaces them on its next readiness pass, `skarbiec \
                         recover-daemons` replaces them now",
                        over.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                )
            }
        }
        Err(error) => check(
            "gpg_daemons",
            FAIL,
            format!("the GnuPG daemons could not be measured: {error:#}"),
        ),
    }
}
