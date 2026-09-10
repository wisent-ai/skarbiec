// Which gpg failures are worth one retry, and the daemon repair that earns
// it. Killing daemons beside a live decryption is why this is serialized.

use anyhow::{bail, Result};

use super::run_once;

/// Failures where killing and relaunching the GnuPG daemons is worth one retry.
///
/// The daemon-lost shapes matter as much as the daemon-missing ones. When
/// `gpg-agent` or `keyboxd` goes away while a child is mid-operation, the
/// child does not report a key problem: it reports the socket it lost, as
/// `Broken pipe`, `End of file` or `IPC connect call failed`. Those were not
/// listed, so the one failure this recovery exists for -- a daemon that died
/// under a live read -- was reported to the caller as unreachable
/// infrastructure.
pub(super) fn recoverable_gpg_failure(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    [
        "gpg timed out",
        "keyboxd",
        "keybox daemon",
        "no keybox daemon running",
        "resource temporarily unavailable",
        "too many open files",
        "broken pipe",
        "end of file",
        "ipc connect call failed",
    ]
    .iter()
    .any(|needle| detail.contains(needle))
}

/// Put the gpg daemons back into a state a fresh `gpg` can use.
///
/// `gpgconf` is asked first because it is the supported control surface, and
/// it is not trusted to answer: a keyboxd stuck mid-request makes both
/// `--kill` and `--launch` hit this seam's deadline, which is how one wedged
/// daemon took a vault of 641 items offline. So every `gpgconf` call is
/// best-effort and the escalation below signals the daemons directly.
///
/// Nothing is launched at the end on purpose. `gpg` starts `gpg-agent` and
/// `keyboxd` on demand, so a kill is a complete repair, while waiting on
/// `--launch` reintroduces exactly the timeout this escalation exists to get
/// past. The error case is narrow by design: it means neither control surface
/// could even be spawned.
pub(super) fn recover_gpg_daemons() -> Result<()> {
    let _ = run_once("gpgconf", &["--kill", "keyboxd"], None);
    let _ = run_once("gpgconf", &["--kill", "gpg-agent"], None);
    let mut escalation_errors = Vec::new();
    let mut signalled = false;
    for signal in ["-TERM", "-KILL"] {
        for daemon in ["keyboxd", "gpg-agent", "scdaemon"] {
            // `pkill` exits 1 when nothing matched, which is the common case
            // and not a failure: the daemon this call was meant to remove is
            // already gone. No `-u` filter is needed and none is passed —
            // an unprivileged process cannot signal another account's
            // daemons, so the kernel is the filter.
            match run_once("pkill", &[signal, "-x", daemon], None) {
                Ok(_) => signalled = true,
                Err(error) => {
                    let detail = error.to_string();
                    if detail.contains("spawn pkill") || detail.contains("timed out") {
                        escalation_errors.push(format!("{daemon} {signal}: {detail}"));
                    } else {
                        signalled = true;
                    }
                }
            }
        }
    }
    let _ = run_once("gpgconf", &["--launch", "keyboxd"], None);
    if signalled || escalation_errors.is_empty() {
        return Ok(());
    }
    bail!(
        "no gpg daemon control surface answered ({})",
        escalation_errors.join("; ")
    )
}
