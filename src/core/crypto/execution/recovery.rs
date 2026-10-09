// Which gpg failures are worth one retry, and the daemon repair that earns
// it. Killing daemons beside a live decryption is why this is serialized.

use anyhow::{bail, Result};

use super::{run_once, ToolExit};

/// pkill's exit status for "nothing matched" (pgrep(1) EXIT STATUS: 1 no
/// process matched, 2 syntax error, 3 fatal error).
const PKILL_NO_MATCH: i32 = 1;

/// `gpg_err_code_t` sits in the low 16 bits of a status line's error value
/// (`GPG_ERR_CODE_MASK` in gpg-error.h); the high bits name the source.
const GPG_ERR_CODE_MASK: u32 = 0xFFFF;
/// gpg-error.h `GPG_ERR_SYSTEM_ERROR`: the flag a mapped errno code carries.
const GPG_ERR_SYSTEM_ERROR: u32 = 1 << 15;

/// gpg error codes that mean a daemon is missing or was lost under a live
/// operation, where killing and relaunching the GnuPG daemons is worth one
/// retry. Values are gpg-error.h's `gpg_err_code_t`.
///
/// The daemon-lost shapes matter as much as the daemon-missing ones: when
/// `gpg-agent` or `keyboxd` goes away mid-operation the child reports the
/// socket it lost (EPIPE, EOF, a failed IPC connect), not a key problem.
const RECOVERABLE_GPG_ERRORS: [u32; 10] = [
    77,                         // GPG_ERR_NO_AGENT
    259,                        // GPG_ERR_ASS_CONNECT_FAILED
    270,                        // GPG_ERR_ASS_READ_ERROR
    271,                        // GPG_ERR_ASS_WRITE_ERROR
    316,                        // GPG_ERR_NO_KEYBOXD
    317,                        // GPG_ERR_KEYBOXD
    16383,                      // GPG_ERR_EOF
    GPG_ERR_SYSTEM_ERROR | 6,   // GPG_ERR_EAGAIN
    GPG_ERR_SYSTEM_ERROR | 65,  // GPG_ERR_EMFILE
    GPG_ERR_SYSTEM_ERROR | 109, // GPG_ERR_EPIPE
];

/// The wedged-daemon shapes: a daemon that stays but holds the key database.
/// On a vault host a process kept the keybox lock (`gpg: Note:
/// database_open … waiting for lock (held by <pid>)`), every decryption ended
/// `keydb_search failed: Operation timed out`, and the vault answered every
/// read with a service-unavailable error; killing the daemons is the
/// repair there too. Named as gpg-error.h names them and resolved through
/// libgpg-error's own `gpg-error` tool, which prints `<code> = …` for a name.
const WEDGED_GPG_ERROR_NAMES: &[&str] = &["GPG_ERR_TIMEOUT", "GPG_ERR_LOCKED", "GPG_ERR_ETIMEDOUT"];

/// [`WEDGED_GPG_ERROR_NAMES`] as codes, resolved once. A name the tool does
/// not answer is left out and said so on stderr: that shape then stays
/// unrecovered, as it was before it was named.
static WEDGED_GPG_ERRORS: std::sync::LazyLock<Vec<u32>> = std::sync::LazyLock::new(|| {
    WEDGED_GPG_ERROR_NAMES
        .iter()
        .filter_map(|name| {
            let answer = std::process::Command::new("gpg-error").arg(name).output();
            let code = answer.as_ref().ok().and_then(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .split_whitespace()
                    .next()
                    .and_then(|code| code.parse::<u32>().ok())
            });
            if code.is_none() {
                eprintln!(
                    "skarbiec: gpg-error did not resolve {name} ({answer:?}); a gpg failure with \
                     that code is not recovered"
                );
            }
            code
        })
        .collect()
});

/// Whether a failed gpg run is worth one daemon recovery and a retry, read
/// from gpg's own machine status (`--status-fd`), never from its prose. A gpg
/// that died before it could report a status line and stopped reading its
/// input lost its daemon the same way, so that shape counts too.
pub(super) fn recoverable_gpg_failure(error: &anyhow::Error) -> bool {
    let Some(exit) = error.downcast_ref::<ToolExit>() else {
        return false;
    };
    if exit.gpg_errors.is_empty() {
        return exit.stdin_closed;
    }
    exit.gpg_errors.iter().any(|value| {
        let code = value & GPG_ERR_CODE_MASK;
        RECOVERABLE_GPG_ERRORS.contains(&code) || WEDGED_GPG_ERRORS.contains(&code)
    })
}

/// Split gpg's stderr under `--status-fd 2` into the error values of its
/// `[GNUPG:] ERROR <where> <value>` and `[GNUPG:] FAILURE <where> <value>`
/// status lines and the human-readable remainder.
pub(super) fn gpg_status(stderr: &str) -> (Vec<u32>, String) {
    let mut errors = Vec::new();
    let mut said = Vec::new();
    for line in stderr.lines() {
        let Some(status) = line.strip_prefix("[GNUPG:] ") else {
            said.push(line);
            continue;
        };
        let mut fields = status.split_whitespace();
        if matches!(fields.next(), Some("ERROR" | "FAILURE")) {
            if let Some(value) = fields.nth(1).and_then(|value| value.parse::<u32>().ok()) {
                errors.push(value);
            }
        }
    }
    (errors, said.join("\n"))
}

/// Put the gpg daemons back into a state a fresh `gpg` can use.
///
/// `gpgconf --kill` is GnuPG's own control surface, so it is asked first for
/// every daemon and its answer counts. Only the daemons it could not settle
/// are escalated to a signal: a keyboxd stuck mid-request makes `--kill` hit
/// this seam's deadline, which is how one wedged daemon took a vault of 641
/// items offline.
///
/// Escalating for every daemon regardless is what broke the repair on a
/// loaded host. Six `pkill` calls each hit the deadline while `gpgconf` had
/// already killed the daemons, and the repair still reported `no gpg daemon
/// control surface answered`, failing every credential read behind it. The
/// error now means what the sentence says: no surface answered, for any
/// daemon.
///
/// Nothing is launched at the end on purpose. `gpg` starts `gpg-agent` and
/// `keyboxd` on demand, so a kill is a complete repair, while waiting on
/// `--launch` reintroduces exactly the hang this escalation exists to get
/// past.
pub(super) fn recover_gpg_daemons() -> Result<()> {
    let mut answered = false;
    let mut escalation_errors = Vec::new();
    for daemon in ["keyboxd", "gpg-agent", "scdaemon"] {
        match run_once("gpgconf", &["--kill", daemon], None) {
            Ok(_) => {
                answered = true;
                continue;
            }
            Err(error) => escalation_errors.push(format!("{daemon} gpgconf --kill: {error}")),
        }
        for signal in ["-TERM", "-KILL"] {
            // `pkill` exits 1 when nothing matched, which is the common case
            // and not a failure: the daemon this call was meant to remove is
            // already gone. No `-u` filter is needed and none is passed —
            // an unprivileged process cannot signal another account's
            // daemons, so the kernel is the filter.
            match run_once("pkill", &[signal, "-x", daemon], None) {
                Ok(_) => answered = true,
                Err(error) => {
                    // Only pkill's own "nothing matched" status is an answer:
                    // the daemon is already gone. A syntax or fatal status, a
                    // pkill that could not start, or a reader that failed is
                    // an escalation that did not happen. Read from the exit
                    // status, not the words.
                    let no_match = error
                        .downcast_ref::<ToolExit>()
                        .is_some_and(|exit| exit.status.code() == Some(PKILL_NO_MATCH));
                    if no_match {
                        answered = true;
                    } else {
                        escalation_errors.push(format!("{daemon} {signal}: {error:#}"));
                    }
                }
            }
        }
    }
    // A keyring lock whose holder is not one of the daemons above survives
    // their end: a stale lock of a dead or reused pid, or a gpg client that
    // never let go. Each is released and said on stderr, the vault's log.
    for sentence in super::lock_holder::release_wedged_locks() {
        eprintln!("skarbiec: keyring lock: {sentence}");
    }
    let _ = run_once("gpgconf", &["--launch", "keyboxd"], None);
    if answered {
        return Ok(());
    }
    bail!(
        "no gpg daemon control surface answered ({})",
        escalation_errors.join("; ")
    )
}
