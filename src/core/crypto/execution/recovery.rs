// Which gpg failures are worth one retry, and the daemon repair that earns
// it. Killing daemons beside a live decryption is why this is serialized.

use anyhow::{bail, Result};

use super::{run_once, ToolExit};

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

/// Stop this keyring's daemons through GnuPG's own control surface.
///
/// Every failed control operation remains an error. A successful control of
/// another daemon does not prove that the failed daemon was recovered.
/// Never signal account-wide executable-name matches: another keyring may
/// have a daemon with the same executable.
///
/// GnuPG starts its daemons on demand on the next read; recovery does not
/// launch them. Lock-holder recovery retains its kernel-bound identity checks.
pub(super) fn recover_gpg_daemons() -> Result<()> {
    let mut errors = Vec::new();
    for daemon in ["keyboxd", "gpg-agent", "scdaemon"] {
        if let Err(error) = run_once("gpgconf", &["--kill", daemon], None) {
            errors.push(format!("{daemon} gpgconf --kill: {error:#}"));
        }
    }
    for sentence in super::lock_holder::release_wedged_locks() {
        eprintln!("skarbiec: keyring lock: {sentence}");
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("GnuPG daemon recovery incomplete: {}", errors.join("; "))
    }
}
