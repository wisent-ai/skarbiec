// Which gpg failures are worth one retry, and the daemon repair that earns
// it. Killing daemons beside a live decryption is why this is serialized.

use anyhow::{bail, Result};

use super::{run_once, ToolExit};

/// `gpg_err_code_t` sits in the low 16 bits of a status line's error value;
/// the high bits name the source (`GPG_ERR_CODE_MASK`,
/// https://github.com/gpg/libgpg-error/blob/master/src/gpg-error.h.in).
const GPG_ERR_CODE_MASK: u32 = 0xFFFF;

/// `GPG_ERR_NO_AGENT` (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_NO_AGENT: u32 = 77;
/// `GPG_ERR_ASS_CONNECT_FAILED` (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_ASS_CONNECT_FAILED: u32 = 259;
/// `GPG_ERR_ASS_READ_ERROR` (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_ASS_READ_ERROR: u32 = 270;
/// `GPG_ERR_ASS_WRITE_ERROR` (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_ASS_WRITE_ERROR: u32 = 271;
/// `GPG_ERR_NO_KEYBOXD` (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_NO_KEYBOXD: u32 = 316;
/// `GPG_ERR_KEYBOXD` (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_KEYBOXD: u32 = 317;
/// `GPG_ERR_EOF` (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_EOF: u32 = 16383;
/// `GPG_ERR_EAGAIN`: the system-error flag over errno code 6
/// (https://github.com/gpg/libgpg-error/blob/master/src/errnos.in).
const GPG_ERR_EAGAIN: u32 = 32774;
/// `GPG_ERR_EMFILE`: the system-error flag over errno code 65
/// (https://github.com/gpg/libgpg-error/blob/master/src/errnos.in).
const GPG_ERR_EMFILE: u32 = 32833;
/// `GPG_ERR_EPIPE`: the system-error flag over errno code 109
/// (https://github.com/gpg/libgpg-error/blob/master/src/errnos.in).
const GPG_ERR_EPIPE: u32 = 32877;
/// gpg error code 62, the code for a wait that expired
/// (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_WAIT_EXPIRED: u32 = 62;
/// `GPG_ERR_LOCKED` (https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in).
const GPG_ERR_LOCKED: u32 = 173;
/// The system-error flag over errno code 132, a system wait that expired
/// (https://github.com/gpg/libgpg-error/blob/master/src/errnos.in).
const GPG_ERR_SYSTEM_WAIT_EXPIRED: u32 = 32900;

/// gpg error codes worth one daemon recovery and a retry. Values are
/// gpg-error.h's `gpg_err_code_t`, as `gpg-error <code>` prints them.
///
/// A daemon missing or lost under a live operation: when `gpg-agent` or
/// `keyboxd` goes away mid-operation the child reports the socket it lost
/// (EPIPE, EOF, a failed IPC connect), not a key problem.
///
/// A wedged daemon, one that stays but holds the key database: on a vault
/// host a process kept the keybox lock (`gpg: Note: database_open … waiting
/// for lock (held by <pid>)`), every decryption ended with keydb_search's
/// expired wait, and the vault answered every read with a
/// service-unavailable error; killing the daemons is the repair there too.
const RECOVERABLE_GPG_ERRORS: &[u32] = &[
    GPG_ERR_NO_AGENT,
    GPG_ERR_ASS_CONNECT_FAILED,
    GPG_ERR_ASS_READ_ERROR,
    GPG_ERR_ASS_WRITE_ERROR,
    GPG_ERR_NO_KEYBOXD,
    GPG_ERR_KEYBOXD,
    GPG_ERR_EOF,
    GPG_ERR_EAGAIN,
    GPG_ERR_EMFILE,
    GPG_ERR_EPIPE,
    GPG_ERR_WAIT_EXPIRED,
    GPG_ERR_LOCKED,
    GPG_ERR_SYSTEM_WAIT_EXPIRED,
];

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
    exit.gpg_errors
        .iter()
        .any(|value| RECOVERABLE_GPG_ERRORS.contains(&(value & GPG_ERR_CODE_MASK)))
}

/// Split gpg's stderr under `--status-fd 2` into the error values of its
/// `[GNUPG:] ERROR <where> <value>` and `[GNUPG:] FAILURE <where> <value>`
/// status lines and the human-readable remainder. A status line whose value
/// is missing or not a number stays in the remainder, so it is read rather
/// than lost.
pub(super) fn gpg_status(stderr: &str) -> (Vec<u32>, String) {
    let mut errors = Vec::new();
    let mut said = Vec::new();
    for line in stderr.lines() {
        let Some(status) = line.strip_prefix("[GNUPG:] ") else {
            said.push(line);
            continue;
        };
        let mut fields = status.split_whitespace();
        if !matches!(fields.next(), Some("ERROR" | "FAILURE")) {
            continue;
        }
        let _where = fields.next();
        match fields.next().map(str::parse::<u32>) {
            Some(Ok(value)) => errors.push(value),
            // A value that is not a number, or no value, is kept as said.
            Some(Err(_unparsed)) => said.push(line),
            None => said.push(line),
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
/// The `gpg` children Skarbiec processes started against the stopped daemons
/// are taken from the process table first and ended after them
/// (`lock_holder::children`), so their callers are answered and their slots
/// given back instead of waiting on daemons that no longer exist. A `gpg`
/// whose parent could not be identified fails the recovery with its pid, its
/// parent and the reason: it may be a Skarbiec child still waiting, and
/// reporting the path recovered over it is how a vault answered healthy
/// while its reads stood.
pub(super) fn recover_gpg_daemons() -> Result<()> {
    let mut errors = Vec::new();
    let stranded = match super::lock_holder::children::of_skarbiec() {
        Ok(found) => {
            if !found.unidentified.is_empty() {
                errors.push(format!(
                    "{} gpg process(es) wait under a parent whose identity could not be read, \
                     so whether Skarbiec started them is unknown: {}",
                    found.unidentified.len(),
                    found.unidentified.join("; ")
                ));
            }
            found.children
        }
        Err(why) => {
            errors.push(format!(
                "stranded gpg children could not be looked for: {why}"
            ));
            Vec::new()
        }
    };
    for daemon in ["keyboxd", "gpg-agent", "scdaemon"] {
        if let Err(error) = run_once("gpgconf", &["--kill", daemon], None) {
            errors.push(format!("{daemon} gpgconf --kill: {error:#}"));
        }
    }
    for sentence in super::lock_holder::release_wedged_locks() {
        eprintln!("skarbiec: keyring lock: {sentence}");
    }
    for sentence in super::lock_holder::children::end_stranded(&stranded) {
        eprintln!("skarbiec: stranded gpg child: {sentence}");
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("GnuPG daemon recovery incomplete: {}", errors.join("; "))
    }
}
