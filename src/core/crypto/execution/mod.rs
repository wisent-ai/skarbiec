// Running the crypto programs: one retry after a recoverable gpg daemon
// failure, and the capacity and process rules the modules beside this own.

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};

/// A crypto program that ran and exited unsuccessfully. The exit status is
/// kept so a caller that knows the program's status table (pkill: 1 means
/// nothing matched) can read it; the text is the program's own diagnosis.
#[derive(Debug)]
pub(super) struct ToolExit {
    pub(super) status: ExitStatus,
    detail: String,
    /// The error values of gpg's `ERROR`/`FAILURE` status lines.
    pub(super) gpg_errors: Vec<u32>,
    /// The child stopped reading its input before it was all written.
    pub(super) stdin_closed: bool,
}

impl std::fmt::Display for ToolExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for ToolExit {}

mod footprint;
mod limits;
mod recovery;

pub use footprint::{
    daemon_footprints, daemon_memory_limit_bytes, human_size, DaemonFootprint,
    DAEMON_MEMORY_LIMIT_SETTING,
};

use limits::{crypto_program, CRYPTO_LIMIT, GPG_LIMIT, GPG_RECOVERY_GENERATION};
use recovery::{gpg_status, recover_gpg_daemons, recoverable_gpg_failure};

// gpg daemon failure gets one serialized daemon recovery and one retry.
pub(super) fn run(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let recovery_generation = (program == "gpg").then(|| {
        *GPG_RECOVERY_GENERATION
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    });
    let first = run_once(program, args, input);
    let Err(first_error) = first else {
        return first;
    };
    if program != "gpg" || !recoverable_gpg_failure(&first_error) {
        return Err(first_error);
    }

    let mut current_generation = GPG_RECOVERY_GENERATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if recovery_generation == Some(*current_generation) {
        // Drain the gpg capacity first. `recover_gpg_daemons` kills daemons
        // that any concurrent `gpg` child holds an open socket to, so running
        // it beside a live decryption is what produced the reported
        // `gpg: public key decryption failed: Broken pipe`.
        //
        // The generation then advances because recovery was ATTEMPTED, not
        // because it reported success. A wedged keyboxd that makes `gpgconf
        // --launch` time out has this call return the error, and `?`
        // propagating it without retrying means every later read repeats
        // the identical failing sequence and the whole vault answers 503
        // until a person intervenes. A recovery that cannot
        // complete must still let the next request try something else.
        let recovery = {
            let _exclusive = GPG_LIMIT.acquire_exclusive();
            recover_gpg_daemons()
        };
        *current_generation = current_generation.wrapping_add(1);
        drop(current_generation);
        if let Err(error) = recovery {
            return run_once(program, args, input).with_context(|| {
                format!(
                    "gpg retry after incomplete daemon recovery ({error:#}); initial error: \
                     {first_error}"
                )
            });
        }
    } else {
        drop(current_generation);
    }
    run_once(program, args, input).with_context(|| {
        format!("gpg retry failed after daemon recovery; initial error: {first_error}")
    })
}

pub(super) fn run_once(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    // The narrow permit FIRST, then the general one.
    //
    // Taken the other way round, a `gpg` child that is waiting for one of the
    // two GnuPG slots sits on a general crypto slot while doing no work, and
    // eight of those hold the whole pool. Every cheap tool then queues behind
    // decryptions it has nothing to do with: `shasum`, which is how a bearer
    // is verified on EVERY authenticated route, and `openssl`, which is how a
    // token is minted. Several verifier sweeps reading dozens of mapped
    // items through one broker while the queue agent asks it for the
    // metadata of its own grant — a call that decrypts nothing — make that
    // metadata call take over ten seconds, `GET /readyz` on the same broker
    // nearly as long, and Stado's `agent-skarbiec` check report `not
    // measured` about a broker answering every request with 200.
    //
    // One order everywhere, so the two limits cannot deadlock against each
    // other: `acquire_exclusive` on the GnuPG limit is also taken before any
    // general permit, and nothing acquires the general permit before the
    // GnuPG one.
    let _gpg_capacity = (program == "gpg").then(|| GPG_LIMIT.acquire());
    let _capacity = CRYPTO_LIMIT.acquire();
    // gpg reports what failed as machine status lines on stderr; that, not
    // its prose, is what the recovery decision reads.
    let status_args: &[&str] = if program == "gpg" {
        &["--status-fd", "2"]
    } else {
        &[]
    };
    let mut child = Command::new(crypto_program(program).as_ref())
        .args(status_args)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {program}"))?;

    let input = input.map(str::as_bytes).map(Vec::from);
    let stdin = child.stdin.take();
    let input_writer = std::thread::spawn(move || -> std::io::Result<()> {
        if let (Some(mut stdin), Some(input)) = (stdin, input) {
            stdin.write_all(&input)?;
        }
        Ok(())
    });
    let mut stdout = child.stdout.take().context("child stdout unavailable")?;
    let stdout_reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    let mut stderr = child.stderr.take().context("child stderr unavailable")?;
    let stderr_reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes)?;
        Ok(bytes)
    });

    // The tool's own exit is the answer. A gpg agent asking the keychain on a
    // loaded host and a gpg agent that will never answer look the same to a
    // clock, and killing the first one turns a credential that exists into a
    // read this vault reports as failed.
    let status = child.wait()?;
    let written = input_writer
        .join()
        .map_err(|_| anyhow::anyhow!("{program} stdin writer panicked"))?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{program} stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{program} stderr reader panicked"))??;
    // A child that failed explains itself; the broken stdin pipe is only the
    // consequence of it having stopped reading. Reporting the write error
    // first replaced every such diagnosis with a bare `Broken pipe`.
    if !status.success() {
        let (gpg_errors, said) = gpg_status(String::from_utf8_lossy(&stderr).trim());
        let said = said.trim().to_owned();
        let stdin_closed = matches!(
            &written,
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe
        );
        let detail = match (said.is_empty(), written) {
            (false, _) => format!("{program} failed: {said}"),
            (true, Err(error)) => {
                format!("{program} failed ({status}) and stopped reading stdin: {error}")
            }
            (true, Ok(())) => format!("{program} failed ({status}) without output"),
        };
        return Err(ToolExit {
            status,
            detail,
            gpg_errors,
            stdin_closed,
        }
        .into());
    }
    written.with_context(|| format!("write {program} stdin"))?;
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

pub(super) fn run_opt(program: &str, args: &[&str], input: Option<&str>) -> Option<String> {
    run(program, args, input).ok()
}

/// Put the GnuPG daemons back into a usable state on demand.
///
/// The same repair [`run`] performs after a recoverable failure, reachable
/// without one. A long-lived reader — the HTTP server, a browser host, an
/// agent — holds no gpg state of its own, so a keyboxd that wedges under it
/// is repaired for every one of them by the next `gpg` finding fresh daemons.
/// Before this existed the only way to clear that was an inline `gpgconf`
/// nobody could re-run or audit, or restarting the service and its keychain
/// unlock with it.
///
/// The receipt carries what each daemon held before it was replaced, so an
/// operator reading it learns whether the repair met a wedge or a bloat.
pub fn recover_daemons() -> Result<Vec<DaemonFootprint>> {
    let before = daemon_footprints().unwrap_or_default();
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
/// next `gpg` start, and the point is to stop a keyboxd from growing for
/// twelve days, not to churn a healthy one. Above the ceiling the repair is
/// the same serialized one a failed read earns, so no live decryption is
/// beside it, and the retry generation advances so a `gpg` that loses its
/// socket to this pass retries once instead of recovering a second time.
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

/// The daemon repair with the gpg capacity drained first, for the reason
/// [`ExecutionLimit::acquire_exclusive`] gives: killing daemons beside a live
/// decryption is what reports `Broken pipe` to a caller that asked for a
/// credential. The generation advances because a recovery was attempted, the
/// same rule [`run`] applies to its own.
fn recover_exclusively() -> Result<()> {
    let mut generation = GPG_RECOVERY_GENERATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let outcome = {
        let _exclusive = GPG_LIMIT.acquire_exclusive();
        recover_gpg_daemons()
    };
    *generation = generation.wrapping_add(1);
    outcome
}

/// How many cryptographic children run now, all and GnuPG.
pub fn executor_status() -> (usize, usize) {
    (CRYPTO_LIMIT.in_use(), GPG_LIMIT.in_use())
}
