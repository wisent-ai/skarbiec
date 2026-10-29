// Running the crypto programs: one retry after a recoverable gpg daemon
// failure, and the capacity and process rules the modules beside this own.

use anyhow::{Context, Result};
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};

/// A crypto program's failure, retaining its status in the diagnostic and
/// GnuPG's structured failure fields for the recovery decision.
#[derive(Debug)]
pub(super) struct ToolExit {
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
pub mod in_flight;
mod limits;
mod lock_holder;
mod maintenance;
mod recovery;

pub use footprint::{
    daemon_footprints, daemon_memory_limit_bytes, human_size, DAEMON_MEMORY_LIMIT_SETTING,
};
pub use maintenance::{recover_daemons, recycle_oversized_daemons};

pub(in crate::core::crypto) use limits::crypto_program;
use limits::{CRYPTO_LIMIT, GPG_LIMIT, GPG_RECOVERY_GENERATION};
use maintenance::next_generation;
use recovery::{gpg_status, recover_gpg_daemons, recoverable_gpg_failure};

/// The recovery generation, taken over from a holder that panicked: it is
/// one number replaced whole, so nothing half-written can be behind it.
fn generation_guard() -> std::sync::MutexGuard<'static, u64> {
    match GPG_RECOVERY_GENERATION.lock() {
        Ok(generation) => generation,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Run one crypto program. A gpg run that still fails after its recovery
/// names every keyring lock held now — the holder's pid, host, what it runs
/// and since when (`lock_holder`) — so a vault answering 503 because one
/// process kept the key database says which process.
pub(super) fn run(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    match run_recovering(program, args, input) {
        Err(error) if program == "gpg" => {
            let holders = lock_holder::keyring_lock_holders();
            if holders.is_empty() {
                return Err(error);
            }
            Err(anyhow::anyhow!("{error:#}; {}", holders.join("; ")))
        }
        answered => answered,
    }
}

// gpg daemon failure gets one serialized daemon recovery and one retry.
fn run_recovering(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let recovery_generation = (program == "gpg").then(|| *generation_guard());
    let first = run_once(program, args, input);
    let Err(first_error) = first else {
        return first;
    };
    if program != "gpg" || !recoverable_gpg_failure(&first_error) {
        return Err(first_error);
    }

    let mut current_generation = generation_guard();
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
            let _exclusive = GPG_LIMIT.acquire_exclusive(in_flight::waiting_on_agent);
            recover_gpg_daemons()
        };
        *current_generation = next_generation(*current_generation);
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
    // A gpg run that would queue behind daemons every run in flight is
    // already waiting on is refused here with those runs named, instead of
    // becoming one more child that never answers (`in_flight`).
    if program == "gpg" {
        if let Some(refusal) = in_flight::agent_refusal() {
            anyhow::bail!(refusal);
        }
    }
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
    let stderr_fd = libc::STDERR_FILENO.to_string();
    let status_args: Vec<&str> = if program == "gpg" {
        vec!["--status-fd", &stderr_fd]
    } else {
        Vec::new()
    };
    let mut child = Command::new(crypto_program(program)?)
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
    let stderr = child.stderr.take().context("child stderr unavailable")?;
    // gpg's status lines are read as they come, so the register knows where
    // a child stopped while it is still running; the bytes are kept whole for
    // the failure report.
    // The arguments name the run; a passphrase travels on stdin, never here.
    let registered = (program == "gpg").then(|| in_flight::register(child.id(), &args.join(" ")));
    let stderr_reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut stderr = std::io::BufReader::new(stderr);
        let mut bytes = Vec::new();
        let mut line = Vec::new();
        loop {
            stderr.read_until(b'\n', &mut line)?;
            if line.is_empty() {
                return Ok(bytes);
            }
            if let Some(registered) = &registered {
                in_flight::noted(registered, String::from_utf8_lossy(&line).trim_end());
            }
            bytes.append(&mut line);
        }
    });

    // The tool's own exit is the answer. A gpg agent asking the keychain on a
    // loaded host and a gpg agent that will never answer look the same to a
    // clock, and killing the first one turns a credential that exists into a
    // read this vault reports as failed. The wait is said on stderr, so a run
    // that never ends is attributable while it stands.
    let status = stado_wait::blocking(
        stado_wait::Kind::Process,
        format!("{program} {}", args.join(" ")),
        "this host",
        || child.wait(),
    )?;
    let written = input_writer.join().map_err(|panic| {
        anyhow::anyhow!(
            "{program} stdin writer panicked: {}",
            crate::core::panic_reason(&*panic)
        )
    })?;
    let stdout = stdout_reader.join().map_err(|panic| {
        anyhow::anyhow!(
            "{program} stdout reader panicked: {}",
            crate::core::panic_reason(&*panic)
        )
    })??;
    let stderr = stderr_reader.join().map_err(|panic| {
        anyhow::anyhow!(
            "{program} stderr reader panicked: {}",
            crate::core::panic_reason(&*panic)
        )
    })??;
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
            (false, _) => format!("{program} failed ({status}): {said}"),
            (true, Err(error)) => {
                format!("{program} failed ({status}) and stopped reading stdin: {error}")
            }
            (true, Ok(())) => format!("{program} failed ({status}) without output"),
        };
        return Err(ToolExit {
            detail,
            gpg_errors,
            stdin_closed,
        }
        .into());
    }
    written.with_context(|| format!("write {program} stdin"))?;
    // The tool's output is a value (a decrypted vault, a signature): bytes
    // that are not UTF-8 are refused, never replaced, so nothing is read back
    // other than as the tool wrote it.
    String::from_utf8(stdout).with_context(|| format!("{program} wrote output that is not UTF-8"))
}

/// How many cryptographic children run now, all and GnuPG.
pub fn executor_status() -> (usize, usize) {
    (CRYPTO_LIMIT.in_use(), GPG_LIMIT.in_use())
}

/// Every keyring lock held now, one sentence each naming the holder's pid,
/// host, what it runs and since when; empty when no lock is held. What a
/// gpg run of this process would queue behind before it could answer.
pub fn keyring_lock_holders() -> Vec<String> {
    lock_holder::keyring_lock_holders()
}
