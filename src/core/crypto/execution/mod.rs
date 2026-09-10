// Running the crypto programs: one retry after a recoverable gpg daemon
// failure, and the capacity and process rules the modules beside this own.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use wait_timeout::ChildExt;

mod limits;
mod recovery;

use limits::{crypto_program, execution_timeout, CRYPTO_LIMIT, GPG_LIMIT, GPG_RECOVERY_GENERATION};
use recovery::{recover_gpg_daemons, recoverable_gpg_failure};

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
    if program != "gpg" || !recoverable_gpg_failure(&first_error.to_string()) {
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
        // because it reported success. On 2026-09-03 a wedged keyboxd on the
        // always-on Mac made `gpgconf --launch` time out, this call returned
        // the error, and `?` propagated it without retrying — so every later
        // read repeated the identical failing sequence and a 641-item vault
        // answered 503 until a person intervened. A recovery that cannot
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
    // token is minted. On 2026-09-05 the fleet's four verifier sweeps read 48
    // mapped items through one broker while the queue agent asked it for the
    // metadata of its own grant — a call that decrypts nothing — and that
    // metadata call took 14.4s, `GET /readyz` on the same broker 9.7s, and
    // Stado's `agent-skarbiec` check reported `not measured` about a broker
    // answering every request with 200.
    //
    // One order everywhere, so the two limits cannot deadlock against each
    // other: `acquire_exclusive` on the GnuPG limit is also taken before any
    // general permit, and nothing acquires the general permit before the
    // GnuPG one.
    let _gpg_capacity = (program == "gpg").then(|| GPG_LIMIT.acquire());
    let _capacity = CRYPTO_LIMIT.acquire();
    let mut child = Command::new(crypto_program(program).as_ref())
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

    let status = match child.wait_timeout(execution_timeout())? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} timed out");
        }
    };
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
    // first replaced every such diagnosis with a bare `Broken pipe`, which
    // told the operator nothing and hid the very text
    // `recoverable_gpg_failure` classifies on -- so the retry could not fire
    // either.
    if !status.success() {
        let said = String::from_utf8_lossy(&stderr).trim().to_owned();
        if said.is_empty() {
            return match written {
                Err(error) => Err(anyhow::anyhow!(
                    "{program} failed ({status}) and stopped reading stdin: {error}"
                )),
                Ok(()) => Err(anyhow::anyhow!(
                    "{program} failed ({status}) without output"
                )),
            };
        }
        bail!("{program} failed: {said}");
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
/// The gpg capacity is drained first for the reason
/// [`ExecutionLimit::acquire_exclusive`] gives: killing daemons beside a live
/// decryption is what reports `Broken pipe` to a caller that asked for a
/// credential.
pub fn recover_daemons() -> Result<()> {
    let _exclusive = GPG_LIMIT.acquire_exclusive();
    recover_gpg_daemons()
}

pub fn executor_status() -> (usize, usize, usize, usize) {
    (
        CRYPTO_LIMIT.in_use(),
        CRYPTO_LIMIT.maximum,
        GPG_LIMIT.in_use(),
        GPG_LIMIT.maximum,
    )
}
