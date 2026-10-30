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

mod caller;
mod footprint;
pub mod in_flight;
mod limits;
mod lock_holder;
mod maintenance;
mod recovery;

pub use caller::{deadline_seconds, serving};
pub use footprint::{
    daemon_footprints, daemon_memory_limit_bytes, human_size, DAEMON_MEMORY_LIMIT_SETTING,
};
pub use maintenance::{recover_daemons, recycle_oversized_daemons};

use caller::{Watch, Withdrawal};
pub(in crate::core::crypto) use limits::crypto_program;
use limits::{Left, CRYPTO_LIMIT, GPG_LIMIT, GPG_RECOVERY, GPG_RECOVERY_GENERATION};
use maintenance::next_generation;
use recovery::{gpg_status, recover_gpg_daemons, recoverable_gpg_failure};
use std::sync::atomic::Ordering;

/// The one recovery that runs at a time, taken over from a holder that
/// panicked: it guards no data, only the order of recoveries.
fn recovery_guard() -> std::sync::MutexGuard<'static, ()> {
    match GPG_RECOVERY.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Run one crypto program. A gpg run that still fails after its recovery
/// names every keyring lock held now — the holder's pid, host, what it runs
/// and since when (`lock_holder`) — so a vault answering 503 because one
/// process kept the key database says which process. The holders are added
/// as context, so gpg's own failure stays readable to callers that decide
/// on its status (a key that is absent is not an error): keyboxd holds its
/// database lock for as long as it runs, so on a keyboxd home a holder is
/// named beside every failure.
pub(super) fn run(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    match run_recovering(program, args, input) {
        Err(error) if program == "gpg" => {
            let holders = lock_holder::keyring_lock_holders();
            if holders.is_empty() {
                return Err(error);
            }
            Err(error.context(format!(
                "gpg failed while these keyring locks were held: {}",
                holders.join("; ")
            )))
        }
        answered => answered,
    }
}

// gpg daemon failure gets one serialized daemon recovery and one retry.
fn run_recovering(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    // Read without waiting: a run about to start never queues behind a
    // recovery's drain here, only in the gpg queue, where its caller can
    // leave and where it is counted.
    let recovery_generation =
        (program == "gpg").then(|| GPG_RECOVERY_GENERATION.load(Ordering::Acquire));
    let first = run_once(program, args, input);
    let Err(first_error) = first else {
        return first;
    };
    if program != "gpg" || !recoverable_gpg_failure(&first_error) {
        return Err(first_error);
    }

    let recovering = recovery_guard();
    if recovery_generation == Some(GPG_RECOVERY_GENERATION.load(Ordering::Acquire)) {
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
        GPG_RECOVERY_GENERATION.store(
            next_generation(GPG_RECOVERY_GENERATION.load(Ordering::Acquire)),
            Ordering::Release,
        );
        drop(recovering);
        if let Err(error) = recovery {
            return run_once(program, args, input).with_context(|| {
                format!(
                    "gpg retry after incomplete daemon recovery ({error:#}); initial error: \
                     {first_error}"
                )
            });
        }
    } else {
        drop(recovering);
    }
    run_once(program, args, input).with_context(|| {
        format!("gpg retry failed after daemon recovery; initial error: {first_error}")
    })
}

/// How many gpg runs this host runs at once, in words.
fn capacity_words() -> String {
    let capacity = GPG_LIMIT.capacity();
    match (capacity.runs, &capacity.unread) {
        (Some(runs), _) => format!("the {runs} gpg runs this host runs at once"),
        (None, Some(why)) => format!("a gpg run ({why})"),
        (None, None) => "a gpg run".to_owned(),
    }
}

/// The deadline in words, for a run the deadline ended.
fn deadline_words(watch: &Watch) -> String {
    match watch.deadline_seconds {
        Some(seconds) => format!("{}={seconds}", caller::DEADLINE_SETTING),
        None => caller::DEADLINE_SETTING.to_owned(),
    }
}

/// The refusal of a run that left the gpg queue before it ran: how long it
/// waited, behind what, why it left, and what would let it run.
fn left_queue(verb: &str, watch: &Watch, left: &Left) -> anyhow::Error {
    let Left {
        why,
        waited,
        ahead,
        active,
    } = left;
    match why {
        Withdrawal::Abandoned => anyhow::anyhow!(
            "gpg {verb} was not run: its caller closed the connection after it waited {waited:.1?} \
             for one of {} behind {ahead} queued and {active} running gpg run(s); nobody was \
             left to answer, so nothing was decrypted. A caller that gives up before its read is \
             answered leaves no run behind; give the read longer, or read fewer items at once",
            capacity_words()
        ),
        Withdrawal::Expired => anyhow::anyhow!(
            "gpg {verb} waited {waited:.1?} for one of {} and its deadline ({}s, {}) passed \
             first, with {ahead} gpg run(s) queued ahead of it and {active} running. The vault \
             was asked for more decrypts than it answers within the deadline, or the running \
             ones wait on the GnuPG daemons (GET /health names them under \
             crypto.gpg_waiting_on_agent and gives the queue). Ask again once the queue is \
             shorter, run `skarbiec maintain` to replace daemons that stopped answering, or \
             raise {}",
            capacity_words(),
            watch.deadline_seconds.map_or(0, std::num::NonZeroU64::get),
            deadline_words(watch),
            caller::DEADLINE_SETTING
        ),
    }
}

/// The refusal of a run whose child was ended before gpg answered, with
/// what gpg had said by then.
fn ended_run(verb: &str, watch: &Watch, why: Withdrawal, said: &str) -> anyhow::Error {
    let ran = watch.began.elapsed();
    let said = if said.is_empty() {
        "gpg had written nothing".to_owned()
    } else {
        format!("gpg had said: {said}")
    };
    match why {
        Withdrawal::Abandoned => anyhow::anyhow!(
            "gpg {verb} was ended after {ran:.1?}: its caller closed the connection, so nobody \
             was left to answer ({said}). Give the read longer, or read fewer items at once"
        ),
        Withdrawal::Expired => anyhow::anyhow!(
            "gpg {verb} was ended after {ran:.1?} because its deadline ({}) passed before gpg \
             answered ({said}). gpg-agent or keyboxd did not answer in time, or another process \
             holds the keyring lock (GET /readyz names the holder): run `skarbiec maintain` to \
             replace daemons that stopped answering, or raise {} if decrypts on this host are \
             this slow",
            deadline_words(watch),
            caller::DEADLINE_SETTING
        ),
    }
}

/// Wait until the child `pid` has exited, without reaping it, so its pid
/// stays this child's until [`Watch::exited`] has been told.
fn exited_unreaped(pid: u32) -> std::io::Result<()> {
    let id = libc::id_t::try_from(pid)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: one writable siginfo_t; WNOWAIT leaves the child to be
        // reaped by `Child::wait`.
        let status = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if !status.is_negative() {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
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
    // Taken the other way round, a `gpg` child that is waiting for its turn
    // in the GnuPG queue would sit on a general crypto slot while doing no
    // work. Every cheap tool would then queue behind decryptions it has
    // nothing to do with.
    //
    // One order everywhere, so the two limits cannot deadlock against each
    // other: `acquire_exclusive` on the GnuPG limit is also taken before any
    // general permit, and nothing acquires the general permit before the
    // GnuPG one.
    //
    // A gpg run is watched from before it queues until its child is reaped
    // (`caller`): the caller leaving or the deadline passing takes it out of
    // the queue, or ends its child, and its caller is answered with why.
    let verb = args.join(" ");
    let watch = if program == "gpg" {
        Some(Watch::begin()?)
    } else {
        None
    };
    let _gpg_capacity = match &watch {
        Some(watch) => Some(
            GPG_LIMIT
                .acquire(&|| watch.withdrawn())
                .map_err(|left| left_queue(&verb, watch, &left))?,
        ),
        None => None,
    };
    let _capacity = CRYPTO_LIMIT.acquire(&|| None).map_err(|left| {
        anyhow::anyhow!("{program} left the crypto queue after {:.1?}", left.waited)
    })?;
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
    if let Some(watch) = &watch {
        watch.running(child.id());
    }

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

    // The tool's own exit is the answer, unless its caller left or its
    // deadline passed first, and then the watcher ends it. The child is
    // reaped only after the watcher is told it exited, so the pid the
    // watcher signals is always this child's. The wait is said on stderr,
    // so a run that never ends is attributable while it stands.
    let status = stado_wait::blocking(
        stado_wait::Kind::Process,
        format!("{program} {verb}"),
        "this host",
        || {
            if let Some(watch) = &watch {
                exited_unreaped(child.id())?;
                watch.exited();
            }
            child.wait()
        },
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
        // A child the watcher ended is answered with why it was ended, never
        // as a daemon failure: the caller is gone or out of time, and a
        // recovery and a retry would only run for nobody.
        if let Some((watch, why)) = watch
            .as_ref()
            .and_then(|watch| watch.withdrawn().map(|why| (watch, why)))
        {
            return Err(ended_run(&verb, watch, why, &said));
        }
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

/// The cryptographic children and the gpg queue as they stand now.
pub struct ExecutorStatus {
    /// Every cryptographic child running now.
    pub active: usize,
    /// The gpg children running now.
    pub gpg_active: usize,
    /// How many gpg runs may run at once; none when nothing caps them.
    pub gpg_capacity: Option<usize>,
    /// Why nothing caps them, when the cap could not be read.
    pub gpg_capacity_unread: Option<String>,
    /// The gpg runs waiting for their turn.
    pub gpg_queued: usize,
    /// How long the run at the head of the queue has waited.
    pub gpg_oldest_wait: Option<std::time::Duration>,
}

/// The cryptographic children and the gpg queue now. It reads two counters
/// and runs nothing, so it answers while every gpg run waits.
pub fn executor_status() -> ExecutorStatus {
    let gpg = GPG_LIMIT.occupancy();
    let capacity = GPG_LIMIT.capacity();
    ExecutorStatus {
        active: CRYPTO_LIMIT.in_use(),
        gpg_active: gpg.active,
        gpg_capacity: capacity.runs.map(std::num::NonZeroUsize::get),
        gpg_capacity_unread: capacity.unread.clone(),
        gpg_queued: gpg.queued,
        gpg_oldest_wait: gpg.oldest_wait,
    }
}

/// Every keyring lock held now, one sentence each naming the holder's pid,
/// host, what it runs and since when; empty when no lock is held. What a
/// gpg run of this process would queue behind before it could answer.
pub fn keyring_lock_holders() -> Vec<String> {
    lock_holder::keyring_lock_holders()
}
