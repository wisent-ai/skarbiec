// Which crypto programs are running, which binaries they are, and the drain
// a GnuPG daemon recovery waits for. A permit is held for the length of one
// run; nothing caps how many run at once.

use anyhow::{bail, Result};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, Weak};

/// The tools Skarbiec's cryptographic path runs, and no other program: the
/// cryptographic tools themselves, and `ps` and `uname`, which the GnuPG
/// recovery reads the process table (published runs, stranded children, a
/// lock holder's command) and the host name a lock file records with.
const CRYPTO_PROGRAMS: &[&str] = &[
    "gpg",
    "gpgconf",
    "gpg-connect-agent",
    "openssl",
    "shasum",
    "ps",
    "uname",
];

/// The runs holding a permit, and whether a recovery holds the whole set.
/// Each permit holds a weak reference to `permits`, so the number of runs is
/// the number of live permits and cannot drift from them.
#[derive(Default)]
struct Runs {
    permits: Arc<()>,
    exclusive: bool,
}

impl Runs {
    fn active(&self) -> usize {
        Arc::weak_count(&self.permits)
    }
}

#[derive(Default)]
pub(super) struct ExecutionLimit {
    runs: Mutex<Runs>,
    available: Condvar,
}

/// A guard taken over from a holder that panicked: the permits and the flag
/// are each replaced whole, so nothing half-written can be behind it.
fn taken<T>(locked: std::sync::LockResult<MutexGuard<'_, T>>) -> MutexGuard<'_, T> {
    match locked {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl ExecutionLimit {
    /// A permit for one run; it waits only while a recovery holds the set.
    pub(super) fn acquire(&self) -> ExecutionPermit<'_> {
        let mut runs = taken(self.runs.lock());
        while runs.exclusive {
            runs = taken(self.available.wait(runs));
        }
        ExecutionPermit {
            limit: self,
            run: Some(Arc::downgrade(&runs.permits)),
        }
    }

    /// Take the whole set, so that nothing holding it can be running while
    /// this permit lives — except the runs that `stalled` counts, which are
    /// waiting on the very daemons the holder is about to replace.
    ///
    /// Recovering the GnuPG daemons is not an operation on this process: it
    /// kills and relaunches host daemons that every concurrent `gpg` child is
    /// already talking to over a socket. Doing that beside a live decryption
    /// takes that child's agent away mid-operation, and the child reports the
    /// lost socket -- `gpg: public key decryption failed: Broken pipe` -- to a
    /// caller that asked for nothing but a credential read. That is how one
    /// slow read turned into an unavailable vault for a release publisher, a
    /// capability broker and an agent reading the same vault at once. The
    /// recovery therefore waits for every progressing run to finish. A run
    /// that has asked the agent for its key and heard nothing is not
    /// progressing: waiting for it would wait on the wedge the recovery
    /// exists to clear, so the recovery goes ahead past those; each ends with
    /// the lost socket's own error and its caller retries once, as a run
    /// that meets a daemon failure always has.
    pub(super) fn acquire_exclusive(&self, stalled: impl Fn() -> usize) -> ExclusivePermit<'_> {
        let mut runs = taken(self.runs.lock());
        while runs.active() > stalled() || runs.exclusive {
            runs = taken(self.available.wait(runs));
        }
        runs.exclusive = true;
        ExclusivePermit { limit: self }
    }

    pub(super) fn in_use(&self) -> usize {
        taken(self.runs.lock()).active()
    }
}

pub(super) struct ExecutionPermit<'a> {
    limit: &'a ExecutionLimit,
    /// This run's place among the live permits; released under the lock.
    run: Option<Weak<()>>,
}

impl Drop for ExecutionPermit<'_> {
    fn drop(&mut self) {
        let _runs = taken(self.limit.runs.lock());
        // The run leaves the count while the lock is held, before any waiter
        // is woken to read it.
        drop(self.run.take());
        // Every waiter, not one: an exclusive waiter only proceeds once the
        // count reaches zero, and waking a single ordinary waiter instead can
        // leave it parked behind a drain it would never be told about.
        self.limit.available.notify_all();
    }
}

pub(super) struct ExclusivePermit<'a> {
    limit: &'a ExecutionLimit,
}

impl Drop for ExclusivePermit<'_> {
    fn drop(&mut self) {
        let mut runs = taken(self.limit.runs.lock());
        runs.exclusive = false;
        self.limit.available.notify_all();
    }
}

pub(super) static CRYPTO_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(ExecutionLimit::default);
pub(super) static GPG_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(ExecutionLimit::default);
/// How many GnuPG daemon recoveries this process has run; none before the
/// first.
pub(super) static GPG_RECOVERY_GENERATION: LazyLock<Mutex<u64>> = LazyLock::new(Mutex::default);

/// The binary `program` runs from: the first directory of the `PATH` this
/// process was started with that holds it. The service unit states that PATH
/// (Stado's launchd units name Homebrew's bin beside the system's), so no
/// install directory is guessed here and the unit's choice of gpg is the one
/// that decrypts. Resolved on every run, so a tool installed after the
/// service started is found without a restart.
pub(in crate::core::crypto) fn crypto_program(program: &str) -> Result<PathBuf> {
    if !CRYPTO_PROGRAMS.contains(&program) {
        bail!(
            "{program} is not one of the tools Skarbiec's cryptographic path runs ({})",
            CRYPTO_PROGRAMS.join(", ")
        );
    }
    let Some(path) = std::env::var_os("PATH") else {
        bail!("{program} cannot be found: PATH is not set, and the service unit states the directories its tools run from");
    };
    match crate::core::presence::on_path(program, &path)? {
        Some(binary) => Ok(binary),
        None => bail!(
            "{program} is in no directory of PATH ({}); install it there or name its directory in the service unit's PATH",
            path.to_string_lossy()
        ),
    }
}
