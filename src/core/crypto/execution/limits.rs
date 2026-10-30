// Which crypto programs are running, which binaries they are, how many gpg
// runs may run at once, and the drain a GnuPG daemon recovery waits for. A
// permit is held for the length of one run.
//
// One gpg-agent and one keyboxd serve every decrypt of a keyring, one
// request at a time each, so gpg runs beyond what the host can work on at
// once do not finish sooner: they queue inside the daemons instead, out of
// sight. Uncapped, a burst of readers each spawned its own `gpg --decrypt`,
// the callers gave up and asked again while their abandoned children kept
// waiting, and a vault held hundreds of children and connections and
// answered nothing. The gpg runs therefore wait their turn here, in arrival
// order, where the queue can be counted and measured, and a run whose
// caller has gone or whose deadline passed leaves the queue instead of
// running for nobody.

use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use super::caller::Withdrawal;

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

/// The runs holding a permit, the runs waiting for one in arrival order, and
/// whether a recovery holds the whole set. Each permit holds a weak reference
/// to `permits`, so the number of runs is the number of live permits and
/// cannot drift from them.
#[derive(Default)]
struct Runs {
    permits: Arc<()>,
    exclusive: bool,
    /// Every waiting run's ticket and when it began to wait; the lowest
    /// ticket is the next to run.
    queued: BTreeMap<u64, Instant>,
    next_ticket: u64,
}

impl Runs {
    fn active(&self) -> usize {
        Arc::weak_count(&self.permits)
    }
}

/// How many runs may hold a permit at once: a number of runs, or no cap.
/// Where the number comes from, and what was not read when it could not be.
pub(super) struct Capacity {
    pub(super) runs: Option<NonZeroUsize>,
    pub(super) unread: Option<String>,
}

pub(super) struct ExecutionLimit {
    runs: Mutex<Runs>,
    available: Condvar,
    capacity: Capacity,
}

/// What one look at a limit found: its runs, its queue, and how long the run
/// at the head of the queue has waited.
pub(super) struct Occupancy {
    pub(super) active: usize,
    pub(super) queued: usize,
    pub(super) oldest_wait: Option<Duration>,
}

/// Why a queued run left the queue without a permit, with what the queue
/// held when it left.
pub(super) struct Left {
    pub(super) why: Withdrawal,
    pub(super) waited: Duration,
    pub(super) ahead: usize,
    pub(super) active: usize,
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
    fn new(capacity: Capacity) -> Self {
        Self {
            runs: Mutex::default(),
            available: Condvar::new(),
            capacity,
        }
    }

    /// A permit for one run. It waits while a recovery holds the set, while
    /// a run that arrived first is still waiting, and while the capacity is
    /// taken; it leaves the queue, answering why, once `withdrawn` says the
    /// run's caller is gone or its deadline passed. Whoever withdraws a run
    /// calls [`Self::wake`], so the waiter reads it at once.
    pub(super) fn acquire(
        &self,
        withdrawn: &dyn Fn() -> Option<Withdrawal>,
    ) -> Result<ExecutionPermit<'_>, Left> {
        let mut runs = taken(self.runs.lock());
        let ticket = runs.next_ticket;
        runs.next_ticket = runs.next_ticket.wrapping_add(1);
        let arrived = Instant::now();
        runs.queued.insert(ticket, arrived);
        loop {
            // A withdrawn run never starts, even when a permit has just come
            // free: its caller is gone or out of time.
            if let Some(why) = withdrawn() {
                let left = Left {
                    why,
                    waited: arrived.elapsed(),
                    ahead: runs.queued.range(..ticket).count(),
                    active: runs.active(),
                };
                runs.queued.remove(&ticket);
                self.available.notify_all();
                return Err(left);
            }
            let first = runs.queued.keys().next() == Some(&ticket);
            let room = self
                .capacity
                .runs
                .is_none_or(|capacity| runs.active() < capacity.get());
            if first && room && !runs.exclusive {
                runs.queued.remove(&ticket);
                let permit = ExecutionPermit {
                    limit: self,
                    run: Some(Arc::downgrade(&runs.permits)),
                };
                // The next in line may fit beside this run.
                self.available.notify_all();
                return Ok(permit);
            }
            runs = taken(self.available.wait(runs));
        }
    }

    /// Make every waiter look at its queue position and its caller again.
    pub(super) fn wake(&self) {
        let _runs = taken(self.runs.lock());
        self.available.notify_all();
    }

    pub(super) fn capacity(&self) -> &Capacity {
        &self.capacity
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
        while runs.exclusive {
            runs = taken(self.available.wait(runs));
        }
        // Taken before the drain, so no queued run starts while the
        // recovery waits for the running ones; each queued run still leaves
        // when its caller does.
        runs.exclusive = true;
        while runs.active() > stalled() {
            runs = taken(self.available.wait(runs));
        }
        ExclusivePermit { limit: self }
    }

    pub(super) fn in_use(&self) -> usize {
        taken(self.runs.lock()).active()
    }

    pub(super) fn occupancy(&self) -> Occupancy {
        let runs = taken(self.runs.lock());
        Occupancy {
            active: runs.active(),
            queued: runs.queued.len(),
            oldest_wait: runs.queued.values().next().map(Instant::elapsed),
        }
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

pub(super) static CRYPTO_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(|| {
    ExecutionLimit::new(Capacity {
        runs: None,
        unread: None,
    })
});
/// The gpg runs: as many at once as this host can work on at once, as the
/// system reports it. When the system cannot say, nothing caps them and the
/// health document says why.
pub(super) static GPG_LIMIT: LazyLock<ExecutionLimit> =
    LazyLock::new(|| match std::thread::available_parallelism() {
        Ok(runs) => ExecutionLimit::new(Capacity {
            runs: Some(runs),
            unread: None,
        }),
        Err(error) => ExecutionLimit::new(Capacity {
            runs: None,
            unread: Some(format!(
                "this host's available parallelism cannot be read ({error}), so gpg runs are not \
                 capped"
            )),
        }),
    });
/// How many GnuPG daemon recoveries this process has run; none before the
/// first. A run reads it before it starts, without waiting on anything.
pub(super) static GPG_RECOVERY_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Held by the one recovery that runs at a time. Only a run that met a
/// recoverable failure takes it, never a run that is about to start.
pub(super) static GPG_RECOVERY: Mutex<()> = Mutex::new(());

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
