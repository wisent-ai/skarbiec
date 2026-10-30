//! Each `gpg` run's tie to the caller it runs for. A request thread names
//! its connection ([`serving`]); every `gpg` run that thread starts, waiting
//! for its turn or running, is watched by one watcher thread, which ends it
//! the moment that connection closes or the run's deadline passes. A caller
//! that gave up and asked again used to leave its first decrypt running for
//! nobody, and those abandoned children are what held a vault's agent and
//! hundreds of its connections. The deadline is the operator's, from
//! [`DEADLINE_SETTING`], and optional: unset, a run is bounded by its caller
//! alone, and a run with no caller (a command run in a shell) by gpg's own
//! exit, as it always was.
//!
//! A connection counts as closed when the kernel says so: reading it would
//! answer end-of-file, or it was reset. A caller that sends more bytes after
//! its request is not judged by those bytes, and only its reset or close
//! ends its run.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Read;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

/// The setting that bounds how long one request's `gpg` run may wait for its
/// turn and run, in whole seconds. Optional: unset, a run is bounded by its
/// caller's connection alone.
pub const DEADLINE_SETTING: &str = "SKARBIEC_GPG_DEADLINE_SECONDS";

/// The bound [`DEADLINE_SETTING`] states; none when it is unset, and the
/// refusal naming it when it holds anything but a whole number of seconds
/// above zero.
pub fn deadline_seconds() -> Result<Option<NonZeroU64>> {
    let Some(text) = crate::core::env::text(DEADLINE_SETTING)? else {
        return Ok(None);
    };
    text.trim()
        .parse::<NonZeroU64>()
        .map(Some)
        .map_err(|error| {
            anyhow!(
            "{DEADLINE_SETTING} is {text:?}, which is not a whole number of seconds above zero \
             ({error}); set it to how long one request's gpg run may wait for its turn and run, \
             or unset it to bound each run by its caller's connection alone"
        )
        })
}

/// Why a run was ended before gpg answered.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Withdrawal {
    /// The caller it ran for closed its connection.
    Abandoned,
    /// Its deadline passed.
    Expired,
}

/// The connection this thread serves, and since when.
struct Caller {
    socket: Arc<OwnedFd>,
    since: Instant,
}

thread_local! {
    static CALLER: RefCell<Option<Caller>> = const { RefCell::new(None) };
}

/// This thread serves the caller on `socket` until the guard drops.
pub struct Serving(());

impl Drop for Serving {
    fn drop(&mut self) {
        CALLER.with(|caller| caller.borrow_mut().take());
    }
}

/// Tie every `gpg` run this thread starts, until the guard drops, to the
/// caller on `socket`. A process out of descriptors cannot hold the copy the
/// watcher reads, and that is the error.
pub fn serving(socket: &impl AsFd) -> std::io::Result<Serving> {
    let socket = Arc::new(socket.as_fd().try_clone_to_owned()?);
    CALLER.with(|caller| {
        *caller.borrow_mut() = Some(Caller {
            socket,
            since: Instant::now(),
        });
    });
    Ok(Serving(()))
}

/// One watched run.
struct Watched {
    socket: Option<Arc<OwnedFd>>,
    /// The caller sent bytes after its request: its socket stays readable
    /// without having closed, so it is no longer polled for reading, and only
    /// a reset or hang-up the kernel reports ends the run.
    talking: bool,
    deadline: Option<Instant>,
    /// The child running for it now, until it has exited and before it is
    /// reaped, so the pid signalled is always this run's child.
    child: Option<libc::pid_t>,
    withdrawn: Option<Withdrawal>,
}

static WATCHED: LazyLock<Mutex<BTreeMap<u64, Watched>>> = LazyLock::new(Mutex::default);
static NEXT: AtomicU64 = AtomicU64::new(0);

fn watched() -> MutexGuard<'static, BTreeMap<u64, Watched>> {
    match WATCHED.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The write end of the pipe that wakes the watcher, once it runs; why it
/// could not be started, when it could not.
static WATCHER: LazyLock<Result<std::io::PipeWriter, String>> = LazyLock::new(|| {
    let (reader, writer) = std::io::pipe()
        .map_err(|error| format!("the pipe that wakes it could not be made: {error}"))?;
    std::thread::Builder::new()
        .name("skarbiec-gpg-watch".to_owned())
        .spawn(move || watch(reader))
        .map_err(|error| format!("its thread could not be started: {error}"))?;
    Ok(writer)
});

fn watcher() -> Result<&'static std::io::PipeWriter> {
    WATCHER.as_ref().map_err(|why| {
        anyhow!(
            "the watcher that ends a gpg run whose caller left or whose deadline passed is not \
             running: {why}; restart the service once the host has descriptors and threads to \
             spare"
        )
    })
}

/// Make the watcher read the watched runs again.
fn nudge() {
    if let Ok(mut writer) = watcher() {
        if let Err(error) = std::io::Write::write_all(&mut writer, &[0]) {
            eprintln!("skarbiec: the gpg run watcher could not be woken: {error}");
        }
    }
}

/// The watch over one `gpg` run, removed when dropped.
pub(super) struct Watch {
    id: Option<u64>,
    pub(super) deadline_seconds: Option<NonZeroU64>,
    pub(super) began: Instant,
}

impl Watch {
    /// Watch the run this thread is about to start: tied to this thread's
    /// caller, and to the deadline counted from when that caller's request
    /// arrived (from now, for a run with no caller).
    pub(super) fn begin() -> Result<Self> {
        let deadline_seconds = deadline_seconds()?;
        let began = Instant::now();
        let caller = CALLER.with(|caller| {
            caller
                .borrow()
                .as_ref()
                .map(|caller| (Arc::clone(&caller.socket), caller.since))
        });
        if caller.is_none() && deadline_seconds.is_none() {
            return Ok(Self {
                id: None,
                deadline_seconds,
                began,
            });
        }
        watcher()?;
        let since = caller.as_ref().map_or(began, |(_, since)| *since);
        let deadline = deadline_seconds.map(|seconds| since + Duration::from_secs(seconds.get()));
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        watched().insert(
            id,
            Watched {
                socket: caller.map(|(socket, _)| socket),
                talking: false,
                deadline,
                child: None,
                withdrawn: None,
            },
        );
        nudge();
        Ok(Self {
            id: Some(id),
            deadline_seconds,
            began,
        })
    }

    /// Why the run was ended, once it was.
    pub(super) fn withdrawn(&self) -> Option<Withdrawal> {
        let id = self.id?;
        watched().get(&id).and_then(|run| run.withdrawn)
    }

    /// The run's child `pid` runs now. A run already withdrawn ends it at
    /// once.
    pub(super) fn running(&self, pid: u32) {
        let Some(id) = self.id else {
            return;
        };
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return;
        };
        let mut held = watched();
        if let Some(run) = held.get_mut(&id) {
            run.child = Some(pid);
            if run.withdrawn.is_some() {
                end(pid);
            }
        }
    }

    /// The run's child has exited and is about to be reaped: it is no
    /// longer signalled, so its pid cannot be another process's.
    pub(super) fn exited(&self) {
        let Some(id) = self.id else {
            return;
        };
        if let Some(run) = watched().get_mut(&id) {
            run.child = None;
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            watched().remove(&id);
            nudge();
        }
    }
}

/// End a run's child. A child already gone has nothing to end.
fn end(pid: libc::pid_t) {
    // SAFETY: kill takes a pid and a signal and touches no memory; the pid
    // is a child of this process that has not been reaped.
    if unsafe { libc::kill(pid, libc::SIGTERM) }.is_negative() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            eprintln!("skarbiec: the gpg child {pid} could not be ended: {error}");
        }
    }
}

/// Whether the peer of `socket` has closed or reset it, as reading it
/// without consuming anything says; `None` when it is open with bytes to
/// read.
fn closed(socket: &OwnedFd) -> Option<bool> {
    let mut byte = [0_u8];
    // SAFETY: one writable byte; MSG_PEEK consumes nothing the request
    // thread would read.
    let read = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            byte.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    match read {
        0 => Some(true),
        read if read.is_positive() => None,
        _ => match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => Some(false),
            _ => Some(true),
        },
    }
}

/// Withdraw one run: record why, and end its child when one runs.
fn withdraw(run: &mut Watched, why: Withdrawal) {
    run.withdrawn = Some(why);
    if let Some(pid) = run.child {
        end(pid);
    }
}

/// The watcher: wait until a watched caller's socket says something, the
/// nearest deadline passes or a run is added or removed, then withdraw every
/// run whose caller left or whose deadline passed, and wake the gpg queue so
/// a waiting run reads it.
fn watch(mut wake: std::io::PipeReader) {
    let wake_fd = wake.as_raw_fd();
    let mut drained = [0_u8; 64];
    loop {
        let (sockets, nearest) = {
            let held = watched();
            let sockets: Vec<(u64, Arc<OwnedFd>)> = held
                .iter()
                .filter(|(_, run)| run.withdrawn.is_none() && !run.talking)
                .filter_map(|(id, run)| run.socket.as_ref().map(|socket| (*id, Arc::clone(socket))))
                .collect();
            let nearest = held
                .values()
                .filter(|run| run.withdrawn.is_none())
                .filter_map(|run| run.deadline)
                .min();
            (sockets, nearest)
        };
        let mut polled: Vec<libc::pollfd> = std::iter::once(wake_fd)
            .chain(sockets.iter().map(|(_, socket)| socket.as_raw_fd()))
            .map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // Milliseconds to the nearest deadline, rounded up so the deadline
        // has passed when the wait ends; none waits until woken.
        let timeout = nearest.map_or(-1, |deadline| {
            let left = deadline.saturating_duration_since(Instant::now());
            let millis = left.as_millis() + u128::from(left.subsec_nanos() % 1_000_000 != 0);
            libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX)
        });
        let Ok(count) = libc::nfds_t::try_from(polled.len()) else {
            eprintln!("skarbiec: the gpg run watcher holds more sockets than poll takes");
            return;
        };
        // SAFETY: `polled` is `count` initialized pollfd entries whose
        // descriptors stay open: each socket is held by `sockets`.
        if unsafe { libc::poll(polled.as_mut_ptr(), count, timeout) }.is_negative() {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                eprintln!("skarbiec: the gpg run watcher stopped: poll failed: {error}");
                return;
            }
            continue;
        }
        if polled[0].revents != 0 {
            if let Err(error) = wake.read(&mut drained) {
                eprintln!("skarbiec: the gpg run watcher stopped: its wake pipe: {error}");
                return;
            }
        }
        let now = Instant::now();
        let mut withdrew = false;
        let mut held = watched();
        for (entry, (id, socket)) in polled[1..].iter().zip(&sockets) {
            if entry.revents == 0 {
                continue;
            }
            let Some(run) = held.get_mut(id) else {
                continue;
            };
            let hung_up = entry.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0;
            match closed(socket) {
                Some(true) => {
                    withdraw(run, Withdrawal::Abandoned);
                    withdrew = true;
                }
                _ if hung_up => {
                    withdraw(run, Withdrawal::Abandoned);
                    withdrew = true;
                }
                None => run.talking = true,
                Some(false) => {}
            }
        }
        for run in held.values_mut() {
            if run.withdrawn.is_none() && run.deadline.is_some_and(|deadline| deadline <= now) {
                withdraw(run, Withdrawal::Expired);
                withdrew = true;
            }
        }
        drop(held);
        if withdrew {
            super::limits::GPG_LIMIT.wake();
        }
    }
}
