// Which crypto programs are running, which binaries they are, and the drain
// a GnuPG daemon recovery waits for. A permit is held for the length of one
// run; nothing caps how many run at once.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, LazyLock, Mutex};

/// How many runs hold a permit, and whether a recovery holds the whole set.
#[derive(Default)]
struct Runs {
    active: usize,
    exclusive: bool,
}

#[derive(Default)]
pub(super) struct ExecutionLimit {
    runs: Mutex<Runs>,
    available: Condvar,
}

impl ExecutionLimit {
    /// A permit for one run; it waits only while a recovery holds the set.
    pub(super) fn acquire(&self) -> ExecutionPermit<'_> {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while runs.exclusive {
            runs = self
                .available
                .wait(runs)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        runs.active += 1;
        ExecutionPermit { limit: self }
    }

    /// Take the whole set, so that nothing holding it can be running while
    /// this permit lives.
    ///
    /// Recovering the GnuPG daemons is not an operation on this process: it
    /// kills and relaunches host daemons that every concurrent `gpg` child is
    /// already talking to over a socket. Doing that beside a live decryption
    /// takes that child's agent away mid-operation, and the child reports the
    /// lost socket -- `gpg: public key decryption failed: Broken pipe` -- to a
    /// caller that asked for nothing but a credential read. That is how one
    /// slow read turned into `503 infra_down` for a release publisher, a
    /// capability broker and an agent reading the same vault at once. The
    /// recovery therefore waits for every run to finish instead.
    pub(super) fn acquire_exclusive(&self) -> ExclusivePermit<'_> {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while runs.active > 0 || runs.exclusive {
            runs = self
                .available
                .wait(runs)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        runs.exclusive = true;
        ExclusivePermit { limit: self }
    }

    pub(super) fn in_use(&self) -> usize {
        self.runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }
}

pub(super) struct ExecutionPermit<'a> {
    limit: &'a ExecutionLimit,
}

impl Drop for ExecutionPermit<'_> {
    fn drop(&mut self) {
        let mut runs = self
            .limit
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runs.active = runs.active.saturating_sub(1);
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
        let mut runs = self
            .limit
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runs.exclusive = false;
        self.limit.available.notify_all();
    }
}

pub(super) static CRYPTO_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(ExecutionLimit::default);
pub(super) static GPG_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(ExecutionLimit::default);
pub(super) static GPG_RECOVERY_GENERATION: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));
static CRYPTO_PROGRAMS: LazyLock<HashMap<&'static str, PathBuf>> = LazyLock::new(|| {
    [
        "gpg",
        "gpgconf",
        "gpg-connect-agent",
        "openssl",
        "shasum",
    ]
    .into_iter()
    .map(|program| (program, resolve_program_path(program)))
    .collect()
});

fn resolve_program_path(program: &str) -> PathBuf {
    let from_environment = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default();
    let home_local = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/bin"));
    let fallbacks = [
        Some(PathBuf::from("/opt/homebrew/bin")),
        Some(PathBuf::from("/usr/local/MacGPG2/bin")),
        Some(PathBuf::from("/home/linuxbrew/.linuxbrew/bin")),
        Some(PathBuf::from("/usr/local/bin")),
        home_local,
        Some(PathBuf::from("/usr/bin")),
        Some(PathBuf::from("/bin")),
    ];
    from_environment
        .into_iter()
        .chain(fallbacks.into_iter().flatten())
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| PathBuf::from(program))
}

pub(super) fn crypto_program(program: &str) -> Cow<'_, Path> {
    CRYPTO_PROGRAMS
        .get(program)
        .map(|path| Cow::Borrowed(path.as_path()))
        .unwrap_or_else(|| Cow::Borrowed(Path::new(program)))
}

// One subprocess seam for every cryptographic tool. Output pipes are drained
// concurrently and every child is waited for until it exits; nothing bounds
// this seam by a count or a clock.
