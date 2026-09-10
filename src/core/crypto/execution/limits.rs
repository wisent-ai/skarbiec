// How many crypto programs may run at once, which binaries they are, and how
// long one of them may take. A permit is held for the length of one run.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, LazyLock, Mutex};
use std::time::Duration;

const DEFAULT_CRYPTO_LIMIT: usize = 8;
const DEFAULT_GPG_LIMIT: usize = 2;
const DEFAULT_CRYPTO_TIMEOUT_SECONDS: u64 = 30;

pub(super) struct ExecutionLimit {
    active: Mutex<usize>,
    available: Condvar,
    pub(super) maximum: usize,
}

impl ExecutionLimit {
    pub(super) fn acquire(&self) -> ExecutionPermit<'_> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active >= self.maximum {
            active = self
                .available
                .wait(active)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *active += 1;
        ExecutionPermit { limit: self }
    }

    /// Take the whole limit, so that nothing holding it can be running while
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
    /// recovery now waits for the gpg capacity to drain instead.
    pub(super) fn acquire_exclusive(&self) -> ExclusivePermit<'_> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active > 0 {
            active = self
                .available
                .wait(active)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *active = self.maximum;
        ExclusivePermit { limit: self }
    }

    pub(super) fn in_use(&self) -> usize {
        *self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(super) struct ExecutionPermit<'a> {
    limit: &'a ExecutionLimit,
}

impl Drop for ExecutionPermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .limit
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = active.saturating_sub(1);
        // Every waiter, not one: an exclusive waiter only proceeds once the
        // count reaches zero, and waking a single ordinary waiter instead can
        // leave it parked behind capacity it would never be told about.
        self.limit.available.notify_all();
    }
}

pub(super) struct ExclusivePermit<'a> {
    limit: &'a ExecutionLimit,
}

impl Drop for ExclusivePermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .limit
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = 0;
        self.limit.available.notify_all();
    }
}

pub(super) static CRYPTO_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(|| ExecutionLimit {
    active: Mutex::new(0),
    available: Condvar::new(),
    maximum: configured_limit("SKARBIEC_CRYPTO_CONCURRENCY", DEFAULT_CRYPTO_LIMIT),
});
pub(super) static GPG_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(|| ExecutionLimit {
    active: Mutex::new(0),
    available: Condvar::new(),
    maximum: configured_limit("SKARBIEC_GPG_CONCURRENCY", DEFAULT_GPG_LIMIT),
});
pub(super) static GPG_RECOVERY_GENERATION: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));
static CRYPTO_PROGRAMS: LazyLock<HashMap<&'static str, PathBuf>> = LazyLock::new(|| {
    ["gpg", "gpgconf", "openssl", "shasum", "pkill"]
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

fn configured_limit(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

pub(super) fn execution_timeout() -> Duration {
    let seconds = std::env::var("SKARBIEC_CRYPTO_TIMEOUT_SECONDS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CRYPTO_TIMEOUT_SECONDS);
    Duration::from_secs(seconds)
}

// One bounded subprocess seam for every cryptographic tool. Output pipes are
// drained concurrently, every child has a deadline, and timed-out children are
