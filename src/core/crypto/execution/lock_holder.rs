// Who holds the keyring's lock when gpg waits on it.
//
// A gpg run that cannot open the key database waits on its lock and, when
// the holder never lets go, ends `keydb_search failed: Operation timed out`
// after tens of minutes. The failure names neither the holder nor how long
// it has held the lock, so a vault answering every read with 503 could not
// be told from a slow one. GnuPG's lock files carry the holder's pid and
// host on their first two lines; reading them names the process to look at.

use std::path::{Path, PathBuf};

/// The lock files GnuPG keeps beside the key databases of one home: the
/// keyboxd database and the legacy keybox.
const LOCK_FILES: &[&str] = &["public-keys.d/pubring.db.lock", "pubring.kbx.lock"];

/// This keyring's home as GnuPG itself names it.
fn gnupg_home() -> Result<PathBuf, String> {
    super::run_once("gpgconf", &["--list-dirs", "homedir"], None)
        .map(|home| PathBuf::from(home.trim()))
        .map_err(|error| format!("gpgconf could not name the keyring's home: {error:#}"))
}

/// What a pid runs now, as the process table says; why not, when it cannot.
fn command_of(pid: &str) -> String {
    match super::run_once("ps", &["-o", "command=", "-p", pid], None) {
        Ok(command) if !command.trim().is_empty() => format!("running {}", command.trim()),
        Ok(_) => "not running on this host".to_string(),
        Err(error) => format!("its command could not be read: {error:#}"),
    }
}

/// One lock file's holder, as a sentence: its pid, host and what the pid
/// runs now, and when the lock was taken.
fn describe(lock: &Path) -> Option<String> {
    let held = std::fs::read_to_string(lock).ok()?;
    let mut lines = held.lines();
    let pid = lines.next()?.trim().to_string();
    let host = lines.next().map(str::trim).filter(|host| !host.is_empty());
    let since = std::fs::metadata(lock)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|taken| taken.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|taken| i64::try_from(taken.as_secs()).ok())
        .map(crate::core::clock::iso_at);
    let running = command_of(&pid);
    let on = host
        .map(|host| format!(" on {host}"))
        .into_iter()
        .collect::<String>();
    let taken = since
        .map(|since| format!(", taken {since}"))
        .into_iter()
        .collect::<String>();
    Some(format!(
        "{} is held by pid {pid}{on} ({running}){taken}",
        lock.display()
    ))
}

/// Every keyring lock of this home that is held now, one sentence each.
pub(super) fn keyring_lock_holders() -> Vec<String> {
    match gnupg_home() {
        Ok(home) => LOCK_FILES
            .iter()
            .map(|file| home.join(file))
            .filter_map(|lock| describe(&lock))
            .collect(),
        Err(why) => vec![why],
    }
}
