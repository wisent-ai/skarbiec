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

/// Canonical executable paths from gpgconf's percent-escaped program field.
/// Its record is `name:description:pgmname:`; the trailing field is empty.
fn gnupg_programs() -> Result<Vec<PathBuf>, String> {
    let components = super::run_once("gpgconf", &["--list-components"], None)
        .map_err(|error| format!("gpgconf could not list GnuPG's programs: {error:#}"))?;
    components
        .lines()
        .map(|line| {
            let mut fields = line.split(':');
            let _name = fields.next();
            let _description = fields.next();
            let program = fields
                .next()
                .filter(|program| !program.is_empty())
                .ok_or_else(|| format!("gpgconf component has no executable field: {line}"))?;
            let program = percent_encoding::percent_decode_str(program)
                .decode_utf8()
                .map_err(|error| format!("gpgconf executable path is not UTF-8: {error}"))?;
            std::fs::canonicalize(program.as_ref()).map_err(|error| {
                format!("could not establish GnuPG executable identity for {program}: {error}")
            })
        })
        .collect()
}

/// The executable a pid runs, or none when the pid runs nothing on this host.
/// Linux names it through `/proc`; elsewhere `ps -o comm=` prints its path.
fn executable_of(pid: &str) -> Result<Option<PathBuf>, String> {
    if let Ok(path) = std::fs::read_link(Path::new("/proc").join(pid).join("exe")) {
        return Ok(Some(path));
    }
    match super::run_once("ps", &["-o", "comm=", "-p", pid], None) {
        Ok(path) if path.trim().is_empty() => Ok(None),
        Ok(path) => Ok(Some(PathBuf::from(path.trim()))),
        Err(error) => Err(format!(
            "the process table could not name pid {pid}: {error:#}"
        )),
    }
}

/// This host's name as GnuPG writes it into a lock file.
fn node_name() -> Result<String, String> {
    super::run_once("uname", &["-n"], None)
        .map(|name| name.trim().to_string())
        .map_err(|error| format!("uname could not name this host: {error:#}"))
}

/// Release one keyring lock its holder can no longer let go of, and say what
/// was done. Called only after gpg itself gave up waiting on the lock and
/// with every gpg of this process drained, so no decryption of ours holds
/// it:
/// - a lock is considered only when its recorded host is this host; a
///   different or absent host is not evidence of a stale lock, because the
///   keyring may be shared with another machine;
/// - an executable outside the configured GnuPG paths is left alone: a
///   basename or a possibly reused pid does not establish ownership;
/// - a lock one of GnuPG's programs has held past gpg's own wait is wedged,
///   and that program is ended the way a wedged daemon is.
fn release(lock: &Path, gnupg: &[PathBuf], node: &str) -> Option<String> {
    let held = std::fs::read_to_string(lock).ok()?;
    let mut lines = held.lines();
    let recorded_pid = lines.next()?.trim();
    let pid = match recorded_pid.parse::<std::num::NonZeroI32>() {
        Ok(pid) if pid.get().is_positive() => pid.to_string(),
        _ => {
            return Some(format!(
                "left {} alone: {recorded_pid:?} is not a positive process id",
                lock.display()
            ));
        }
    };
    let Some(host) = lines.next().map(str::trim).filter(|host| !host.is_empty()) else {
        return Some(format!(
            "left {} alone: the lock names no host; ownership cannot be established",
            lock.display()
        ));
    };
    if host != node {
        return Some(format!(
            "left {} alone: holder pid {pid} belongs to host {host}, not {node}; a shared keyring lock is not stale merely because its host differs",
            lock.display()
        ));
    }
    let sentence = match executable_of(&pid) {
        Err(why) => format!("left {} alone: {why}", lock.display()),
        // GnuPG owns stale-lock detection on the following retry. Unlinking
        // here could remove a replacement lock acquired after our snapshot.
        Ok(None) => format!(
            "left {} for GnuPG's stale-lock recovery: holder pid {pid} runs nothing here",
            lock.display()
        ),
        Ok(Some(program)) => match std::fs::canonicalize(&program) {
            Err(error) => format!(
                "left {} alone: could not establish executable identity for pid {pid} ({}): {error}",
                lock.display(),
                program.display()
            ),
            Ok(program) if !gnupg.contains(&program) => format!(
                "left {} alone: pid {pid} runs {}, not a configured GnuPG executable; a different executable is not proof that this lock is safe to remove",
                lock.display(),
                program.display()
            ),
            Ok(program) => match super::run_once("kill", &["-TERM", &pid], None) {
                Ok(_) => format!(
                    "ended pid {pid} ({}), which held {} past gpg's own wait",
                    program.display(),
                    lock.display()
                ),
                Err(error) => format!(
                    "could not end pid {pid} ({}) holding {}: {error:#}",
                    program.display(),
                    lock.display()
                ),
            },
        },
    };
    Some(sentence)
}

/// Release every keyring lock of this home whose holder can no longer let go
/// (see [`release`]), one sentence per lock acted on or left alone.
pub(super) fn release_wedged_locks() -> Vec<String> {
    let (home, gnupg, node) = match (gnupg_home(), gnupg_programs(), node_name()) {
        (Ok(home), Ok(gnupg), Ok(node)) => (home, gnupg, node),
        (home, gnupg, node) => {
            return [home.err(), gnupg.err(), node.err()]
                .into_iter()
                .flatten()
                .collect()
        }
    };
    LOCK_FILES
        .iter()
        .map(|file| home.join(file))
        .filter_map(|lock| release(&lock, &gnupg, &node))
        .collect()
}
