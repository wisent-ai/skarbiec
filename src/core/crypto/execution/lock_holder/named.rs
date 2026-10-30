//! What the keyring's lock checks inside every gpg run read: the keyring's
//! home, this host's name and the keyboxd socket of that home, named once
//! by gpgconf and uname in this process. Those checks stand inside every
//! gpg run, gpgconf's included, so they run no program themselves; until
//! [`super::keyring_lock_holders`] has named the three, they know no holder.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::{node_name, socket_server, KEYBOXD_DATABASE_LOCK, LOCK_FILES};

/// The keyring's home, this host's name and the keyboxd socket of that
/// home. All are fixed for the life of the process.
struct Named {
    home: PathBuf,
    node: String,
    keyboxd_socket: PathBuf,
}

static NAMED: OnceLock<Named> = OnceLock::new();

/// The socket the keyboxd of this home serves, as gpgconf names it.
fn keyboxd_socket() -> Result<PathBuf, String> {
    super::super::run_once("gpgconf", &["--list-dirs", "keyboxd-socket"], None)
        .map(|socket| PathBuf::from(socket.trim()))
        .map_err(|error| format!("gpgconf could not name the keyboxd socket: {error:#}"))
}

/// Record `home` with this host's name and its keyboxd socket, once; what
/// could not be named, one sentence each.
pub(super) fn remember(home: &Path) -> Vec<String> {
    if NAMED.get().is_some() {
        return Vec::new();
    }
    match (node_name(), keyboxd_socket()) {
        (Ok(node), Ok(keyboxd_socket)) => {
            NAMED.get_or_init(|| Named {
                home: home.to_path_buf(),
                node,
                keyboxd_socket,
            });
            Vec::new()
        }
        (node, socket) => [node.err(), socket.err()].into_iter().flatten().collect(),
    }
}

/// The holder pid and host one lock file of the named home records; none
/// when the lock is absent. A lock that cannot be read, or that does not
/// hold a positive pid and a host on its first two lines, the way GnuPG
/// writes one, is the error.
fn recorded(named: &Named, file: &str) -> Result<Option<(libc::pid_t, String)>, String> {
    let lock = named.home.join(file);
    let held = match std::fs::read_to_string(&lock) {
        Ok(held) => held,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{} cannot be read: {error}", lock.display())),
    };
    let mut lines = held.lines().map(str::trim);
    let pid = lines
        .next()
        .filter(|pid| !pid.is_empty())
        .ok_or_else(|| format!("{} names no holder pid", lock.display()))?;
    let pid = pid.parse::<libc::pid_t>().map_err(|error| {
        format!(
            "{} names holder {pid:?}, not a pid: {error}",
            lock.display()
        )
    })?;
    if !pid.is_positive() {
        return Err(format!(
            "{} names holder {pid}, not a positive pid",
            lock.display()
        ));
    }
    let host = lines
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| format!("{} names no holder host", lock.display()))?;
    Ok(Some((pid, host.to_owned())))
}

/// The pids this host's lock files name as holding the keyring; empty
/// before the home is named. A lock of another host names no holder here.
pub(in crate::core::crypto::execution) fn recorded_holder_pids() -> Result<Vec<u32>, String> {
    let Some(named) = NAMED.get() else {
        return Ok(Vec::new());
    };
    let mut pids = Vec::new();
    for file in LOCK_FILES {
        if let Some((pid, host)) = recorded(named, file)? {
            if host == named.node {
                pids.push(pid.unsigned_abs());
            }
        }
    }
    Ok(pids)
}

/// Whether `pid` is a process that lives now. A process this account may
/// not signal still lives; any other failure of the probe is the error.
fn lives(pid: libc::pid_t) -> Result<bool, String> {
    // SAFETY: signal 0 delivers nothing; it only asks whether pid exists.
    let status = unsafe { libc::kill(pid, libc::c_int::default()) };
    if !status.is_negative() {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(format!("whether pid {pid} lives cannot be read: {error}")),
    }
}

/// The keyboxd database lock's holder, as a sentence, when it is a live
/// process of this host other than the one serving this home's keyboxd
/// socket. keyboxd holds that lock for as long as it keeps the database
/// open, so a holder that no longer serves the socket keeps the database
/// from every keyboxd gpg starts: each waits on the lock, and every gpg
/// behind them waits with it. It connects to the socket to learn who serves
/// it. None before the home is named, and for a lock that is absent, of
/// another host, held by a process that is gone (GnuPG takes a stale lock
/// over) or held by the socket's own server.
///
/// The kernel names as a socket's server the process that called `listen`
/// on it. A keyboxd that gpg starts with `--daemon` listens and then forks:
/// the process that listened exits and its child serves the socket and
/// holds the lock. When the process that listened no longer runs, the
/// server is that child and cannot be named, so the holder is not judged
/// orphaned here; a run that waits behind a holder that truly lost the
/// socket is still found standing by the next maintenance pass. Judged
/// orphaned, every healthy keyboxd home looked wedged whenever a gpg run
/// had not yet written its first status, and the maintenance pass replaced
/// the daemons under every read in flight, each of which then started
/// daemons of its own.
pub(in crate::core::crypto::execution) fn orphaned_database_holder(
) -> Result<Option<String>, String> {
    let Some(named) = NAMED.get() else {
        return Ok(None);
    };
    let Some((pid, host)) = recorded(named, KEYBOXD_DATABASE_LOCK)? else {
        return Ok(None);
    };
    if host != named.node || !lives(pid)? {
        return Ok(None);
    }
    let serving = match socket_server::peer_pid(&named.keyboxd_socket) {
        Ok(server) if server == pid => return Ok(None),
        Ok(server) if !lives(server)? => return Ok(None),
        Ok(server) => format!("it is served by pid {server}"),
        Err(why) => why,
    };
    Ok(Some(format!(
        "{} is held by pid {pid}, which does not serve the keyboxd socket {} ({serving}), so \
         every keyboxd gpg starts waits on that lock",
        named.home.join(KEYBOXD_DATABASE_LOCK).display(),
        named.keyboxd_socket.display()
    )))
}
