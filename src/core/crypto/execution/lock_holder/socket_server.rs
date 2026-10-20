//! The process serving a Unix socket, as the kernel names the peer of a
//! connection to it. The peer of a connection is the process that listens,
//! whether or not it has accepted the connection yet, so a daemon that is
//! itself stuck is still named.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// The pid of the process serving `socket`, or why it cannot be named:
/// nothing answers the socket, or the kernel will not say who does.
pub(super) fn peer_pid(socket: &Path) -> Result<libc::pid_t, String> {
    let stream =
        UnixStream::connect(socket).map_err(|error| format!("nothing serves it: {error}"))?;
    platform::peer_pid(&stream).map_err(|error| format!("its server cannot be named: {error}"))
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{AsRawFd, UnixStream};

    pub(super) fn peer_pid(stream: &UnixStream) -> std::io::Result<libc::pid_t> {
        let mut pid = libc::pid_t::default();
        let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::pid_t>())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        // SAFETY: pid and length describe one writable pid_t, the value
        // LOCAL_PEERPID writes.
        let status = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut length,
            )
        };
        if status.is_negative() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(pid)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{AsRawFd, UnixStream};

    pub(super) fn peer_pid(stream: &UnixStream) -> std::io::Result<libc::pid_t> {
        let mut credentials = libc::ucred {
            pid: libc::pid_t::default(),
            uid: libc::uid_t::default(),
            gid: libc::gid_t::default(),
        };
        let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        // SAFETY: credentials and length describe one writable ucred, the
        // value SO_PEERCRED writes.
        let status = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if status.is_negative() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(credentials.pid)
    }
}
