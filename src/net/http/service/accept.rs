//! What one failed `accept` means for the listener that reported it.
//!
//! A client that resets its connection while it still waits in the listen
//! queue is reported by the kernel as ECONNABORTED from `accept`; Linux also
//! hands back a pending network error of that one connection (EPROTO,
//! EHOSTUNREACH, ...). charless-mac-mini's vault logged `accept error:
//! Software caused connection abort (os error 53)` continuously on 2026-09-23
//! and kept serving. The one Skarbiec process instead ended its HTTP
//! component on the first such error, and a component that ends ends the
//! process: one impatient client restarted every listener, the capability
//! broker and replication. An error that belongs to one connection now ends
//! only that connection; any other error still ends the listener, and with it
//! the process launchd restarts.

use std::io::{Error, ErrorKind};

/// `Ok` when `error` ended only the connection being accepted, so the
/// listener accepts the next one; the error itself otherwise.
pub(crate) fn survive(error: Error) -> std::io::Result<()> {
    let connection_gone = matches!(
        error.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted
    ) || matches!(
        error.raw_os_error(),
        Some(
            libc::EPROTO
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::EHOSTUNREACH
                | libc::ENETDOWN
                | libc::ENETUNREACH
                | libc::EOPNOTSUPP
        )
    );
    if connection_gone {
        Ok(())
    } else {
        Err(error)
    }
}
