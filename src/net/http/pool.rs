// The request workers behind the listener: every accepted connection is
// served on a thread of its own, so no request waits behind a worker count
// or is refused because a queue is full; the one request failure that ends
// the process is handed back from whichever thread meets it.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::net::TcpStream;
use std::sync::{mpsc, Mutex, PoisonError};
use wisent_errors::Code;

use super::routes::handle;
use super::write_response;

pub(super) struct RequestPool {
    lost_sender: mpsc::Sender<anyhow::Error>,
    lost: Mutex<mpsc::Receiver<anyhow::Error>>,
}

impl RequestPool {
    pub(super) fn new() -> Result<Self> {
        let (lost_sender, lost) = mpsc::channel();
        Ok(Self {
            lost_sender,
            lost: Mutex::new(lost),
        })
    }

    /// Wait for the one request failure that ends this process, and return it.
    ///
    /// A vault can print `request error: Bad file descriptor (os error 9)`
    /// for every request it accepts, for tens of thousands of log lines,
    /// while launchd and the health beacon keep reporting its unit active:
    /// the fleet's credential route answers nothing and nothing restarts it,
    /// because a process that keeps running is a process launchd
    /// leaves alone. A client can reset, stall or abandon its connection; it
    /// cannot close a descriptor inside this process. So the first worker that
    /// meets EBADF on a socket this process just accepted hands the failure
    /// here, the component ends, and with it the process launchd restarts.
    pub(super) fn descriptor_loss(&self) -> Result<Value> {
        let lost = self
            .lost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        match lost {
            Ok(error) => Err(error.context(
                "a request worker found the socket of a connection this process had just \
                 accepted already closed (EBADF); no client can close a descriptor inside this \
                 process, so no answer it writes can be trusted to reach the caller it is for",
            )),
            Err(_) => Err(anyhow!("the request workers' failure channel closed")),
        }
    }

    /// Serve `stream` on a thread of its own. When the system refuses a
    /// thread, the caller is answered with the system's own reason.
    pub(super) fn submit(&self, stream: TcpStream) {
        let answer = stream.try_clone();
        let lost = self.lost_sender.clone();
        let started = std::thread::Builder::new()
            .name("skarbiec-http".to_owned())
            .spawn(move || {
                let Err(error) = handle(stream) else {
                    return;
                };
                if descriptor_lost(&error) {
                    let _ = lost.send(error);
                    return;
                }
                eprintln!("request error: {error}");
            });
        let (Err(refused), Ok(mut stream)) = (started, answer) else {
            return;
        };
        let _ = write_response(
            &mut stream,
            "HTTP/1.1 503 Service Unavailable",
            &json!({
                "error": format!("skarbiec could not start a thread for this request: {refused}"),
                "error_code": Code::InfraDown.as_str(),
                "retryable": true,
            }),
        );
    }
}

/// EBADF or ENOSPC anywhere in the failure's chain. Every other request
/// failure belongs to its one connection and its client, and ends only that
/// request.
///
/// ENOSPC joins EBADF because the process that meets it does not recover:
/// once the disk fills, the vault answers every request with `No space left
/// on device (os error 28)` and keeps doing so after the disk has room again,
/// so every Stado credential read in the fleet fails until the process is
/// replaced. Ending it hands the restart to launchd, which starts a clean
/// vault once there is room.
fn descriptor_lost(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|cause| matches!(cause.raw_os_error(), Some(libc::EBADF | libc::ENOSPC)))
}
