// The bounded worker pool behind the listener: a fixed number of threads, a
// bounded queue, an explicit answer when the queue is full, and the one
// request failure that ends the process.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::net::TcpStream;
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use wisent_errors::Code;

use super::routes::handle;
use super::{configured_usize, write_response, DEFAULT_HTTP_QUEUE, DEFAULT_HTTP_WORKERS};

pub(super) struct RequestPool {
    sender: mpsc::SyncSender<TcpStream>,
    lost: Mutex<mpsc::Receiver<anyhow::Error>>,
}

impl RequestPool {
    pub(super) fn new() -> Result<Self> {
        let workers = configured_usize("SKARBIEC_HTTP_WORKERS", DEFAULT_HTTP_WORKERS);
        let queue = configured_usize("SKARBIEC_HTTP_QUEUE", DEFAULT_HTTP_QUEUE);
        let (sender, receiver) = mpsc::sync_channel::<TcpStream>(queue);
        let receiver = Arc::new(Mutex::new(receiver));
        let (lost_sender, lost) = mpsc::channel();
        for index in 0..workers {
            let receiver = Arc::clone(&receiver);
            let lost_sender = lost_sender.clone();
            std::thread::Builder::new()
                .name(format!("skarbiec-http-{index}"))
                .spawn(move || loop {
                    let next = receiver
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .recv();
                    let Ok(stream) = next else {
                        break;
                    };
                    let Err(error) = handle(stream) else {
                        continue;
                    };
                    if descriptor_lost(&error) {
                        let _ = lost_sender.send(error);
                        break;
                    }
                    eprintln!("request error: {error}");
                })
                .context("spawn bounded HTTP worker")?;
        }
        Ok(Self {
            sender,
            lost: Mutex::new(lost),
        })
    }

    /// Wait for the one request failure that ends this process, and return it.
    ///
    /// charless-mac-mini's vault 0.3.12 printed `request error: Bad file
    /// descriptor (os error 9)` for every request it accepted, for 20000 log
    /// lines, while launchd and the health beacon kept reporting its unit
    /// active: the fleet's credential route answered nothing and nothing
    /// restarted it, because a process that keeps running is a process launchd
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
            Err(_) => Err(anyhow!("every Skarbiec request worker stopped")),
        }
    }

    pub(super) fn submit(&self, stream: TcpStream) {
        match self.sender.try_send(stream) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(mut stream)) => {
                let _ = write_response(
                    &mut stream,
                    "HTTP/1.1 503 Service Unavailable",
                    &json!({
                        "error": "skarbiec request capacity exhausted",
                        "error_code": Code::RateLimit.as_str(),
                        "retryable": true,
                    }),
                );
            }
            Err(mpsc::TrySendError::Disconnected(mut stream)) => {
                let _ = write_response(
                    &mut stream,
                    "HTTP/1.1 503 Service Unavailable",
                    &json!({
                        "error": "skarbiec request workers unavailable",
                        "error_code": Code::InfraDown.as_str(),
                        "retryable": false,
                    }),
                );
            }
        }
    }
}

/// EBADF anywhere in the failure's chain. Every other request failure belongs
/// to its one connection and its client, and ends only that request.
fn descriptor_lost(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|cause| cause.raw_os_error() == Some(libc::EBADF))
}
