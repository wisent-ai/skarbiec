// The bounded worker pool behind the listener: a fixed number of threads, a
// bounded queue, and an explicit answer when the queue is full.

use anyhow::{Context, Result};
use serde_json::json;
use wisent_errors::Code;
use std::net::TcpStream;
use std::sync::{mpsc, Arc, Mutex};

use super::routes::handle;
use super::{configured_usize, write_response, DEFAULT_HTTP_QUEUE, DEFAULT_HTTP_WORKERS};

pub(super) struct RequestPool {
    sender: mpsc::SyncSender<TcpStream>,
}

impl RequestPool {
    pub(super) fn new() -> Result<Self> {
        let workers = configured_usize("SKARBIEC_HTTP_WORKERS", DEFAULT_HTTP_WORKERS);
        let queue = configured_usize("SKARBIEC_HTTP_QUEUE", DEFAULT_HTTP_QUEUE);
        let (sender, receiver) = mpsc::sync_channel::<TcpStream>(queue);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..workers {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name(format!("skarbiec-http-{index}"))
                .spawn(move || loop {
                    let next = receiver
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv();
                    let Ok(stream) = next else {
                        break;
                    };
                    if let Err(error) = handle(stream) {
                        eprintln!("request error: {error}");
                    }
                })
                .context("spawn bounded HTTP worker")?;
        }
        Ok(Self { sender })
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
