//! The deadline a network exchange is held to, and the socket that keeps it.
//!
//! A run Stado starts from a schedule (`skarbiec maintain`, `rotation run`)
//! must end before that schedule fires again, or the next run starts behind
//! it and one that never gets an answer holds the item's rotation state for
//! good. Stado names the schedule to the run: `STADO_SCHEDULE_ID`, its
//! `STADO_SCHEDULE_CRON`, and `STADO_SCHEDULE_NEXT_DUE_AT`, the RFC 3339
//! moment of its next firing. Every exchange such a run makes, connect,
//! TLS handshake, request and reply, ends by that moment or is refused
//! naming the schedule. A command a person runs carries no schedule and
//! waits until the server answers or the person interrupts it.

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The schedule a run was started from, and when it fires again.
#[derive(Clone, Debug)]
pub(crate) struct Deadline {
    schedule: String,
    cron: String,
    next_due: String,
    at: SystemTime,
}

impl Deadline {
    /// The deadline of the schedule this process was started from; none for
    /// a run no schedule started. A schedule named without its next firing,
    /// or with one that is no RFC 3339 moment, is refused naming the
    /// variable: a scheduled run with no bound is the hang this prevents.
    pub(crate) fn of_this_run() -> Result<Option<Deadline>> {
        let Some(schedule) = crate::core::env::text("STADO_SCHEDULE_ID")? else {
            return Ok(None);
        };
        let next_due =
            crate::core::env::text("STADO_SCHEDULE_NEXT_DUE_AT")?.with_context(|| {
                format!(
                    "this run was started by Stado schedule {schedule} (STADO_SCHEDULE_ID) and \
                 STADO_SCHEDULE_NEXT_DUE_AT, the schedule's next firing, is not set, so no \
                 network exchange can be held to end before it; Stado sets both on a \
                 scheduled run"
                )
            })?;
        let cron = crate::core::env::text("STADO_SCHEDULE_CRON")?.with_context(|| {
            format!(
                "this run was started by Stado schedule {schedule} (STADO_SCHEDULE_ID) and \
                 STADO_SCHEDULE_CRON, its period, is not set; Stado sets it on a scheduled run"
            )
        })?;
        let at = OffsetDateTime::parse(next_due.trim(), &Rfc3339).with_context(|| {
            format!(
                "STADO_SCHEDULE_NEXT_DUE_AT {next_due:?} (schedule {schedule}) is not an RFC \
                 3339 moment"
            )
        })?;
        let at = SystemTime::from(at);
        Ok(Some(Deadline {
            schedule,
            cron,
            next_due,
            at,
        }))
    }

    /// What holds the exchange, as every refusal says it.
    fn named(&self) -> String {
        format!(
            "deadline from routine {} period {} (its next firing, {})",
            self.schedule, self.cron, self.next_due
        )
    }

    /// The time left, or the refusal once none is.
    fn left(&self) -> std::io::Result<Duration> {
        match self.at.duration_since(SystemTime::now()) {
            Ok(left) if !left.is_zero() => Ok(left),
            _ => Err(self.passed()),
        }
    }

    fn passed(&self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "the exchange did not end by the {}; the next run starts then",
                self.named()
            ),
        )
    }
}

/// A connection to `place`, held to `deadline` when there is one: connect,
/// and then every read and write, ends by it.
pub(crate) fn connect(
    place: impl ToSocketAddrs,
    deadline: Option<&Deadline>,
) -> std::io::Result<Bounded> {
    let Some(deadline) = deadline else {
        return Ok(Bounded {
            stream: TcpStream::connect(place)?,
            deadline: None,
        });
    };
    let mut last = None;
    for address in place.to_socket_addrs()? {
        match connect_one(address, deadline) {
            Ok(stream) => {
                return Ok(Bounded {
                    stream,
                    deadline: Some(deadline.clone()),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => return Err(error),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "the address resolves to no socket address",
        )
    }))
}

fn connect_one(address: SocketAddr, deadline: &Deadline) -> std::io::Result<TcpStream> {
    TcpStream::connect_timeout(&address, deadline.left()?).map_err(|error| {
        if error.kind() == std::io::ErrorKind::TimedOut {
            deadline.passed()
        } else {
            error
        }
    })
}

/// A TCP connection whose every read and write ends by its deadline.
pub(crate) struct Bounded {
    stream: TcpStream,
    deadline: Option<Deadline>,
}

impl Bounded {
    /// Run one socket operation with the time left as its timeout, the
    /// timeout said as the deadline that ended it.
    fn bounded<T>(
        &mut self,
        set: fn(&TcpStream, Option<Duration>) -> std::io::Result<()>,
        operation: impl FnOnce(&mut TcpStream) -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        let Some(deadline) = &self.deadline else {
            return operation(&mut self.stream);
        };
        set(&self.stream, Some(deadline.left()?))?;
        operation(&mut self.stream).map_err(|error| match error.kind() {
            // A socket timeout reads as WouldBlock on Unix and TimedOut on
            // Windows.
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => deadline.passed(),
            _ => error,
        })
    }
}

impl Read for Bounded {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.bounded(TcpStream::set_read_timeout, |stream| stream.read(out))
    }
}

impl Write for Bounded {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.bounded(TcpStream::set_write_timeout, |stream| stream.write(data))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
