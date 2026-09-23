use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::process::Child;

/// A broker owned by one test, stopped when that test ends however it ends.
pub struct Broker {
    pub(super) child: Child,
    pub(super) port: u16,
}

impl Broker {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether this broker has already exited, and how. A test waiting on the
    /// broker's next action asks this so a broker that died is a failure now
    /// rather than a wait that never ends.
    pub fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("read the broker's exit state")
    }

    /// The absolute URL of one route on this broker.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}:{}{path}", Ipv4Addr::LOCALHOST, self.port)
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Ask the kernel for a free loopback port and give it straight back.
///
/// A hard-coded port is the whole hazard: 8787 is this product's own default
/// and is occupied on any machine running the broker, so a test naming it
/// talks to the operator's vault instead of its own.
pub(super) fn reserve_port() -> u16 {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("reserve a loopback port for this fixture");
    listener
        .local_addr()
        .expect("read the reserved loopback port")
        .port()
}
