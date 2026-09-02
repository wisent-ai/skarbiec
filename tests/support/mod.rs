#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// Where fixture roots live.
///
/// Deliberately neither `HOME` nor `TMPDIR`. `HOME` is the operator's own
/// configuration - `~/.stado` holds the live vault, the routes table and the
/// service unlock file - and a fixture that both writes and `remove_dir_all`s
/// below it is one typo away from taking real state with it. `TMPDIR` is
/// rejected for a duller reason: GnuPG binds sockets under `GNUPGHOME`, macOS
/// caps `sun_path` at 104 bytes, and the per-user `TMPDIR` spends forty of
/// them before this fixture adds a name.
const TEMP_BASE: &str = "/tmp/skarbiec-tests";

/// How long a spawned broker may take to bind its port before the test that
/// asked for it fails. Generous: a cold fixture pays for gpg-agent's startup.
const BROKER_READY_TIMEOUT: Duration = Duration::from_secs(20);

pub struct CliFixture {
    pub root: PathBuf,
    pub gnupg: PathBuf,
    pub vault: PathBuf,
    /// A port reserved for this fixture by the kernel, so a broker a test
    /// starts can never be confused with one already running on this machine.
    pub port: u16,
}

impl CliFixture {
    pub fn new(area: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        // GnuPG places sockets below GNUPGHOME. Keep this path short enough
        // for macOS AF_UNIX while making parallel fixtures distinct.
        let root = PathBuf::from(TEMP_BASE).join(format!(
            "{area}-{:x}{:08x}{sequence:x}",
            std::process::id(),
            unique & 0xffff_ffff
        ));
        let gnupg = root.join("gnupg");
        fs::create_dir_all(&gnupg).expect("create isolated GPG home");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect isolated fixture root");
        fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700))
            .expect("protect isolated GPG home");
        Self {
            vault: root.join("vault.json"),
            port: reserve_port(),
            root,
            gnupg,
        }
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command(args)
            .output()
            .expect("run real skarbiec binary")
    }

    pub fn run_with_vault(&self, vault: &Path, args: &[&str]) -> Output {
        let mut command = self.command(args);
        command.env("SKARBIEC_VAULT_FILE", vault);
        command.output().expect("run real skarbiec binary")
    }

    pub fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start real skarbiec binary");
        child
            .stdin
            .take()
            .expect("open child stdin")
            .write_all(stdin.as_bytes())
            .expect("write command stdin");
        child.wait_with_output().expect("collect command output")
    }

    pub fn init(&self, owner: &str) {
        let output = self.run(&["init", owner]);
        assert_success("initialize isolated vault", &output);
    }

    pub fn assert_vault_exists(&self) {
        assert!(Path::new(&self.vault).is_file(), "vault was not written");
    }

    /// Start a broker on this fixture's reserved port and wait until it is
    /// actually accepting connections.
    ///
    /// Waiting is the point. A broker that fails to bind still spawns, so a
    /// test that only sleeps will happily send its requests to whatever else
    /// answers on that port - on an operator's machine, the service holding
    /// the real vault. Here a broker that never listens fails the test that
    /// asked for it instead.
    pub fn serve(&self) -> Broker {
        let port = self.port.to_string();
        let child = self
            .command(&["serve", "--port", &port])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start real skarbiec broker");
        let mut broker = Broker {
            child,
            port: self.port,
        };
        broker.await_listening();
        broker
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_skarbiec"));
        command.args(args);
        // Every backend this product reads is selected by a `SKARBIEC_`
        // variable, and each one falls back to a path below `HOME` when it is
        // unset. Redirecting `HOME` covers the fallbacks; dropping the whole
        // prefix covers the other half - an operator shell that exports
        // `SKARBIEC_CAPABILITY_ROUTES_FILE` or `SKARBIEC_UNLOCK` would
        // otherwise hand a test the real table and the real passphrase.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SKARBIEC_") {
                command.env_remove(&key);
            }
        }
        command
            .env("HOME", &self.root)
            .env("GNUPGHOME", &self.gnupg)
            .env("SKARBIEC_VAULT_FILE", &self.vault)
            .env("SKARBIEC_AUDIT_FILE", self.root.join("audit.jsonl"));
        command
    }
}

impl Drop for CliFixture {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", &self.gnupg)
            .args(["--kill", "all"])
            .status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A broker owned by one test, stopped when that test ends however it ends.
pub struct Broker {
    child: Child,
    port: u16,
}

impl Broker {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The absolute URL of one route on this broker.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}:{}{path}", Ipv4Addr::LOCALHOST, self.port)
    }

    fn await_listening(&mut self) {
        let address = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port));
        let deadline = Instant::now() + BROKER_READY_TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("broker exited before listening on {address}: {status}");
            }
            if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("broker never began listening on {address}");
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
fn reserve_port() -> u16 {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("reserve a loopback port for this fixture");
    listener
        .local_addr()
        .expect("read the reserved loopback port")
        .port()
}

pub fn assert_success(context: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{context} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}
