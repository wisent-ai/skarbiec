//! What the vault does when a `gpg` child loses the daemon it was talking to.
//!
//! On 2026-09-03 a release pipeline's post-publish step died on
//! `Skarbiec returned HTTP 503 {gpg: public key decryption failed: Broken pipe
//! / item is stored but could not be decrypted}, error_code infra_down`, after
//! a build had compiled 182 crates. Two things had to be true for that
//! sentence to reach a caller, and both were:
//!
//!   * the vault's own daemon recovery killed `gpg-agent` and `keyboxd` while
//!     a sibling request still had a live `gpg` child holding a socket to
//!     them, so the recovery manufactured the broken pipe it exists to
//!     repair; and
//!   * a lost socket was not among the failures worth recovering from, so the
//!     one failure that recovery exists for was the one that never got a
//!     retry, and left as `503 infra_down` for the caller to read as
//!     unreachable infrastructure.
//!
//! A sibling is never hypothetical here: the broker decrypts every canary item
//! from its own readiness monitor on a timer, so request traffic is always
//! concurrent with a decryption. These tests pin that timer far out and drive
//! the concurrency themselves.
//!
//! Both facts are observed through the real broker. The crypto seam resolves
//! each tool through `PATH`, so a scripted `gpg` and `gpgconf` on this
//! fixture's `PATH` are what the broker actually spawns, and they record what
//! it did.

#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use support::{Broker, CliFixture};

/// How long to let the broker's startup readiness sweep finish before arming
/// the scripted failure, so the request under test is the one that meets it.
const SWEEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Where skarbiec itself looks for a cryptographic tool, so the stand-in can
/// delegate everything it is not scripted to answer to the real one.
fn real_program(program: &str) -> PathBuf {
    std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain(
            [
                "/opt/homebrew/bin",
                "/usr/local/MacGPG2/bin",
                "/home/linuxbrew/.linuxbrew/bin",
                "/usr/local/bin",
                "/usr/bin",
                "/bin",
            ]
            .into_iter()
            .map(PathBuf::from),
        )
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("this host has no {program} to test the vault against"))
}

fn install_script(directory: &Path, name: &str, body: &str) {
    let path = directory.join(name);
    fs::write(&path, body).expect("write scripted cryptographic tool");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .expect("make scripted cryptographic tool executable");
}

/// When a decryption is allowed to become the claimant.
///
/// `ALWAYS` is for the test that asks what a caller receives: its request is
/// the only decryption in flight, so it must be the one that fails.
const ALWAYS: &str = "true";

/// Only once some other decryption is already in flight. This is the state the
/// reported failure needed, and the broker supplies it by itself: the readiness
/// monitor opens every canary item on a timer, so request traffic is never
/// alone.
const ONLY_BESIDE_A_LIVE_DECRYPTION: &str =
    r#"[ "$(ls "$state/inflight" | wc -l | tr -d ' ')" -ge 2 ]"#;

/// The claimant's decryption: die the way a child whose `gpg-agent` went away
/// dies, reporting the socket it lost rather than a key problem.
const LOSE_SOCKET: &str = r#"  echo "claimed" >> "$state/sibling-seen"
  rm -f "$marker"
  echo "gpg: public key decryption failed: Broken pipe" >&2
  echo "gpg: decryption failed: Broken pipe" >&2
  exit 2"#;

/// Any other decryption: answer straight away.
const ANSWER_AT_ONCE: &str = ":";

/// Any other decryption: stay in flight a while, so a recovery triggered
/// beside it overlaps it unless something stops that from happening.
const STAY_IN_FLIGHT: &str = "sleep 1.5";

/// A scripted `gpg`/`gpgconf` pair on a directory of their own, plus the state
/// directory they record into.
struct ScriptedTools {
    bin: PathBuf,
    state: PathBuf,
}

impl ScriptedTools {
    fn install(fixture: &CliFixture, claim_when: &str, sibling: &str) -> Self {
        let bin = fixture.root.join("scripted-bin");
        let state = fixture.root.join("scripted-state");
        fs::create_dir_all(&bin).expect("create scripted tool directory");
        fs::create_dir_all(state.join("inflight")).expect("create scripted state directory");
        let gpg = real_program("gpg");

        // Only a vault decryption is scripted: it is the one invocation that
        // carries `--pinentry-mode`, which tells it apart from the `--decrypt`
        // a clearsignature verification also runs. Nothing is scripted until
        // the test arms it, so the broker's startup readiness sweep cannot
        // consume the one failure the test is about to observe.
        install_script(
            &bin,
            "gpg",
            &format!(
                r#"#!/bin/sh
state="{state}"
real="{gpg}"
decrypt=0
pinentry=0
for argument in "$@"; do
  [ "$argument" = "--decrypt" ] && decrypt=1
  [ "$argument" = "--pinentry-mode" ] && pinentry=1
done
if [ "$decrypt" -eq 0 ] || [ "$pinentry" -eq 0 ]; then
  exec "$real" "$@"
fi
marker="$state/inflight/$$"
: > "$marker"
if [ ! -f "$state/armed" ]; then
  echo "startup" >> "$state/unarmed"
elif {claim_when} && mkdir "$state/claimed" 2>/dev/null; then
{claimant}
fi
{sibling}
"$real" "$@"
status=$?
rm -f "$marker"
exit $status
"#,
                state = state.display(),
                gpg = gpg.display(),
                claim_when = claim_when,
                claimant = LOSE_SOCKET,
                sibling = sibling,
            ),
        );

        // `gpgconf` records whether a `gpg` child was in flight at the instant
        // it was asked to kill a daemon. That is the invariant under test: the
        // recovery may not kill a daemon somebody is still using.
        //
        // It records instead of delegating, deliberately. Whether killing a
        // live child's agent breaks that child is GnuPG's business, not this
        // product's, and actually killing it here makes every later assertion
        // a measurement of how long this host takes to relaunch a daemon --
        // which is how an earlier version of this test came to pass while
        // measuring nothing. What belongs to skarbiec is the order of its own
        // operations, so the order is what is recorded.
        install_script(
            &bin,
            "gpgconf",
            &format!(
                r#"#!/bin/sh
state="{state}"
if [ "$1" = "--kill" ]; then
  echo "$2" >> "$state/kills"
  if [ -n "$(ls -A "$state/inflight" 2>/dev/null)" ]; then
    echo "$2" >> "$state/overlap"
  fi
fi
exit 0
"#,
                state = state.display(),
            ),
        );

        Self { bin, state }
    }

    /// Start the broker with these tools on its `PATH`, let its readiness
    /// monitor's first sweep through, then arm the scripted failure.
    ///
    /// Arming only after a real decryption has been answered is what keeps the
    /// scripted failure for the traffic under test rather than handing it to
    /// the monitor's startup sweep. `readiness_seconds` then decides whether
    /// the monitor keeps decrypting: pinned far out it stays quiet, and at one
    /// second it is the concurrent reader the reported failure needed.
    fn serve_armed(&self, fixture: &CliFixture, readiness_seconds: &str) -> Broker {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let broker = fixture.serve_with_env(&[
            ("PATH", path.as_str()),
            ("SKARBIEC_GPG_CONCURRENCY", "2"),
            ("SKARBIEC_READINESS_INTERVAL_SECONDS", readiness_seconds),
        ]);
        self.await_first_sweep();
        fs::write(self.state.join("armed"), "").expect("arm the scripted failure");
        broker
    }

    fn in_flight(&self) -> usize {
        fs::read_dir(self.state.join("inflight"))
            .map(|entries| entries.count())
            .unwrap_or_default()
    }

    fn await_first_sweep(&self) {
        let deadline = Instant::now() + SWEEP_TIMEOUT;
        while Instant::now() < deadline {
            if !self.recorded("unarmed").is_empty() && self.in_flight() == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "the broker's readiness monitor never opened a canary item, so the \
             scripted failure cannot be armed for the traffic under test"
        );
    }

    /// Wait for the recovery a claimed failure triggers to have run, so the
    /// order it ran in can be read off. Bounded: a recovery that never happens
    /// is a finding, not a reason to hang.
    fn await_claim(&self) -> String {
        let deadline = Instant::now() + SWEEP_TIMEOUT;
        while Instant::now() < deadline {
            if !self.recorded("kills").is_empty() {
                // Let the rest of that recovery's kills land before reading.
                std::thread::sleep(Duration::from_millis(500));
                return format!("recovery killed: {}", self.recorded("kills").trim());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        "no recovery ran within the window".to_string()
    }

    fn recorded(&self, name: &str) -> String {
        fs::read_to_string(self.state.join(name)).unwrap_or_default()
    }
}

fn read_credential(broker: &Broker, item: &str) -> String {
    let body = format!(r#"{{"operation": "get", "item": "{item}"}}"#);
    let output = Command::new("curl")
        .args(["-s", "-X", "POST", &broker.url("/v1/operator/credential")])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", &body])
        .output()
        .expect("run curl");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_read_whose_gpg_lost_its_socket_is_recovered_instead_of_refused() {
    let fixture = CliFixture::new("crypto-retry");
    fixture.init("Recovery Test <recovery@test.local>");
    fixture.run(&["set", "publisher", "username=alice", "password=secret123"]);

    let tools = ScriptedTools::install(&fixture, ALWAYS, ANSWER_AT_ONCE);
    let broker = tools.serve_armed(&fixture, "3600");

    let response = read_credential(&broker, "publisher");

    assert!(
        !tools.recorded("kills").is_empty(),
        "a lost socket was never classified as worth recovering from, so no \
         daemon was recovered and no retry was attempted; the read answered: \
         {response}"
    );
    assert!(
        response.contains("alice"),
        "the read was refused instead of retried after daemon recovery: {response}"
    );
    assert!(
        !response.contains("public key decryption failed"),
        "the caller was handed the lost socket verbatim -- the detail the item \
         route reports as `503 infra_down` beside `item is stored but could \
         not be decrypted`: {response}"
    );
}

#[test]
fn daemon_recovery_never_kills_a_daemon_a_live_decryption_is_using() {
    let fixture = CliFixture::new("crypto-race");
    fixture.init("Recovery Race <race@test.local>");
    fixture.run(&["set", "publisher", "username=alice", "password=secret123"]);
    fixture.run(&["set", "broker-item", "username=bob", "password=secret456"]);

    let tools = ScriptedTools::install(&fixture, ONLY_BESIDE_A_LIVE_DECRYPTION, STAY_IN_FLIGHT);
    // One second, so the readiness monitor is decrypting while the read runs.
    // That concurrency is the product's own, not the test's: the monitor opens
    // every canary item on this timer whatever else the broker is serving.
    let broker = tools.serve_armed(&fixture, "1");

    let first = read_credential(&broker, "publisher");
    let second = tools.await_claim();

    assert!(
        !tools.recorded("sibling-seen").is_empty(),
        "no decryption ever failed beside a live one, so nothing here says \
         anything about a recovery running next to one; the read answered \
         {first}, and {second}"
    );
    assert!(
        !tools.recorded("kills").is_empty(),
        "no daemon recovery ran, so this proves nothing; the read answered \
         {first}, and {second}"
    );
    assert_eq!(
        tools.recorded("overlap"),
        "",
        "the recovery killed a daemon while another decryption was still in \
         flight, which is what takes a live `gpg` child's agent away and \
         reports `public key decryption failed: Broken pipe` to a caller that \
         asked for nothing but a credential; the read answered {first}, and \
         {second}"
    );
}
