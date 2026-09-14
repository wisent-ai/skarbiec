//! What the daemon repair does on a host whose process table stops answering.
//!
//! `recover-daemons` is the repair every credential read falls back to when
//! `gpg` reports a lost or wedged daemon. It asks GnuPG's own control surface,
//! `gpgconf --kill`, and then used to signal `keyboxd`, `gpg-agent` and
//! `scdaemon` with `pkill` regardless of what `gpgconf` had answered.
//!
//! On 2026-09-12 a loaded host stopped answering process-table queries: `ps`
//! and `pkill` both sat until they were killed. All six `pkill` calls hit the
//! product's own crypto deadline, and the repair reported `no gpg daemon
//! control surface answered (keyboxd -TERM: pkill timed out; ...)` even though
//! `gpgconf` had killed the daemons first. Every read behind it failed:
//! `skarbiec get` exited 1 and the signing lifecycle test that reads a
//! certificate out of the vault failed with it.
//!
//! So the behaviour under test is the sentence that refusal makes. A repair
//! may only refuse when no surface answered for any daemon; a surface that
//! answered is a repair. The host is staged the way that host behaved — a
//! `pkill` on `PATH` that never answers — and what ends the wait is the
//! product's own `SKARBIEC_CRYPTO_TIMEOUT_SECONDS`, not a deadline this test
//! invented. Nothing stands in for `gpgconf` or `gpg`: the real GnuPG control
//! surface is asked, against this fixture's own `GNUPGHOME`, so the daemons
//! that die are the fixture's and never the operator's.

#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;
use support::{stderr, CliFixture};

/// The product's deadline for one crypto child while this test runs. Long
/// enough for a healthy `gpgconf` to answer, short enough that six unanswered
/// signals would end the run in seconds.
const CRYPTO_TIMEOUT_SECONDS: &str = "5";

#[test]
fn repair_answers_when_gpgconf_kills_and_the_process_table_does_not() {
    let fixture = CliFixture::new("daemon-recovery");
    let unanswering = fixture.root.join("unanswering-bin");
    fs::create_dir_all(&unanswering).expect("create the directory holding this host's tools");
    let pkill = unanswering.join("pkill");
    fs::write(&pkill, "#!/bin/sh\nsleep 600\n").expect("write a pkill that never answers");
    fs::set_permissions(&pkill, fs::Permissions::from_mode(0o755))
        .expect("make the unanswering pkill executable");
    let path = format!(
        "{}:{}",
        unanswering.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = fixture.run_with_env(
        &[
            ("PATH", &path),
            ("SKARBIEC_CRYPTO_TIMEOUT_SECONDS", CRYPTO_TIMEOUT_SECONDS),
        ],
        &["recover-daemons"],
    );

    assert!(
        output.status.success(),
        "the repair refused while gpgconf was answering: {}",
        stderr(&output)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("recover-daemons prints one JSON object");
    assert_eq!(
        report["recovered"],
        Value::Bool(true),
        "the receipt reports no repair although gpgconf killed the daemons: {report}"
    );
    assert_eq!(
        report["detail"],
        Value::Null,
        "a repair that happened still carries a failure detail: {report}"
    );
}
