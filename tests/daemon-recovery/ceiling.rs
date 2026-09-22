//! What the running service does to a GnuPG daemon that holds more than its
//! memory ceiling, and what `doctor` and `recover-daemons` say about it.
//!
//! On charless-mac-mini `keyboxd` answered one vault's reads for twelve days
//! and grew to 15 GiB while `ps` reported 327 MiB, because the rest was
//! compressed or swapped. The host refused placement on memory pressure and
//! nothing named the daemon, because the only repair (`recover-daemons`) ran
//! after a failed read, never on a healthy one, and Stado's memory policy
//! asked Skarbiec and got `ok`.
//!
//! The flow here is the real one. A fixture keyring gets its own daemons the
//! way every keyring does — `gpg` starts them on the first operation — and a
//! real broker is started with the ceiling set to one mebibyte, which every
//! live daemon exceeds. The daemon's pid is read through GnuPG's own control
//! surface before and after, the broker's journal is asked through
//! `audit-query` for the `daemon-recycle` row, and a read is made afterwards
//! to prove the vault still opens with fresh daemons. `doctor` is then run
//! against the same keyring under the same ceiling and under the default one,
//! and `recover-daemons` is asked for its receipt. Nothing stands in for
//! `gpg` or its daemons, and nothing here has a clock: the wait for the
//! broker's pass ends when the journal holds the row or the broker has died.

use std::process::Command;

use serde_json::Value;

use crate::support::{assert_success, stderr, Broker, CliFixture};

const ITEM: &str = "ceiling-item";
const SECRET: &str = "sekret-456";
/// One mebibyte, which any live GnuPG daemon exceeds: the pass under test is
/// the one that finds a daemon over the ceiling.
const CEILING_EVERY_DAEMON_EXCEEDS_MB: &str = "1";
const CEILING_EVERY_DAEMON_EXCEEDS_BYTES: u64 = 1024 * 1024;
/// The tightest readiness interval the service accepts, so the pass runs as
/// soon as the broker is up rather than once a minute.
const READINESS_INTERVAL_SECONDS: &str = "1";
/// The ceiling the product uses when nothing sets one, as the receipt reports
/// it in bytes.
const DEFAULT_CEILING_BYTES: u64 = 1024 * 1024 * 1024;

/// The pid of one daemon serving this fixture's keyring, from GnuPG's own
/// control surface with autostart off, exactly as the product reads it. A
/// daemon that is not running answers no data line.
fn daemon_pid(fixture: &CliFixture, keyboxd: bool) -> Option<u32> {
    let mut command = Command::new("gpg-connect-agent");
    command.env("GNUPGHOME", &fixture.gnupg).arg("--no-autostart");
    if keyboxd {
        command.arg("--keyboxd");
    }
    let output = command
        .args(["GETINFO pid", "/bye"])
        .output()
        .expect("ask GnuPG's control surface for a daemon pid");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("D "))
        .find_map(|data| data.trim().parse().ok())
}

/// The `daemon-recycle` rows the broker journalled, read through the product.
fn recycle_rows(fixture: &CliFixture) -> Vec<Value> {
    let output = fixture.run(&["audit-query", "--op", "daemon-recycle"]);
    assert_success("query the journal for daemon recycles", &output);
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("audit-query prints one JSON object");
    report["entries"].as_array().cloned().unwrap_or_default()
}

/// The first recycle row the broker journals. Each query is a real product
/// run, which is what paces this loop; a broker that exits first is the
/// failure, reported with its exit status.
fn await_recycle(fixture: &CliFixture, broker: &mut Broker) -> Vec<Value> {
    loop {
        let rows = recycle_rows(fixture);
        if !rows.is_empty() {
            return rows;
        }
        if let Some(status) = broker.exited() {
            panic!("the broker exited ({status}) before journalling a daemon-recycle");
        }
    }
}

fn doctor_check(fixture: &CliFixture, env: &[(&str, &str)], name: &str) -> Value {
    let output = fixture.run_with_env(env, &["doctor"]);
    assert_success("run doctor", &output);
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("doctor prints one JSON object");
    report["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["check"] == name))
        .cloned()
        .unwrap_or_else(|| panic!("doctor reports no `{name}` check: {report}"))
}

#[test]
fn the_running_service_replaces_a_daemon_over_its_memory_ceiling() {
    let fixture = CliFixture::new("daemon-ceiling");
    fixture.init("Skarbiec ceiling test <skarbiec-ceiling-test@example.invalid>");
    let field = format!("api_key={SECRET}");
    assert_success(
        "seed one readable item",
        &fixture.run(&["set", ITEM, "--type", "api-key", &field]),
    );
    let agent_before =
        daemon_pid(&fixture, false).expect("init left this keyring's gpg-agent running");
    let keyboxd_before = daemon_pid(&fixture, true);

    let mut broker = fixture.serve_with_env(&[
        (
            "SKARBIEC_GPG_DAEMON_MEMORY_LIMIT_MB",
            CEILING_EVERY_DAEMON_EXCEEDS_MB,
        ),
        ("SKARBIEC_READINESS_INTERVAL_SECONDS", READINESS_INTERVAL_SECONDS),
    ]);
    let rows = await_recycle(&fixture, &mut broker);
    let first = &rows[0];
    let over_limit = first["extra"]["over_limit"]
        .as_array()
        .unwrap_or_else(|| panic!("the recycle row names no daemons: {first}"));
    assert!(
        over_limit.iter().any(|entry| entry
            .as_str()
            .is_some_and(|text| text.contains(&format!("pid {agent_before}")))),
        "the recycle row does not name the gpg-agent that was over the ceiling (pid {agent_before}): {first}"
    );
    assert_eq!(
        first["extra"]["limit_bytes"].as_u64(),
        Some(CEILING_EVERY_DAEMON_EXCEEDS_BYTES),
        "the recycle row does not carry the ceiling it applied: {first}"
    );

    // The broker would replace the fresh daemons again on its next pass,
    // since the ceiling is still one mebibyte; the read below is about the
    // vault opening with the daemons the recycle left, not about racing it.
    drop(broker);
    let read = fixture.run(&["get", ITEM]);
    assert!(
        read.status.success(),
        "the vault no longer opens after the daemons were replaced: {}",
        stderr(&read)
    );
    assert_ne!(
        daemon_pid(&fixture, false),
        Some(agent_before),
        "the gpg-agent that stood over the ceiling is still the one serving this keyring"
    );
    if let Some(before) = keyboxd_before {
        assert_ne!(
            daemon_pid(&fixture, true),
            Some(before),
            "the keyboxd that stood over the ceiling is still the one serving this keyring"
        );
    }
}

#[test]
fn doctor_names_the_daemon_over_the_ceiling_and_recover_daemons_reports_what_it_held() {
    let fixture = CliFixture::new("daemon-doctor");
    fixture.init("Skarbiec doctor test <skarbiec-doctor-test@example.invalid>");
    let agent = daemon_pid(&fixture, false).expect("init left this keyring's gpg-agent running");

    let healthy = doctor_check(&fixture, &[], "gpg_daemons");
    assert_eq!(healthy["status"], "pass", "under the default ceiling: {healthy}");
    let detail = healthy["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("gpg-agent ") && detail.contains(&format!("(pid {agent})")),
        "a passing check does not name the running daemon and its pid: {healthy}"
    );

    let over = doctor_check(
        &fixture,
        &[(
            "SKARBIEC_GPG_DAEMON_MEMORY_LIMIT_MB",
            CEILING_EVERY_DAEMON_EXCEEDS_MB,
        )],
        "gpg_daemons",
    );
    assert_eq!(over["status"], "fail", "under a 1 MiB ceiling: {over}");
    let detail = over["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("over the 1.0 MiB ceiling")
            && detail.contains(&format!("(pid {agent})"))
            && detail.contains("recover-daemons"),
        "a failing check does not name the ceiling, the daemon and the repair: {over}"
    );

    let output = fixture.run(&["recover-daemons"]);
    assert_success("replace the daemons on demand", &output);
    let receipt: Value =
        serde_json::from_slice(&output.stdout).expect("recover-daemons prints one JSON object");
    assert_eq!(receipt["recovered"], Value::Bool(true), "{receipt}");
    assert_eq!(
        receipt["limit_bytes"].as_u64(),
        Some(DEFAULT_CEILING_BYTES),
        "{receipt}"
    );
    let before = receipt["before"]
        .as_array()
        .unwrap_or_else(|| panic!("the receipt carries no `before` footprints: {receipt}"));
    let agent_row = before
        .iter()
        .find(|row| row["daemon"] == "gpg-agent")
        .unwrap_or_else(|| panic!("the receipt does not say what gpg-agent held: {receipt}"));
    assert_eq!(agent_row["pid"].as_u64(), Some(u64::from(agent)), "{receipt}");
    assert!(
        agent_row["bytes"].as_u64().is_some_and(|bytes| bytes > 0),
        "the receipt reports no footprint for the daemon it replaced: {receipt}"
    );
    assert_ne!(
        daemon_pid(&fixture, false),
        Some(agent),
        "recover-daemons left the same gpg-agent serving this keyring"
    );
}
