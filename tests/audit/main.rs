//! The audit journal read through the real CLI, including a journal that has
//! one line nothing can parse.

#[path = "../support/mod.rs"]
mod support;

use serde_json::Value;
use std::fs;

use support::{assert_success, CliFixture};

/// One unparseable line used to end the whole read: `verify-chain` refused a
/// journal of two million entries and named neither the line nor the reason,
/// while the report's own contract says neither scan stops at the first
/// fault. The report has to name the line and keep checking the rest.
#[test]
fn one_malformed_line_is_reported_and_the_rest_of_the_journal_is_still_checked() {
    let fixture = CliFixture::new("audit");
    fixture.init("Skarbiec audit test <skarbiec-audit-test@example.invalid>");
    let set = fixture.run(&["set", "audit-probe", "--type", "note", "value=recorded"]);
    assert_success("seed one journalled write", &set);
    let journal = fixture.root.join("audit.jsonl");
    let body = fs::read_to_string(&journal).expect("the CLI wrote an audit journal");
    let good = body.lines().count();
    assert!(good > 0, "the journal is empty: {body}");
    fs::write(&journal, format!("{body}{{\"at\": broken}}\n")).expect("append a broken line");

    let out = fixture.run(&["verify-chain"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "verify-chain answered nothing readable ({error}): {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });

    assert_eq!(report["entries"], good, "{report}");
    assert_eq!(report["malformed"], 1, "{report}");
    let malformed: Vec<&Value> = report["faults"]
        .as_array()
        .expect("faults is an array")
        .iter()
        .filter(|fault| fault["fault"] == "malformed")
        .collect();
    assert_eq!(malformed.len(), 1, "{report}");
    assert_eq!(
        malformed[0]["line"],
        good.saturating_add(1),
        "the report names the line that could not be parsed: {report}"
    );
    assert!(
        malformed[0]["detail"]
            .as_str()
            .is_some_and(|detail| !detail.is_empty()),
        "the report says why the line could not be parsed: {report}"
    );
    assert_eq!(report["intact"], false, "{report}");
    assert_eq!(
        report["digests_verified"], report["digests_checked"],
        "the well-formed entries are still verified: {report}"
    );
}
