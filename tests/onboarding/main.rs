#[path = "../support/mod.rs"]
mod support;

use std::fs;

use serde_json::Value;
use support::{assert_success, CliFixture};

#[test]
fn onboarding_reaches_first_success_only_after_the_real_note_and_audit_exist() {
    let fixture = CliFixture::new("onboarding");
    fixture.init("Skarbiec onboarding test <skarbiec-onboarding-test@example.invalid>");

    let completed = fixture.run(&["onboarding", "--yes", "--reset"]);
    assert_success("complete real onboarding journey", &completed);
    let stdout = String::from_utf8_lossy(&completed.stdout);
    assert!(stdout.contains("\"status\": \"completed\""));
    assert!(stdout.contains("\"first_success\": \"audit_entry_observed\""));

    let state_path = fixture.root.join(".local/share/skarbiec/onboarding.json");
    let state: Value =
        serde_json::from_slice(&fs::read(&state_path).expect("read persisted onboarding state"))
            .expect("parse persisted onboarding state");
    assert_eq!(state["status"], "completed");

    let listed = fixture.run(&["list"]);
    assert_success("list the onboarding note", &listed);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("onboarding-safe-note-"),
        "the completed journey did not persist its note"
    );

    let audit =
        fs::read_to_string(fixture.root.join("audit.jsonl")).expect("read persisted audit journal");
    assert!(audit.contains("onboarding-safe-note-"));
    assert!(!audit.contains("This is a non-secret onboarding proof"));
}
