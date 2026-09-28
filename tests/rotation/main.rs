#[path = "../support/mod.rs"]
mod support;

use serde_json::{json, Value};
use std::fs;
use support::{assert_success, stderr, CliFixture};

const OWNER: &str = "Skarbiec rotation owner <skarbiec-rotation-owner@example.invalid>";
const PLAIN: &str = "plain-api-key";
const USAGE: &str = "usage: rotation set <item-id> --every-days <N> --provider <provider> --consumer <consumer> [--purpose <text>] | rotation list | rotation remove <item-id> | rotation run [--item <item-id>]";

fn fixture() -> CliFixture {
    let fixture = CliFixture::new("rotation");
    fixture.init(OWNER);
    assert_success(
        "seed one owner-controlled item",
        &fixture.run(&["set", PLAIN, "--type", "api-key", "api_key=plain-value"]),
    );
    fixture
}

fn answer(fixture: &CliFixture, args: &[&str]) -> Value {
    let output = fixture.run(args);
    assert_success(&format!("{args:?}"), &output);
    serde_json::from_slice(&output.stdout).expect("a JSON answer")
}

#[test]
fn an_empty_schedule_lists_nothing_runs_here_and_starts_nothing() {
    let fixture = fixture();
    assert_eq!(
        answer(&fixture, &["rotation", "list"]),
        json!({"policies": [], "runs_here": true})
    );
    let run = answer(&fixture, &["rotation", "run"]);
    assert_eq!(run["ok"], true);
    assert_eq!(run["ran"], json!([]));
    assert_eq!(run["failed"].as_u64(), Some(u64::MIN));
    let help = answer(&fixture, &["rotation"]);
    assert_eq!(
        help["commands"],
        json!(["rotation set", "rotation list", "rotation remove", "rotation run"])
    );
    let root = answer(&fixture, &["help"]);
    assert!(root["groups"]
        .as_array()
        .expect("groups")
        .contains(&json!("rotation")));
    assert!(root["commands"]
        .as_array()
        .expect("commands")
        .contains(&json!("remove-user")));
}

#[test]
fn rotation_set_refuses_what_it_cannot_rotate_without_writing_a_policy() {
    let fixture = fixture();
    let untouched = fs::read(&fixture.vault).expect("read the vault");
    let owned = |args: &[&str]| -> Vec<String> { args.iter().map(|a| a.to_string()).collect() };
    let with = |item: &str, days: &str| {
        owned(&[
            "rotation",
            "set",
            item,
            "--every-days",
            days,
            "--provider",
            "openai",
            "--consumer",
            "rotation-test",
        ])
    };
    let refusals: Vec<(Vec<String>, String)> = vec![
        (with("absent-item", "30"), "no live item: absent-item".to_string()),
        (
            with(PLAIN, "30"),
            format!("{PLAIN} is unmanaged, not a Weles-managed credential; only a managed credential can be rotated on a schedule. Bring it under management with credential adopt or credential acquire first"),
        ),
        (
            with(PLAIN, "0"),
            "--every-days must be a whole number of days above zero".to_string(),
        ),
        (
            owned(&["rotation", "set", PLAIN, "--every-days", "30", "--consumer", "c"]),
            "--provider is required".to_string(),
        ),
        (
            owned(&["rotation", "set", PLAIN, "--every-days", "30", "--provider", "p"]),
            "--consumer is required".to_string(),
        ),
        (
            owned(&[
                "rotation", "set", PLAIN, "--every-days", "30", "--provider", "p", "--consumer",
                "c", "--bogus", "x",
            ]),
            USAGE.to_string(),
        ),
        (
            owned(&["rotation", "remove", PLAIN]),
            format!("no rotation policy for {PLAIN}"),
        ),
        (
            owned(&["rotation", "bogus"]),
            format!("unknown rotation command: bogus; {USAGE}"),
        ),
    ];
    for (args, sentence) in refusals {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let refused = fixture.run(&borrowed);
        assert_eq!(refused.status.code(), Some(1), "{args:?} must be refused");
        assert_eq!(stderr(&refused), format!("Error: {sentence}"), "{args:?}");
    }
    assert_eq!(
        fs::read(&fixture.vault).expect("read the vault"),
        untouched,
        "a refused rotation command leaves the vault file unchanged"
    );
    assert_eq!(
        answer(&fixture, &["rotation", "list"])["policies"],
        json!([])
    );
}
