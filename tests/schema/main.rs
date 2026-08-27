#[path = "../support/mod.rs"]
mod support;

use support::{assert_success, stderr, CliFixture};

#[test]
fn set_json_persists_canonical_items_and_refuses_invalid_payloads() {
    let fixture = CliFixture::new("schema");
    fixture.init("Skarbiec schema test <skarbiec-schema-test@example.invalid>");

    let note = r#"{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"stored through the real CLI"},"context":{}}"#;
    let stored = fixture.run_with_stdin(&["set-json", "release-note", "--type", "note"], note);
    assert_success("store canonical note", &stored);
    let read = fixture.run(&["get", "release-note", "--field", "value"]);
    assert_success("read canonical note", &read);
    assert_eq!(
        String::from_utf8_lossy(&read.stdout),
        "stored through the real CLI\n"
    );

    let missing_value = r#"{"schema":"skarbiec.item.v2","kind":"note","fields":{"title":"not canonical"},"context":{}}"#;
    let refused = fixture.run_with_stdin(
        &["set-json", "missing-note", "--type", "note"],
        missing_value,
    );
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        stderr(&refused),
        "Error: field title is not allowed for note"
    );
    let absent = fixture.run(&["get", "missing-note", "--field", "value"]);
    assert_eq!(absent.status.code(), Some(1));
    assert_eq!(stderr(&absent), "Error: no item: missing-note");

    let non_string =
        r#"{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":true},"context":{}}"#;
    let refused = fixture.run_with_stdin(&["set-json", "typed-note", "--type", "note"], non_string);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        stderr(&refused),
        "Error: note field value has an invalid value type"
    );
}
