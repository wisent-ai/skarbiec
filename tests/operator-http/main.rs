#[path = "../support/mod.rs"]
mod support;

use std::process::Command;
use support::{Broker, CliFixture};

/// Make HTTP request to the fixture's own broker and return response text.
///
/// The broker is addressed through the guard that started it, so the port is
/// the one this fixture reserved. Naming a fixed port here would send the
/// request to whatever already holds it - on a machine running the product,
/// the service that holds the operator's real vault.
fn request_credential(broker: &Broker, operation: &str, item: &str, extra: &str) -> String {
    let mut body = format!(r#"{{"operation": "{}", "item": "{}""#, operation, item);
    if !extra.is_empty() {
        body.push(',');
        body.push_str(extra);
    }
    body.push('}');

    let url = broker.url("/v1/operator/credential");
    let output = Command::new("curl")
        .args(["-s", "-X", "POST", &url])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", &body])
        .output()
        .expect("run curl");

    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn operator_http_get_returns_full_item_and_fields() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");

    // Add test item
    fixture.run(&[
        "set",
        "test-item",
        "username=alice",
        "password=secret123",
        "totp_secret=SEED",
    ]);

    // Start broker on this fixture's port; the guard stops it on drop
    let broker = fixture.serve();

    // Test: GET returns full item
    let response = request_credential(&broker, "get", "test-item", "");
    assert!(
        response.contains("\"value\""),
        "response should have value field"
    );
    assert!(
        response.contains("alice"),
        "response should contain username"
    );
    assert!(
        response.contains("secret123"),
        "response should contain password"
    );

    // Test: GET specific field
    let response = request_credential(&broker, "get", "test-item", r#""field": "username""#);
    assert!(response.contains("alice"), "field value should be returned");
}

#[test]
fn operator_http_set_preserves_existing_fields() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");

    fixture.run(&[
        "set",
        "cred",
        "username=bob",
        "password=pass",
        "totp_secret=KEY",
    ]);
    let broker = fixture.serve();

    // SET with new password
    let body = r#""username": "bob", "password": "newpass", "totp_secret": "KEY""#;
    let _response = request_credential(&broker, "set", "cred", body);

    // Verify all fields survived
    let response = request_credential(&broker, "get", "cred", "");
    assert!(response.contains("bob"), "username should be preserved");
    assert!(response.contains("newpass"), "password should be updated");
    assert!(response.contains("KEY"), "totp_secret should be preserved");
}

#[test]
fn operator_http_totp_reports_seed_status() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");

    fixture.run(&[
        "set",
        "with-totp",
        "username=user",
        "password=pass",
        "totp_secret=SEED",
    ]);
    fixture.run(&["set", "no-totp", "username=user", "password=pass"]);
    let broker = fixture.serve();

    // With seed
    let response = request_credential(&broker, "totp", "with-totp", "");
    assert!(
        response.contains("has_seed"),
        "should report has_seed field"
    );

    // Without seed
    let response = request_credential(&broker, "totp", "no-totp", "");
    assert!(
        response.contains("has_seed"),
        "should report has_seed field even when false"
    );
}

#[test]
fn operator_http_unknown_operation_refused_with_contract_message() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");
    fixture.run(&["set", "item", "username=test", "password=test"]);
    let broker = fixture.serve();

    let response = request_credential(&broker, "unknown", "item", "");
    let expected_message = "operator credential operation must be one of status, acquire, rotate, resume, get, set, set-json, totp";
    assert!(
        response.contains(expected_message),
        "error message should contain full contract: {}",
        response
    );
}

#[test]
fn operator_http_set_json_replaces_the_whole_document() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");

    // Seed an item with three fields
    fixture.run(&[
        "set",
        "login",
        "username=alice",
        "password=secret456",
        "totp_secret=SEED123",
    ]);
    let broker = fixture.serve();

    // Phase 1: set-json writes a field the item did not have.
    //
    // This is what the desktop client does on every save: BackendClient
    // .updateCredentialFields reads the whole item, merges one field the item
    // has never carried, and writes the whole document back. Replacement alone
    // does not prove that path - a broker that only ever accepted fields it had
    // already stored would pass the phase below and still refuse the save the
    // client actually performs. So the seeded item has three fields and this
    // payload has four.
    //
    // The new field is recovery_codes rather than a free-form name because the
    // broker refuses anything else on a login: allowed_fields is exactly
    // username, password, totp_secret, recovery_codes (src/core/schema.rs), and
    // a `notes` member is answered with
    // `{"error":"field notes is not allowed for login"}`. recovery_codes is a
    // field this item did not have, which is the property under test.
    let payload_json = r#"{"schema":"skarbiec.item.v2","kind":"login","context":{},"fields":{"username":"alice","password":"newpassword","totp_secret":"SEED123","recovery_codes":"aaa-bbb-ccc"}}"#;
    let body = format!(
        r#"{{"operation":"set-json","item":"login","payload":{}}}"#,
        payload_json
    );
    let output = Command::new("curl")
        .args(["-s", "-X", "POST", &broker.url("/v1/operator/credential")])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", &body])
        .output()
        .expect("run curl");
    let written = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        written.contains("\"ok\":true"),
        "set-json must accept a document carrying a field the item did not have, answered: {written}"
    );

    // All four fields are present, each with its own value. Reading the item
    // back is the assertion: the answer above only says the write was accepted.
    let response = request_credential(&broker, "get", "login", "");
    assert!(
        response.contains(r#"\"username\":\"alice\""#),
        "username should be present with its value, got: {response}"
    );
    assert!(
        response.contains(r#"\"password\":\"newpassword\""#),
        "password should be present with its updated value, got: {response}"
    );
    assert!(
        response.contains(r#"\"totp_secret\":\"SEED123\""#),
        "totp_secret should be present with its value, got: {response}"
    );
    assert!(
        response.contains(r#"\"recovery_codes\":\"aaa-bbb-ccc\""#),
        "recovery_codes was not in the seeded item; set-json must have written it, got: {response}"
    );

    // Phase 2: set-json replaces the entire document, it does not merge. The client is
    // responsible for reading the full item, merging updates, and writing back
    // the complete document. If the broker protected against incomplete writes,
    // clients could not implement conditional fields or schema evolution.
    let payload_json = r#"{"schema":"skarbiec.item.v2","kind":"login","context":{},"fields":{"username":"alice","totp_secret":"SEED123"}}"#;
    let body = format!(
        r#"{{"operation":"set-json","item":"login","payload":{}}}"#,
        payload_json
    );
    let _ = Command::new("curl")
        .args(["-s", "-X", "POST", &broker.url("/v1/operator/credential")])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", &body])
        .output()
        .expect("run curl");

    // Verify username and totp_secret survive, and that BOTH fields the
    // previous document carried and this one omits are gone.
    //
    // The two negatives name the values phase 1 actually wrote. Asserting the
    // seeded "secret456" here would pass without the broker doing anything:
    // phase 1 already replaced it, so its absence says nothing about this
    // write. "newpassword" and "aaa-bbb-ccc" were present immediately before
    // this request, so only the replacement can have removed them.
    let response = request_credential(&broker, "get", "login", "");
    assert!(
        response.contains(r#"\"username\":\"alice\""#),
        "username should still be present, got: {response}"
    );
    assert!(
        response.contains(r#"\"totp_secret\":\"SEED123\""#),
        "totp_secret should still be present, got: {response}"
    );
    assert!(
        !response.contains("newpassword"),
        "the password phase 1 wrote should be gone - set-json replaces, does not merge, got: {response}"
    );
    assert!(
        !response.contains("aaa-bbb-ccc"),
        "the recovery_codes phase 1 wrote should be gone - set-json replaces, does not merge, got: {response}"
    );
}
