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
fn operator_http_get_returns_all_fields_in_value_format() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");

    // Create item with multiple fields
    fixture.run(&[
        "set",
        "login",
        "username=alice",
        "password=secret",
        "totp_secret=SEED123",
    ]);
    let broker = fixture.serve();

    // Get the full item
    let response = request_credential(&broker, "get", "login", "");

    // Verify it contains all fields
    assert!(response.contains("alice"), "should contain username");
    assert!(response.contains("secret"), "should contain password");
    assert!(response.contains("SEED123"), "should contain totp_secret");
    assert!(
        response.contains("value"),
        "response should have value wrapper"
    );
}
