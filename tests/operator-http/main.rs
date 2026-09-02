#[path = "../support/mod.rs"]
mod support;

use support::{assert_success, CliFixture};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Start the broker against the vault and return its PID
fn start_broker(fixture: &CliFixture) -> u32 {
    let pid = Command::new(env!("CARGO_BIN_EXE_skarbiec"))
        .arg("serve")
        .env("SKARBIEC_VAULT_FILE", &fixture.vault)
        .env("GNUPGHOME", &fixture.gnupg)
        .env("HOME", &fixture.root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start broker")
        .id();
    
    // Wait for broker to be ready
    thread::sleep(Duration::from_millis(1500));
    pid
}

/// Make HTTP request to broker and return response text
fn request_credential(operation: &str, item: &str, extra: &str) -> String {
    let mut body = format!(r#"{{"operation": "{}", "item": "{}""#, operation, item);
    if !extra.is_empty() {
        body.push(',');
        body.push_str(extra);
    }
    body.push('}');

    let output = Command::new("curl")
        .args(&["-s", "-X", "POST", "http://127.0.0.1:8787/v1/operator/credential"])
        .args(&["-H", "Content-Type: application/json"])
        .args(&["-d", &body])
        .output()
        .expect("run curl");
    
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn operator_http_get_returns_full_item_and_fields() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");
    
    // Add test item
    fixture.run(&["set", "test-item", "username=alice", "password=secret123", "totp_secret=SEED"]);
    
    // Start broker
    let broker_pid = start_broker(&fixture);
    
    // Test: GET returns full item
    let response = request_credential("get", "test-item", "");
    assert!(response.contains("\"value\""), "response should have value field");
    assert!(response.contains("alice"), "response should contain username");
    assert!(response.contains("secret123"), "response should contain password");
    
    // Test: GET specific field
    let response = request_credential("get", "test-item", r#""field": "username""#);
    assert!(response.contains("alice"), "field value should be returned");
    
    // Cleanup
    std::process::Command::new("kill")
        .arg(broker_pid.to_string())
        .output()
        .ok();
}

#[test]
fn operator_http_set_preserves_existing_fields() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");
    
    fixture.run(&["set", "cred", "username=bob", "password=pass", "totp_secret=KEY"]);
    let broker_pid = start_broker(&fixture);
    
    // SET with new password
    let body = r#""username": "bob", "password": "newpass", "totp_secret": "KEY""#;
    let _response = request_credential("set", "cred", body);
    
    // Verify all fields survived
    let response = request_credential("get", "cred", "");
    assert!(response.contains("bob"), "username should be preserved");
    assert!(response.contains("newpass"), "password should be updated");
    assert!(response.contains("KEY"), "totp_secret should be preserved");
    
    std::process::Command::new("kill")
        .arg(broker_pid.to_string())
        .output()
        .ok();
}

#[test]
fn operator_http_totp_reports_seed_status() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");
    
    fixture.run(&["set", "with-totp", "username=user", "password=pass", "totp_secret=SEED"]);
    fixture.run(&["set", "no-totp", "username=user", "password=pass"]);
    let broker_pid = start_broker(&fixture);
    
    // With seed
    let response = request_credential("totp", "with-totp", "");
    assert!(response.contains("has_seed"), "should report has_seed field");
    
    // Without seed
    let response = request_credential("totp", "no-totp", "");
    assert!(response.contains("has_seed"), "should report has_seed field even when false");
    
    std::process::Command::new("kill")
        .arg(broker_pid.to_string())
        .output()
        .ok();
}

#[test]
fn operator_http_unknown_operation_refused_with_contract_message() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");
    fixture.run(&["set", "item", "username=test", "password=test"]);
    let broker_pid = start_broker(&fixture);
    
    let response = request_credential("unknown", "item", "");
    assert!(response.contains("error"), "should return error");
    assert!(response.contains("status"), "error should name status operation");
    assert!(response.contains("acquire"), "error should name acquire operation");
    assert!(response.contains("rotate"), "error should name rotate operation");
    assert!(response.contains("resume"), "error should name resume operation");
    assert!(response.contains("get"), "error should name get operation");
    assert!(response.contains("set"), "error should name set operation");
    assert!(response.contains("set-json"), "error should name set-json operation");
    assert!(response.contains("totp"), "error should name totp operation");
    
    std::process::Command::new("kill")
        .arg(broker_pid.to_string())
        .output()
        .ok();
}
