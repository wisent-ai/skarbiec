#[path = "../support/mod.rs"]
mod support;

use support::CliFixture;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Guard that kills the broker process on drop, ensuring cleanup even on panic
struct BrokerGuard {
    pid: u32,
}

impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .arg(self.pid.to_string())
            .output();
    }
}

/// Start the broker against the vault on a specific port and return a guard
fn start_broker(fixture: &CliFixture, port: u16) -> BrokerGuard {
    let pid = Command::new(env!("CARGO_BIN_EXE_skarbiec"))
        .arg("serve")
        .arg("--port")
        .arg(port.to_string())
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
    BrokerGuard { pid }
}

/// Make HTTP request to broker on a specific port and return response text
fn request_credential(port: u16, operation: &str, item: &str, extra: &str) -> String {
    let mut body = format!(r#"{{"operation": "{}", "item": "{}""#, operation, item);
    if !extra.is_empty() {
        body.push(',');
        body.push_str(extra);
    }
    body.push('}');
    
    let url = format!("http://127.0.0.1:{}/v1/operator/credential", port);
    let output = Command::new("curl")
        .args(&["-s", "-X", "POST", &url])
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
    
    // Start broker on unique port, guard ensures cleanup on drop
    let _broker = start_broker(&fixture, 8788);
    
    // Test: GET returns full item
    let response = request_credential(8788, "get", "test-item", "");
    assert!(response.contains("\"value\""), "response should have value field");
    assert!(response.contains("alice"), "response should contain username");
    assert!(response.contains("secret123"), "response should contain password");
    
    // Test: GET specific field
    let response = request_credential(8788, "get", "test-item", r#""field": "username""#);
    assert!(response.contains("alice"), "field value should be returned");
}

#[test]
fn operator_http_set_preserves_existing_fields() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");
    
    fixture.run(&["set", "cred", "username=bob", "password=pass", "totp_secret=KEY"]);
    let _broker = start_broker(&fixture, 8789);
    
    // SET with new password
    let body = r#""username": "bob", "password": "newpass", "totp_secret": "KEY""#;
    let _response = request_credential(8789, "set", "cred", body);
    
    // Verify all fields survived
    let response = request_credential(8789, "get", "cred", "");
    assert!(response.contains("bob"), "username should be preserved");
    assert!(response.contains("newpass"), "password should be updated");
    assert!(response.contains("KEY"), "totp_secret should be preserved");
}

#[test]
fn operator_http_totp_reports_seed_status() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");
    
    fixture.run(&["set", "with-totp", "username=user", "password=pass", "totp_secret=SEED"]);
    fixture.run(&["set", "no-totp", "username=user", "password=pass"]);
    let _broker = start_broker(&fixture, 8790);
    
    // With seed
    let response = request_credential(8790, "totp", "with-totp", "");

    assert!(response.contains("has_seed"), "should report has_seed field");
    
    // Without seed
    let response = request_credential(8790, "totp", "no-totp", "");
    assert!(response.contains("has_seed"), "should report has_seed field even when false");
}

#[test]
fn operator_http_unknown_operation_refused_with_contract_message() {
    let fixture = CliFixture::new("operator-http");
    fixture.init("HTTP Test <http@test.local>");
    fixture.run(&["set", "item", "username=test", "password=test"]);
    let _broker = start_broker(&fixture, 8791);
    
    let response = request_credential(8791, "unknown", "item", "");
    let expected_message = "operator credential operation must be one of status, acquire, rotate, resume, get, set, set-json, totp";
    assert!(
        response.contains(expected_message),
        "error message should contain full contract: {}",
        response
    );
}
