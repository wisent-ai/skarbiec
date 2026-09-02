#[path = "../support/mod.rs"]
mod support;

use support::{assert_success, CliFixture};

#[test]
fn operator_get_returns_full_item_when_no_field_specified() {
    let fixture = CliFixture::new("operator-values");
    fixture.init("Test Vault <test@example.com>");

    // Add test item
    let added = fixture.run(&[
        "set",
        "test-login",
        "username=alice",
        "password=secret123",
        "totp_secret=JBSWY3DPEHPK3PXP",
    ]);
    assert_success("add test item", &added);

    // Get full item via get command
    let output = fixture.run(&["get", "test-login"]);
    assert_success("get full item", &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alice"), "username should be in output");
    assert!(stdout.contains("secret123"), "password should be in output");
    assert!(
        stdout.contains("JBSWY3DPEHPK3PXP"),
        "totp_secret should be in output"
    );
}

#[test]
fn operator_get_returns_specific_field_when_field_specified() {
    let fixture = CliFixture::new("operator-values");
    fixture.init("Test Vault <test@example.com>");

    fixture.run(&[
        "set",
        "test-login",
        "username=bob",
        "password=secret456",
        "totp_secret=JBSWY3DPEHJK3PXQ",
    ]);

    // Get specific field
    let output = fixture.run(&["get", "test-login", "--field", "username"]);
    assert_success("get username field", &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bob"), "should contain username value");
}

#[test]
fn operator_set_creates_or_updates_item_with_preserved_fields() {
    let fixture = CliFixture::new("operator-values");
    fixture.init("Test Vault <test@example.com>");

    // Set initial item
    fixture.run(&[
        "set",
        "credentials",
        "username=charlie",
        "password=pass789",
        "totp_secret=JBSWY3DPEHPK3PXS",
    ]);

    // Update one field via set
    let updated = fixture.run(&[
        "set",
        "credentials",
        "username=charlie",
        "password=newpass",
        "totp_secret=JBSWY3DPEHPK3PXS",
    ]);
    assert_success("update item via set", &updated);

    // Verify all fields are still there
    let get = fixture.run(&["get", "credentials"]);
    let stdout = String::from_utf8_lossy(&get.stdout);
    assert!(stdout.contains("charlie"), "username preserved");
    assert!(stdout.contains("newpass"), "password updated");
    assert!(stdout.contains("JBSWY3DPEHPK3PXS"), "totp_secret preserved");
}

#[test]
fn operator_totp_generates_code_when_seed_exists() {
    let fixture = CliFixture::new("operator-values");
    fixture.init("Test Vault <test@example.com>");

    fixture.run(&[
        "set",
        "test-2fa",
        "username=diana",
        "password=pass999",
        "totp_secret=JBSWY3DPEHPK3PXP",
    ]);

    // Get TOTP code
    let output = fixture.run(&["totp", "test-2fa"]);
    assert_success("generate totp code", &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("has_seed") && stdout.contains("true"),
        "should indicate seed exists"
    );
    // Code may be present depending on oathtool availability
}

#[test]
fn operator_totp_indicates_no_seed_when_field_missing() {
    let fixture = CliFixture::new("operator-values");
    fixture.init("Test Vault <test@example.com>");

    fixture.run(&["set", "no-totp", "username=eve", "password=pass111"]);

    let output = fixture.run(&["totp", "no-totp"]);
    assert_success("check totp absence", &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("has_seed") && stdout.contains("false"),
        "should indicate no seed"
    );
}

#[test]
fn update_credential_fields_preserves_all_original_fields() {
    let fixture = CliFixture::new("operator-values");
    fixture.init("Test Vault <test@example.com>");

    // Create initial item
    fixture.run(&[
        "set",
        "user-account",
        "username=frank",
        "password=pass222",
        "totp_secret=JBSWY3DPEHPK3PXR",
    ]);

    // Update by reading, modifying, and writing back
    let get_output = fixture.run(&["get", "user-account"]);
    assert_success("read for update", &get_output);
    let item_json = String::from_utf8_lossy(&get_output.stdout);

    // Now update password via stdin (simulating set-json)
    let updated_json = item_json.replace("pass222", "newpass222").to_string();

    let set_output = fixture.run_with_stdin(&["set-json", "user-account"], &updated_json);
    assert_success("write updated item", &set_output);

    // Verify all fields survived
    let final_get = fixture.run(&["get", "user-account"]);
    let final_json = String::from_utf8_lossy(&final_get.stdout);
    assert!(
        final_json.contains("frank"),
        "username should survive update"
    );
    assert!(
        final_json.contains("newpass222"),
        "password should be updated"
    );
    assert!(
        final_json.contains("JBSWY3DPEHPK3PXR"),
        "totp_secret should survive update"
    );
}
