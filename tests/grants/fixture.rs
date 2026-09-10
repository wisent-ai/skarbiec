//! The vault every grant test starts from, and the two reads each of them
//! makes: mint one grant, and look at what the vault stored for it.

use std::fs;

use serde_json::Value;

use crate::support::{assert_success, CliFixture};

pub const CONSUMER: &str = "landing-cli";
pub const ITEM: &str = "brama-router";

pub fn fixture() -> CliFixture {
    let fixture = CliFixture::new("grants");
    fixture.init("Skarbiec grant test <skarbiec-grant-test@example.invalid>");
    let output = fixture.run(&[
        "set",
        ITEM,
        "--type",
        "api-key",
        "api_key=sekret-123",
        "username=ops",
    ]);
    assert_success("seed one api-key item", &output);
    fixture
}

pub fn mint(fixture: &CliFixture, capabilities: &str) -> Value {
    let output = fixture.run(&["grant", "issue", CONSUMER, "--capabilities", capabilities]);
    assert_success("mint one scoped grant", &output);
    serde_json::from_slice(&output.stdout).expect("parse mint response")
}

pub fn vault_tokens(fixture: &CliFixture) -> Value {
    let raw = fs::read_to_string(&fixture.vault).expect("read vault state");
    let doc: Value = serde_json::from_str(&raw).expect("parse vault state");
    doc.get("tokens").cloned().unwrap_or(Value::Null)
}
