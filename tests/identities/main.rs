//! The identity an account belongs to, and the refusal of an exact duplicate.
//!
//! Both against the real binary, a disposable vault and an isolated keyring.
//! The fleet's own vault is what these cases are about: 66 `login` rows where
//! 29 of them describe 12 platforms, four rows for one Google admin identity,
//! and every row separately reporting `declared_empty` for a second factor
//! that belongs to one account.

#[path = "../support/mod.rs"]
mod support;

use serde_json::Value;
use support::{assert_success, stderr, CliFixture};

pub(crate) const OWNER: &str = "Skarbiec identity test <skarbiec-identity-test@example.invalid>";
/// A real Base32 seed shape, so the TOTP consumer produces a code from it.
const SEED: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

pub(crate) fn json_of(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("command prints one JSON value")
}

/// One Google account carrying the second factor, and a platform login
/// performed as it.
fn vault_with_identity(fixture: &CliFixture) {
    fixture.init(OWNER);
    assert_success(
        "store the identity",
        &fixture.run(&[
            "set",
            "google-lukasz",
            "--type",
            "identity",
            "email=lukasz.bartoszcze@wisent.ai",
            "phone=+48792664336",
            &format!("totp_secret={SEED}"),
        ]),
    );
    assert_success(
        "store a platform login that signs in as the identity",
        &fixture.run_with_stdin(
            &["set-json", "claude-sso", "--type", "login"],
            &serde_json::json!({
                "schema": "skarbiec.item.v2",
                "kind": "login",
                "fields": {"username": "lukasz.bartoszcze@wisent.ai", "password": "platform-one"},
                "context": {"identity": "google-lukasz"},
            })
            .to_string(),
        ),
    );
}

/// The question that had no answer while a second factor lived on platform
/// rows: where does this login's factor come from.
#[test]
fn a_login_resolves_its_second_factor_from_the_identity_it_names() {
    let fixture = CliFixture::new("idnt");
    vault_with_identity(&fixture);

    let state = fixture.run(&["totp-seed-state", "claude-sso"]);
    assert_success("judge the login's factor", &state);
    let row = json_of(&state);
    assert_eq!(row["seed_state"], "present", "{row}");
    assert_eq!(row["identity"], "google-lukasz", "{row}");

    let code = fixture.run(&["totp", "claude-sso"]);
    assert_success("compute a code for the login", &code);
    let answer = json_of(&code);
    assert_eq!(answer["has_seed"], true, "{answer}");
    assert_eq!(answer["identity"], "google-lukasz", "{answer}");
    let digits = answer["code"].as_str().expect("a six-digit code");
    assert_eq!(digits.len(), "000000".len(), "{answer}");
    assert!(digits.bytes().all(|byte| byte.is_ascii_digit()), "{answer}");
}

/// A login with its own seed keeps answering from it: the indirection is for
/// rows that carry no factor, not a redirection of every row.
#[test]
fn a_login_carrying_its_own_seed_answers_from_itself() {
    let fixture = CliFixture::new("idnt");
    vault_with_identity(&fixture);
    assert_success(
        "store a login with its own factor",
        &fixture.run_with_stdin(
            &["set-json", "own-seed-login", "--type", "login"],
            &serde_json::json!({
                "schema": "skarbiec.item.v2",
                "kind": "login",
                "fields": {"username": "someone@example.invalid", "totp_secret": SEED},
                "context": {"identity": "google-lukasz"},
            })
            .to_string(),
        ),
    );

    let row = json_of(&fixture.run(&["totp-seed-state", "own-seed-login"]));
    assert_eq!(row["seed_state"], "present", "{row}");
    assert_eq!(row["identity"], Value::Null, "{row}");
}

/// A reference to an item that is not an active identity is refused at the
/// write, because a dangling reference sends every later factor lookup to
/// nothing.
#[test]
fn a_login_naming_a_missing_identity_is_refused() {
    let fixture = CliFixture::new("idnt");
    fixture.init(OWNER);

    let refused = fixture.run_with_stdin(
        &["set-json", "orphan-login", "--type", "login"],
        &serde_json::json!({
            "schema": "skarbiec.item.v2",
            "kind": "login",
            "fields": {"username": "a@example.invalid", "password": "b"},
            "context": {"identity": "nobody"},
        })
        .to_string(),
    );
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("this vault holds no such item"),
        "{}",
        stderr(&refused)
    );
}


#[path = "cases/duplicates.rs"]
mod duplicates;
