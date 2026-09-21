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

const OWNER: &str = "Skarbiec identity test <skarbiec-identity-test@example.invalid>";
/// A real Base32 seed shape, so the TOTP consumer produces a code from it.
const SEED: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

fn json_of(output: &std::process::Output) -> Value {
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

/// The duplicate the fleet's vault is full of: the same credential stored
/// again under a second name.
#[test]
fn a_second_item_holding_one_payload_is_refused_and_names_the_holder() {
    let fixture = CliFixture::new("idnt");
    fixture.init(OWNER);
    assert_success(
        "store the first row",
        &fixture.run(&[
            "set",
            "oxylabs",
            "--type",
            "login",
            "username=fleet@example.invalid",
            "password=one-proxy-password",
        ]),
    );

    let refused = fixture.run(&[
        "set",
        "platform-admin-oxylabs",
        "--type",
        "login",
        "username=fleet@example.invalid",
        "password=one-proxy-password",
    ]);
    assert_eq!(refused.status.code(), Some(1));
    let said = stderr(&refused);
    assert!(said.contains("oxylabs already holds"), "{said}");
    assert!(said.contains("exact duplicate is refused"), "{said}");

    // One differing field is another account, not a duplicate.
    assert_success(
        "store a row that differs",
        &fixture.run(&[
            "set",
            "platform-admin-oxylabs",
            "--type",
            "login",
            "username=fleet@example.invalid",
            "password=another-proxy-password",
        ]),
    );

    // Rewriting one item with its own payload is a rotation: the refusal is
    // about a SECOND holder, not about writing the same row again.
    assert_success(
        "rewrite one item with its own payload",
        &fixture.run(&[
            "set",
            "oxylabs",
            "--type",
            "login",
            "username=fleet@example.invalid",
            "password=one-proxy-password",
        ]),
    );
}

/// `duplicates` answers for what the refusal cannot reach: rows already in a
/// vault. A vault whose rows all differ reports nothing.
#[test]
fn duplicates_reports_nothing_when_every_row_differs() {
    let fixture = CliFixture::new("idnt");
    fixture.init(OWNER);
    assert_success(
        "store the first row",
        &fixture.run(&[
            "set",
            "umami",
            "--type",
            "login",
            "username=fleet@example.invalid",
            "password=dashboard-password",
        ]),
    );
    assert_success(
        "store a distinct row",
        &fixture.run(&[
            "set",
            "platform-admin-umami",
            "--type",
            "login",
            "username=fleet@example.invalid",
            "password=other-password",
        ]),
    );

    let report = json_of(&fixture.run(&["duplicates"]));
    assert_eq!(report["groups"], 0, "{report}");
    assert_eq!(report["items"], 0, "{report}");
}

/// The refusal only sees rows that carry a fingerprint, so an empty duplicate
/// report has to say how much of the vault it covered. The fleet's own vault
/// is why: on the day the feature shipped, all 658 active items predated the
/// field and the report said `groups: 0` about a vault holding 36 duplicate
/// groups.
#[test]
fn the_report_says_how_many_rows_it_could_not_compare_and_the_pass_stamps_them() {
    let fixture = CliFixture::new("idnt");
    fixture.init(OWNER);
    assert_success(
        "store one row",
        &fixture.run(&[
            "set",
            "oxylabs",
            "--type",
            "login",
            "username=fleet@example.invalid",
            "password=proxy-password",
        ]),
    );

    // Strip the field the way every row written before 0.3.11 lacks it, then
    // ask both questions again.
    fixture.edit_vault(|document| {
        for entry in document["items"]
            .as_object_mut()
            .expect("the vault carries items")
            .values_mut()
        {
            entry
                .as_object_mut()
                .expect("an item is an object")
                .remove("payload_fingerprint");
        }
    });

    let blind = json_of(&fixture.run(&["duplicates"]));
    assert_eq!(blind["compared"], 0, "{blind}");
    assert_eq!(blind["without_fingerprint"], 1, "{blind}");
    assert!(
        blind["note"]
            .as_str()
            .expect("a note when nothing could be compared")
            .contains("cannot be compared"),
        "{blind}"
    );

    let planned = json_of(&fixture.run(&["stamp-fingerprints"]));
    assert_eq!(planned["applied"], false, "{planned}");
    assert_eq!(planned["stamped"], 1, "{planned}");
    let still_blind = json_of(&fixture.run(&["duplicates"]));
    assert_eq!(still_blind["compared"], 0, "{still_blind}");

    let applied = json_of(&fixture.run(&["stamp-fingerprints", "--apply"]));
    assert_eq!(applied["applied"], true, "{applied}");
    assert_eq!(applied["stamped"], 1, "{applied}");
    assert_eq!(applied["unreadable"].as_array().map(Vec::len), Some(0));

    let covered = json_of(&fixture.run(&["duplicates"]));
    assert_eq!(covered["compared"], 1, "{covered}");
    assert_eq!(covered["without_fingerprint"], 0, "{covered}");
    assert!(covered["note"].is_null(), "{covered}");

    // A second pass has nothing left to do and does not re-salt the vault.
    let again = json_of(&fixture.run(&["stamp-fingerprints", "--apply"]));
    assert_eq!(again["stamped"], 0, "{again}");
    assert_eq!(again["already_stamped"], 1, "{again}");
}

/// A stamped vault finds the pair the refusal never saw.
#[test]
fn the_pass_makes_two_rows_written_blind_report_as_one_duplicate_group() {
    let fixture = CliFixture::new("idnt");
    fixture.init(OWNER);
    assert_success(
        "store the first row",
        &fixture.run(&[
            "set",
            "anticaptcha",
            "--type",
            "login",
            "username=fleet@example.invalid",
            "password=one-key",
        ]),
    );
    // The second row holds exactly the first one's payload, which the write
    // funnel refuses — so it is written the way the old vault holds it, with
    // no fingerprint on either row.
    fixture.edit_vault(|document| {
        let items = document["items"]
            .as_object_mut()
            .expect("the vault carries items");
        let (_, first) = items
            .iter()
            .next()
            .map(|(id, entry)| (id.clone(), entry.clone()))
            .expect("one stored row");
        let mut copy = first.clone();
        let object = copy.as_object_mut().expect("an item is an object");
        object.remove("payload_fingerprint");
        items.insert("platform-admin-anticaptcha".to_string(), copy);
        for entry in items.values_mut() {
            entry
                .as_object_mut()
                .expect("an item is an object")
                .remove("payload_fingerprint");
        }
    });

    assert_success(
        "stamp the rows the funnel never saw",
        &fixture.run(&["stamp-fingerprints", "--apply"]),
    );
    let report = json_of(&fixture.run(&["duplicates"]));
    assert_eq!(report["groups"], 1, "{report}");
    assert_eq!(report["items"], 2, "{report}");
    assert_eq!(report["duplicates"][0]["kind"], "login", "{report}");
}
