#[path = "../support/mod.rs"]
mod support;

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use support::{assert_success, stderr, CliFixture};

const OWNER: &str = "Skarbiec removal owner <skarbiec-removal-owner@example.invalid>";
const MEMBER: &str = "Skarbiec removal member <skarbiec-removal-member@example.invalid>";
const SHARED: &str = "shared-login";
const PRIVATE: &str = "owner-only-login";

fn vault(fixture: &CliFixture) -> Value {
    serde_json::from_str(&fs::read_to_string(&fixture.vault).expect("read the fixture vault"))
        .expect("the fixture vault is JSON")
}

fn gpg(home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new("gpg")
        .env("GNUPGHOME", home)
        .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gpg");
    if let Some(text) = stdin {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("gpg stdin")
            .write_all(text.as_bytes())
            .expect("write gpg stdin");
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("wait for gpg")
}

/// A keyring holding only the member's secret key, so a decryption there
/// answers exactly one question: can the removed person still open this?
fn member_only_keyring(fixture: &CliFixture) -> std::path::PathBuf {
    let exported = gpg(
        &fixture.gnupg,
        &["--armor", "--export-secret-keys", MEMBER],
        None,
    );
    assert_success("export the member's secret key", &exported);
    let home = fixture.root.join("mg");
    fs::create_dir_all(&home).expect("create the member keyring");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect it");
    let imported = gpg(
        &home,
        &["--import"],
        Some(&String::from_utf8_lossy(&exported.stdout)),
    );
    assert_success("import the member's secret key alone", &imported);
    home
}

fn ciphertexts(document: &Value, item: &str) -> Vec<String> {
    let entry = &document["items"][item];
    let mut all = vec![entry["current"]["ciphertext"]
        .as_str()
        .expect("current ciphertext")
        .to_string()];
    for version in entry["history"].as_array().expect("history array") {
        all.push(
            version["ciphertext"]
                .as_str()
                .expect("historical ciphertext")
                .to_string(),
        );
    }
    all
}

fn opens(home: &Path, ciphertext: &str) -> bool {
    gpg(home, &["--decrypt"], Some(ciphertext)).status.success()
}

#[test]
fn remove_user_takes_a_person_out_of_every_revision_and_names_what_they_saw() {
    let fixture = CliFixture::new("recipients");
    fixture.init(OWNER);
    assert_success("register the member", &fixture.run(&["add-user", MEMBER]));
    for (item, password) in [(SHARED, "first"), (SHARED, "second"), (PRIVATE, "owner")] {
        let secret = format!("password={password}");
        assert_success(
            "write one login revision",
            &fixture.run(&["set", item, "--type", "login", "username=u", &secret]),
        );
        if item == SHARED && password == "first" {
            assert_success(
                "share it with the member",
                &fixture.run(&["share", SHARED, MEMBER]),
            );
        }
    }
    assert_success(
        "give the member a pending emergency grant",
        &fixture.run(&[
            "emergency-grant",
            MEMBER,
            "--activate-after",
            "2099-01-01T00:00:00Z",
        ]),
    );
    let member_keys = member_only_keyring(&fixture);
    let shared_before = ciphertexts(&vault(&fixture), SHARED);
    assert!(
        shared_before.len() > 1,
        "the shared item carries history to rewrap"
    );
    assert!(
        opens(&member_keys, &shared_before[0]),
        "control: the member opens the shared item before removal"
    );

    let removed = fixture.run(&["remove-user", MEMBER]);
    assert_success("remove the member from the vault", &removed);
    let report: Value = serde_json::from_slice(&removed.stdout).expect("removal report");
    assert_eq!(report["uid"], MEMBER);
    assert_eq!(report["items_rewrapped"], 1);
    assert_eq!(report["emergency_grant_cancelled"], true);
    assert_eq!(report["exposed"][0]["item"], SHARED);
    assert_eq!(report["rotate_manually"], serde_json::json!([SHARED]));
    assert_eq!(report["rotation_marked_due"], serde_json::json!([]));

    let after = vault(&fixture);
    assert!(
        after["recipients"].get(MEMBER).is_none(),
        "registry entry removed"
    );
    assert!(
        after["emergency"].get(MEMBER).is_none(),
        "pending emergency grant cancelled"
    );
    let recipients = after["items"][SHARED]["recipients"]
        .as_array()
        .expect("recipients");
    assert!(!recipients.iter().any(|uid| uid == MEMBER));
    for ciphertext in ciphertexts(&after, SHARED) {
        assert!(
            !opens(&member_keys, &ciphertext),
            "a current or historical revision still opens for the removed member"
        );
    }
    let read_back = fixture.run(&["get", SHARED, "--field", "password"]);
    assert_success("the owner still reads the shared item", &read_back);
    assert!(String::from_utf8_lossy(&read_back.stdout).contains("second"));

    let reshare = fixture.run(&["share", SHARED, MEMBER]);
    assert_success("share answers with a blocked status", &reshare);
    let reshare: Value = serde_json::from_slice(&reshare.stdout).expect("share answer");
    assert_eq!(reshare["reason"], "unknown_recipient");
}

#[test]
fn remove_user_refuses_the_owner_an_unknown_uid_and_no_uid_without_writing() {
    let fixture = CliFixture::new("recipients");
    fixture.init(OWNER);
    let untouched = fs::read(&fixture.vault).expect("read the vault");
    let refusals = [
        (
            vec!["remove-user", OWNER],
            format!(
                "Error: {OWNER} is the vault owner; install another owner with rotate-owner first, then remove {OWNER}"
            ),
        ),
        (
            vec!["remove-user", "nobody@example.invalid"],
            "Error: unknown recipient: nobody@example.invalid".to_string(),
        ),
        (
            vec!["remove-user"],
            "Error: usage: remove-user <uid>".to_string(),
        ),
    ];
    for (args, sentence) in refusals {
        let refused = fixture.run(&args);
        assert_eq!(refused.status.code(), Some(1), "{args:?} must be refused");
        assert_eq!(stderr(&refused), sentence);
    }
    assert_eq!(
        fs::read(&fixture.vault).expect("read the vault"),
        untouched,
        "a refused removal leaves the vault file unchanged"
    );
}
