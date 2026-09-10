//! Changing a grant that already exists: what `verify` answers about it, how
//! rotation, replacement and `ensure` edit it, and what `revoke` leaves.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;

use crate::fixture::{fixture, mint, vault_tokens, CONSUMER, ITEM};
use crate::support::{assert_success, stderr};

#[test]
fn grant_verify_answers_only_the_exact_consumer_field_and_grant() {
    let fixture = fixture();
    let response = mint(&fixture, "read:brama-router#api_key");
    let token = response["token"].as_str().expect("grant value shown once");

    let allowed = |args: &[&str]| -> bool {
        let output = fixture.run(args);
        assert_success("verify answers instead of erroring", &output);
        let verdict: Value = serde_json::from_slice(&output.stdout).expect("parse verify verdict");
        verdict["allowed"].as_bool().expect("boolean verdict")
    };

    // The exact binding — consumer, item, field, grant — is allowed.
    assert!(allowed(&[
        "grant", "verify", CONSUMER, ITEM, "--field", "api_key", "--token", token,
    ]));
    // A field-scoped grant answers item-level questions with a refusal.
    assert!(!allowed(&[
        "grant", "verify", CONSUMER, ITEM, "--token", token
    ]));
    // A wrong grant value is refused for the right consumer.
    assert!(!allowed(&[
        "grant", "verify", CONSUMER, ITEM, "--field", "api_key", "--token", "deadbeef",
    ]));
    // The right grant value is refused for a different consumer.
    assert!(!allowed(&[
        "grant", "verify", "other", ITEM, "--field", "api_key", "--token", token,
    ]));
}

#[test]
fn grant_revoke_deletes_the_grant_and_stays_idempotent() {
    let fixture = fixture();
    let response = mint(&fixture, "read:brama-router#api_key");
    let token = response["token"].as_str().expect("grant value shown once");
    assert!(vault_tokens(&fixture)[CONSUMER].is_object());

    let output = fixture.run(&["grant", "revoke", CONSUMER]);
    assert_success("revoke the consumer's grant", &output);
    let revoked: Value = serde_json::from_slice(&output.stdout).expect("parse revoke response");
    assert_eq!(revoked["ok"], true);
    assert_eq!(revoked["consumer"], CONSUMER);

    // The vault state no longer carries the consumer.
    assert!(vault_tokens(&fixture)[CONSUMER].is_null());

    // The revoked grant no longer authorizes its previous exact binding.
    let output = fixture.run(&[
        "grant", "verify", CONSUMER, ITEM, "--field", "api_key", "--token", token,
    ]);
    assert_success("verify after revoke answers instead of erroring", &output);
    let verdict: Value = serde_json::from_slice(&output.stdout).expect("parse verify verdict");
    assert_eq!(verdict["allowed"], false);

    // Revoking an absent consumer reports the same settled outcome.
    let output = fixture.run(&["grant", "revoke", CONSUMER]);
    assert_success("second revoke is idempotent", &output);
    let repeated: Value = serde_json::from_slice(&output.stdout).expect("parse revoke response");
    assert_eq!(repeated["ok"], true);

    // The listing is empty again.
    let output = fixture.run(&["grant", "list"]);
    assert_success("list consumers after revoke", &output);
    let listing: Value = serde_json::from_slice(&output.stdout).expect("parse consumer listing");
    assert_eq!(listing, serde_json::json!([]));
}

#[test]
fn grants_are_edited_by_rotation_replacement_or_ensure() {
    let fixture = fixture();

    let first = mint(&fixture, "read:brama-router#api_key");
    let first_token = first["token"].as_str().expect("first bearer").to_owned();

    let allowed = |field: &str, token: &str| -> bool {
        let output = fixture.run(&[
            "grant", "verify", CONSUMER, ITEM, "--field", field, "--token", token,
        ]);
        assert_success("verify answers instead of erroring", &output);
        let verdict: Value = serde_json::from_slice(&output.stdout).expect("parse verify verdict");
        verdict["allowed"].as_bool().expect("boolean verdict")
    };

    // Re-minting the same capabilities rotates the bearer: the old value dies,
    // the new one answers for the unchanged scope.
    let rotated = mint(&fixture, "read:brama-router#api_key");
    let rotated_token = rotated["token"]
        .as_str()
        .expect("rotated bearer")
        .to_owned();
    assert_ne!(rotated_token, first_token);
    assert!(!allowed("api_key", &first_token));
    assert!(allowed("api_key", &rotated_token));

    // Changing the scope is refused unless the caller states the replacement.
    let output = fixture.run(&[
        "grant",
        "issue",
        CONSUMER,
        "--capabilities",
        "read:brama-router#username",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains(
        "grant issue refuses to change existing capabilities without --replace-capabilities"
    ));

    // With --replace-capabilities the grant is rewritten: new field answers,
    // the dropped field and the previous bearer both stop.
    let output = fixture.run(&[
        "grant",
        "issue",
        CONSUMER,
        "--capabilities",
        "read:brama-router#username",
        "--replace-capabilities",
        "true",
    ]);
    assert_success("replace the grant's capabilities", &output);
    let replaced: Value = serde_json::from_slice(&output.stdout).expect("parse mint response");
    let replaced_token = replaced["token"]
        .as_str()
        .expect("replaced bearer")
        .to_owned();
    assert!(allowed("username", &replaced_token));
    assert!(!allowed("api_key", &replaced_token));
    assert!(!allowed("api_key", &rotated_token));

    // grant ensure widens by one exact field without rotating the bearer.
    // The owner proves possession through a 0600 token file.
    let bearer_file = fixture.root.join("bearer.txt");
    fs::write(&bearer_file, &replaced_token).expect("write bearer file");
    fs::set_permissions(&bearer_file, fs::Permissions::from_mode(0o600))
        .expect("protect bearer file");
    let bearer_path = bearer_file.to_str().expect("utf-8 bearer path");

    let ensure = |field: &str| -> Value {
        let output = fixture.run(&[
            "grant",
            "ensure",
            CONSUMER,
            ITEM,
            "--field",
            field,
            "--token-file",
            bearer_path,
        ]);
        assert_success("ensure one exact field read", &output);
        serde_json::from_slice(&output.stdout).expect("parse ensure-read response")
    };
    let widened = ensure("api_key");
    assert_eq!(widened["ok"], true);
    assert_eq!(widened["status"], "added");
    assert_eq!(widened["capability"]["field"], "api_key");
    assert!(allowed("api_key", &replaced_token));
    assert!(allowed("username", &replaced_token));

    // Repeating the same widening settles as unchanged.
    assert_eq!(ensure("api_key")["status"], "unchanged");

    // A file that does not hash to the recorded bearer is refused.
    let wrong_file = fixture.root.join("wrong.txt");
    fs::write(&wrong_file, "deadbeef").expect("write wrong bearer");
    fs::set_permissions(&wrong_file, fs::Permissions::from_mode(0o600))
        .expect("protect wrong bearer");
    let output = fixture.run(&[
        "grant",
        "ensure",
        CONSUMER,
        ITEM,
        "--field",
        "username",
        "--token-file",
        wrong_file.to_str().expect("utf-8 path"),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("token file does not match the consumer's recorded bearer"));

    // A world-readable token file is refused before it is read.
    fs::set_permissions(&bearer_file, fs::Permissions::from_mode(0o644))
        .expect("loosen bearer file");
    let output = fixture.run(&[
        "grant",
        "ensure",
        CONSUMER,
        ITEM,
        "--field",
        "username",
        "--token-file",
        bearer_path,
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("token file must be an owner-controlled regular file"));
}

