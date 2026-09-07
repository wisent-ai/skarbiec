#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use support::{assert_success, stderr, CliFixture};

const CONSUMER: &str = "landing-cli";
const ITEM: &str = "brama-router";

fn fixture() -> CliFixture {
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

fn mint(fixture: &CliFixture, capabilities: &str) -> Value {
    let output = fixture.run(&["grant", "issue", CONSUMER, "--capabilities", capabilities]);
    assert_success("mint one scoped grant", &output);
    serde_json::from_slice(&output.stdout).expect("parse mint response")
}

fn vault_tokens(fixture: &CliFixture) -> Value {
    let raw = fs::read_to_string(&fixture.vault).expect("read vault state");
    let doc: Value = serde_json::from_str(&raw).expect("parse vault state");
    doc.get("tokens").cloned().unwrap_or(Value::Null)
}

#[test]
fn grant_issue_shows_the_grant_once_and_stores_only_its_hash() {
    let fixture = fixture();

    let response = mint(&fixture, "read:brama-router#api_key");
    assert_eq!(response["ok"], true);
    assert_eq!(response["consumer"], CONSUMER);
    assert_eq!(response["workload_bound"], false);
    assert_eq!(response["capabilities"][0]["action"], "read");
    assert_eq!(response["capabilities"][0]["item"], ITEM);
    assert_eq!(response["capabilities"][0]["field"], "api_key");

    let token = response["token"].as_str().expect("grant value shown once");
    assert_eq!(token.len(), 64, "grant is one 64-hex bearer");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

    // The vault retains the consumer's capability row and a hash — never the
    // grant value itself.
    let stored = vault_tokens(&fixture);
    let row = &stored[CONSUMER];
    assert_eq!(row["capabilities"][0]["item"], ITEM);
    let hash = row["hash"].as_str().expect("stored grant hash");
    assert_ne!(hash, token, "vault must not retain the presented grant");
    let vault_bytes = fs::read_to_string(&fixture.vault).expect("read vault state");
    assert!(
        !vault_bytes.contains(token),
        "grant value must not appear anywhere in the vault file"
    );

    // The listing repeats scope metadata and never a grant value.
    let output = fixture.run(&["grant", "list"]);
    assert_success("list consumers", &output);
    let listing = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(listing.contains(CONSUMER));
    assert!(!listing.contains(token));
    assert!(!listing.contains("\"token\""));
}

#[test]
fn grant_issue_refuses_inexact_unknown_or_dangling_capabilities() {
    let fixture = fixture();

    let cases: &[(&[&str], &str)] = &[
        (&["grant", "issue", CONSUMER], "--capabilities is required"),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "steal:brama-router#api_key",
            ],
            "unsupported capability action: steal",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "read:brama-*#api_key",
            ],
            "capabilities require exact resource and field names without globs",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "acquire:brama-router",
            ],
            "acquire capability requires one exact field",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "read:brama-router#api_key,read:brama-router#api_key",
            ],
            "duplicate capability: read:brama-router#api_key",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "read:niema#api_key",
            ],
            "capability names a missing item: niema",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "read:brama-router#niema",
            ],
            "capability names a missing field: brama-router#niema",
        ),
    ];

    for (args, sentence) in cases {
        let output = fixture.run(args);
        assert!(
            !output.status.success(),
            "refusal case unexpectedly succeeded: {args:?}"
        );
        let message = stderr(&output);
        assert!(
            message.contains(sentence),
            "refusal for {args:?} must say {sentence:?}, said {message:?}"
        );
    }

    // No refusal may leave a grant behind: the consumer never appears in the
    // vault's token map, whether that map is absent or empty.
    let stored = vault_tokens(&fixture);
    assert!(
        stored.is_null() || stored.as_object().is_some_and(|map| map.is_empty()),
        "refusals must not persist grants, vault kept {stored}"
    );
}

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

#[test]
fn grant_issue_refuses_grants_that_mix_incompatible_actions() {
    let fixture = fixture();

    // Driving a credential lifecycle never authorizes reading the value.
    let output = fixture.run(&[
        "grant",
        "issue",
        "mixer",
        "--capabilities",
        "read:brama-router#api_key,lifecycle:brama-router",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output)
        .contains("lifecycle capabilities cannot share a grant with read capabilities"));

    // One-use acquisition and standing direct access never share one bearer.
    let output = fixture.run(&[
        "grant",
        "issue",
        "mixer",
        "--capabilities",
        "acquire:brama-router#api_key,read:brama-router#username",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output)
        .contains("acquire capabilities cannot share a grant with direct capabilities"));
}

#[test]
fn routes_verify_refuses_placeholder_credentials() {
    let fixture = CliFixture::new("grants");
    fixture.init("Skarbiec route test <skarbiec-route-test@example.invalid>");
    let stored = fixture.run(&[
        "set",
        "placeholder-provider",
        "--type",
        "api-key",
        "api_key=PROVIDER_API_KEY",
    ]);
    assert_success("store placeholder provider item", &stored);
    let added = fixture.run(&[
        "routes",
        "add",
        "--resource",
        "provider:placeholder",
        "--item",
        "placeholder-provider",
        "--field",
        "api_key",
        "--reason",
        "test placeholder diagnosis",
    ]);
    assert_success("add placeholder route", &added);

    let refused = fixture.run(&["routes", "verify"]);
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains(
        "vault item placeholder-provider field api_key contains an uppercase placeholder, not a usable credential"
    ));

    let replaced = fixture.run(&[
        "set",
        "placeholder-provider",
        "--type",
        "api-key",
        "api_key=real-provider-secret",
    ]);
    assert_success("replace placeholder in isolated fixture", &replaced);
    let verified = fixture.run(&["routes", "verify"]);
    assert_success("verify real provider credential", &verified);
    let report: Value =
        serde_json::from_slice(&verified.stdout).expect("parse route verification report");
    assert_eq!(report["checked"], 1);
    assert_eq!(report["broken"], serde_json::json!([]));
}

/// The bearer a declared grant hands back is the one the serving path
/// accepts, and revoking the declaration stops that same read.
///
/// A capability row in the vault is a weaker claim than a read that succeeds:
/// the broker matches the presented bearer, resolves the item and consults the
/// credential lifecycle, so this drives the real route rather than asserting
/// that a row was written.
#[test]
fn a_declared_grant_reads_the_field_it_names_until_it_is_revoked() {
    let fixture = fixture();
    let issued = mint(&fixture, "read:brama-router#api_key");
    let bearer = issued["token"]
        .as_str()
        .expect("bearer shown once")
        .to_owned();
    let broker = fixture.serve();
    let url = broker.url("/v1/items/read");
    let body = format!(r#"{{"id":"{ITEM}","field":"api_key"}}"#);

    let (status, payload) = read_field(&url, CONSUMER, &bearer, &body);
    assert_eq!(status, 200, "the declared read was refused: {payload}");
    assert!(payload.contains("sekret-123"), "read returned {payload}");

    assert_success(
        "revoke the declaration",
        &fixture.run(&["grant", "revoke", CONSUMER]),
    );
    let (status, payload) = read_field(&url, CONSUMER, &bearer, &body);
    assert_eq!(status, 403, "a revoked grant still read: {payload}");
    assert!(
        payload.contains("consumer not authorized to read item field"),
        "refusal was {payload}"
    );
}

fn read_field(url: &str, consumer: &str, bearer: &str, body: &str) -> (u32, String) {
    let output = Command::new("curl")
        .args([
            "-s",
            "-m",
            "60",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            "-X",
            "POST",
            url,
            "-H",
            &format!("X-Consumer: {consumer}"),
            "-H",
            &format!("Authorization: Bearer {bearer}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
        ])
        .output()
        .expect("run curl");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let (payload, status) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (
        status.trim().parse().unwrap_or_default(),
        payload.to_string(),
    )
}

/// An acquire declaration hands out no bearer at all, and states how it is
/// spent.
///
/// This is what `invite` was for: the operator who declares one holds nothing,
/// so the contract has to arrive with the declaration or not at all.
#[test]
fn an_acquire_grant_returns_no_bearer_and_states_its_redemption() {
    let fixture = fixture();
    let key = fixture.root.join("workload.pub.pem");
    write_workload_key(&fixture, &key);
    let path = key.to_str().expect("utf-8 key path");

    let output = fixture.run(&[
        "grant",
        "issue",
        "probe-workload",
        "--capabilities",
        "acquire:brama-router#api_key",
        "--workload-public-key-file",
        path,
    ]);
    assert_success("declare one workload-bound acquire grant", &output);
    let declared: Value = serde_json::from_slice(&output.stdout).expect("parse issue response");
    assert_eq!(declared["workload_bound"], true);
    assert_eq!(
        declared["token"],
        Value::Null,
        "an acquire grant hands out no standing bearer"
    );
    assert_eq!(declared["redeem"][0]["item"], ITEM);
    assert_eq!(declared["redeem"][0]["field"], "api_key");
    assert!(declared["redeem"][0]["how"]
        .as_str()
        .expect("redemption sentence")
        .contains("skarbiec acquisition-request probe-workload brama-router api_key"));

    // No key, no acquire declaration; and a key with nothing to acquire is
    // refused from the other side.
    let output = fixture.run(&[
        "grant",
        "issue",
        "keyless",
        "--capabilities",
        "acquire:brama-router#api_key",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("acquire capabilities require --workload-public-key-file"));
    let output = fixture.run(&[
        "grant",
        "issue",
        "direct",
        "--capabilities",
        "read:brama-router#api_key",
        "--workload-public-key-file",
        path,
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("workload public keys are valid only for acquire capabilities")
    );
}

fn write_workload_key(fixture: &CliFixture, public: &Path) {
    let private = fixture.root.join("workload.pem");
    let generated = Command::new("openssl")
        .args(["genpkey", "-algorithm", "ed25519", "-out"])
        .arg(&private)
        .status()
        .expect("run openssl genpkey");
    assert!(generated.success(), "openssl generated no Ed25519 key");
    let derived = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&private)
        .args(["-pubout", "-out"])
        .arg(public)
        .status()
        .expect("run openssl pkey");
    assert!(derived.success(), "openssl derived no public half");
    fs::set_permissions(public, fs::Permissions::from_mode(0o600))
        .expect("protect the workload public key");
}

/// `grant capability` issues one bounded redemption of a declaration that
/// already exists, and refuses at issue time rather than at redemption.
#[test]
fn grant_capability_refuses_an_unmapped_resource_and_issues_a_mapped_one() {
    let fixture = fixture();
    mint(&fixture, "read:brama-router#api_key");

    let output = fixture.run(&[
        "grant",
        "capability",
        "--agent",
        CONSUMER,
        "--purpose",
        "declared-grant-test",
        "--target",
        "demo",
        "--resource",
        "provider:unmapped",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains(
        "grant capability refused for provider:unmapped: no capability route maps provider:unmapped to a vault field"
    ));

    assert_success(
        "map the resource to a vault field",
        &fixture.run(&[
            "routes",
            "add",
            "--resource",
            "provider:demo",
            "--item",
            ITEM,
            "--field",
            "api_key",
            "--reason",
            "declared consumer grant test",
        ]),
    );
    let output = fixture.run(&[
        "grant",
        "capability",
        "--agent",
        CONSUMER,
        "--purpose",
        "declared-grant-test",
        "--target",
        "demo",
        "--resource",
        "provider:demo",
    ]);
    assert_success("issue one bounded redemption", &output);
    let issued: Value = serde_json::from_slice(&output.stdout).expect("parse capability response");
    assert_eq!(issued["status"], "issued");
    assert_eq!(
        issued["capability_id"]
            .as_str()
            .expect("capability id")
            .len(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".len()
    );

    // The group owns its namespace: a subcommand it does not carry is refused
    // by name instead of falling through to another dispatcher.
    let output = fixture.run(&["grant", "__surface_probe__"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown grant command: __surface_probe__"));
}

/// Widening a declaration that was never written is refused by that name.
#[test]
fn grant_ensure_refuses_a_consumer_with_no_declaration() {
    let fixture = fixture();
    let bearer_file = fixture.root.join("absent.txt");
    fs::write(&bearer_file, "deadbeef").expect("write bearer file");
    fs::set_permissions(&bearer_file, fs::Permissions::from_mode(0o600))
        .expect("protect bearer file");
    let output = fixture.run(&[
        "grant",
        "ensure",
        "nobody",
        ITEM,
        "--field",
        "api_key",
        "--token-file",
        bearer_file.to_str().expect("utf-8 bearer path"),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("consumer has no existing grant"));
}
