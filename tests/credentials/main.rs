#[path = "../support/mod.rs"]
mod support;

use serde_json::Value;
use support::{assert_success, stderr, CliFixture};

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const PRINCIPAL: &str = "22222222-2222-4222-8222-222222222222";
const UPN: &str = "admin@example.invalid";

fn fixture() -> CliFixture {
    let fixture = CliFixture::new("credentials");
    fixture.init("Skarbiec credential test <skarbiec-credential-test@example.invalid>");
    fixture
}

fn seal(fixture: &CliFixture) -> Value {
    let output = fixture.run(&[
        "credential",
        "seal-directory",
        "entra-admin",
        "--provider",
        "microsoft_entra",
        "--tenant",
        TENANT,
        "--object-id",
        PRINCIPAL,
        "--account-upn",
        UPN,
        "--local",
    ]);
    assert_success("seal one directory identity", &output);
    serde_json::from_slice(&output.stdout).expect("parse seal response")
}

#[test]
fn seal_directory_persists_one_identity_contract_and_refuses_replacement() {
    let fixture = fixture();
    let response = seal(&fixture);
    assert_eq!(response["status"], "sealed");
    assert_eq!(response["credential"], "entra-admin");
    assert_eq!(response["directory"]["provider"], "microsoft_entra");

    let status = fixture.run(&["credential", "status", "entra-admin", "--local"]);
    assert_success("read persisted directory identity", &status);
    let status: Value = serde_json::from_slice(&status.stdout).expect("parse credential status");
    assert_eq!(status["directory"]["tenant_id"], TENANT);
    assert_eq!(status["directory"]["principal_object_id"], PRINCIPAL);
    assert_eq!(status["directory"]["account_upn"], UPN);

    let duplicate = fixture.run(&[
        "credential",
        "seal-directory",
        "entra-admin",
        "--provider",
        "microsoft_entra",
        "--tenant",
        "33333333-3333-4333-8333-333333333333",
        "--object-id",
        "44444444-4444-4444-8444-444444444444",
        "--account-upn",
        "other@example.invalid",
        "--local",
    ]);
    assert_eq!(duplicate.status.code(), Some(1));
    assert_eq!(
        stderr(&duplicate),
        "Error: entra-admin already carries a sealed directory contract; changing it requires credential reseal and a reseal capability"
    );
}

#[test]
fn expectation_mismatch_refuses_before_any_weles_operation() {
    let fixture = fixture();
    seal(&fixture);

    for (flag, wrong) in [
        ("--expect-tenant", "33333333-3333-4333-8333-333333333333"),
        ("--expect-object-id", "44444444-4444-4444-8444-444444444444"),
        ("--expect-upn", "other@example.invalid"),
    ] {
        let output = fixture.run(&[
            "credential",
            "verify",
            "entra-admin",
            "--provider",
            "microsoft_entra",
            "--consumer",
            "directory-verifier",
            flag,
            wrong,
            "--local",
        ]);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr(&output).contains("does not match the sealed directory contract"),
            "unexpected refusal for {flag}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn generic_provider_refusals_do_not_create_a_credential() {
    let fixture = fixture();

    let reset = fixture.run(&[
        "credential",
        "reset",
        "openrouter",
        "--provider",
        "openrouter",
        "--consumer",
        "design-assets",
        "--local",
    ]);
    assert_eq!(reset.status.code(), Some(1));
    assert!(stderr(&reset).contains("has no credential reset contract"));

    let malformed = fixture.run(&[
        "credential",
        "acquire",
        "Open_Router",
        "--provider",
        "Open_Router",
        "--consumer",
        "design-assets",
        "--signup-origin",
        "https://openrouter.ai",
        "--local",
    ]);
    assert_eq!(malformed.status.code(), Some(1));
    assert!(stderr(&malformed).contains("generic provider slug"));

    let malformed_origin = fixture.run(&[
        "credential",
        "acquire",
        "openrouter",
        "--provider",
        "openrouter",
        "--consumer",
        "design-assets",
        "--signup-origin",
        "https://openrouter.ai/signup?source=test",
        "--local",
    ]);
    assert_eq!(malformed_origin.status.code(), Some(1));
    assert_eq!(
        stderr(&malformed_origin),
        "Error: --signup-origin must be https://<host>[:<port>]: an absolute https origin, lowercase host, no userinfo, path, query or fragment"
    );

    let absent = fixture.run(&["get", "openrouter", "--field", "api_key"]);
    assert_eq!(absent.status.code(), Some(1));
    assert_eq!(stderr(&absent), "Error: no item: openrouter");
}
