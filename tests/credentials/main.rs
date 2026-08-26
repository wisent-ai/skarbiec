#[path = "../support/mod.rs"]
mod support;

use serde_json::Value;
use support::{assert_success, stderr, CliFixture};

#[test]
fn seal_directory_persists_one_identity_contract_and_refuses_replacement() {
    let fixture = CliFixture::new("credentials");
    fixture.init("Skarbiec credential test <skarbiec-credential-test@example.invalid>");

    let sealed = fixture.run(&[
        "credential",
        "seal-directory",
        "entra-admin",
        "--provider",
        "microsoft_entra",
        "--tenant",
        "11111111-1111-4111-8111-111111111111",
        "--object-id",
        "22222222-2222-4222-8222-222222222222",
        "--account-upn",
        "admin@example.invalid",
        "--local",
    ]);
    assert_success("seal one directory identity", &sealed);
    let response: Value = serde_json::from_slice(&sealed.stdout).expect("parse seal response");
    assert_eq!(response["status"], "sealed");
    assert_eq!(response["credential"], "entra-admin");
    assert_eq!(response["directory"]["provider"], "microsoft_entra");

    let status = fixture.run(&["credential", "status", "entra-admin", "--local"]);
    assert_success("read persisted directory identity", &status);
    let status: Value = serde_json::from_slice(&status.stdout).expect("parse credential status");
    assert_eq!(status["directory"]["tenant_id"], "11111111-1111-4111-8111-111111111111");
    assert_eq!(status["directory"]["principal_object_id"], "22222222-2222-4222-8222-222222222222");
    assert_eq!(status["directory"]["account_upn"], "admin@example.invalid");

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
