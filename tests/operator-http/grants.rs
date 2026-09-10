use super::support::{assert_success, CliFixture};
use serde_json::{json, Value};
use std::process::Command;

#[test]
fn an_operator_issued_bearer_reads_its_field_until_revoked() {
    let fixture = CliFixture::new("operator-grant");
    fixture.init("Operator Grant Test <grant@example.invalid>");
    assert_success(
        "create login",
        &fixture.run(&[
            "set",
            "operator-login",
            "--type",
            "login",
            "username=operator",
            "password=grant-password",
        ]),
    );
    let broker = fixture.serve();
    let issue = Command::new("curl")
        .args([
            "--fail-with-body",
            "--silent",
            "--show-error",
            "--json",
            &json!({"consumer": "desktop-grant", "capabilities": "read:operator-login#password"})
                .to_string(),
            &broker.url("/v1/operator/grants/issue"),
        ])
        .output()
        .expect("run the operator request");
    assert_success("issue through the operator API", &issue);
    let issued: Value = serde_json::from_slice(&issue.stdout).unwrap();
    let bearer = issued["token"]
        .as_str()
        .expect("the operator receives the issued bearer");
    let read = || {
        let output = Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--write-out",
                "\n%{http_code}",
                "--header",
                "X-Consumer: desktop-grant",
                "--header",
                &format!("Authorization: Bearer {bearer}"),
                "--json",
                &json!({"id": "operator-login", "field": "password"}).to_string(),
                &broker.url("/v1/items/read"),
            ])
            .output()
            .expect("read through the actual grant");
        assert_success("field request transport", &output);
        let text = String::from_utf8(output.stdout).unwrap();
        let (body, status) = text.rsplit_once('\n').unwrap();
        (
            serde_json::from_str::<Value>(body).unwrap(),
            status.to_owned(),
        )
    };
    let (field, status) = read();
    assert_eq!(status, "200", "{field}");
    assert_eq!(field["value"], "grant-password");
    assert_success(
        "revoke",
        &fixture.run(&["grant", "revoke", "desktop-grant"]),
    );
    let (refusal, status) = read();
    assert_eq!(status, "403", "{refusal}");
    assert_eq!(
        refusal["error"],
        "consumer not authorized to read item field"
    );
    let vault: Value = serde_json::from_slice(&std::fs::read(&fixture.vault).unwrap()).unwrap();
    assert!(vault["tokens"].get("desktop-grant").is_none());
}
