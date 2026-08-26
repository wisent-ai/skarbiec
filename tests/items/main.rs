#[path = "../support/mod.rs"]
mod support;

use support::{assert_success, stderr, CliFixture};

fn seed_login(fixture: &CliFixture) {
    fixture.init("Skarbiec CLI test <skarbiec-cli-test@example.invalid>");
    let set = fixture.run(&[
        "set",
        "example-login",
        "--type",
        "login",
        "username=reader@example.invalid",
        "password=correct-horse-battery-staple",
    ]);
    assert_success("seed fixture item", &set);
}

#[test]
fn get_reads_one_exact_field_and_refuses_unknown_paths() {
    let fixture = CliFixture::new("items");
    seed_login(&fixture);

    let read = fixture.run(&["get", "example-login", "--field", "password"]);
    assert_success("read one exact field", &read);
    assert_eq!(
        String::from_utf8_lossy(&read.stdout),
        "correct-horse-battery-staple\n"
    );

    let unknown_field = fixture.run(&["get", "example-login", "--field", "missing"]);
    assert_eq!(unknown_field.status.code(), Some(1));
    assert_eq!(
        stderr(&unknown_field),
        "Error: item example-login has no field missing"
    );

    let unknown_item = fixture.run(&["get", "missing", "--field", "password"]);
    assert_eq!(unknown_item.status.code(), Some(1));
    assert_eq!(stderr(&unknown_item), "Error: no item: missing");

    fixture.assert_vault_exists();
}
