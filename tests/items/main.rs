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

/// Brama records which provider account a subscription credential belongs to
/// as `brama:account:<address>`, read from the address the provider signed
/// into the grant. The write is refused unless the namespace is registered,
/// and it was not: every such write came back with `tag
/// `brama:account:<address>` claims a namespace that is not registered`, so
/// a pool could attribute none of its members to an account.
#[test]
fn the_account_namespace_is_writable_and_unregistered_ones_are_not() {
    let fixture = CliFixture::new("items-account-tag");
    seed_login(&fixture);

    let accounted = fixture.run(&[
        "retag",
        "example-login",
        "--tags",
        "brama:subscription,brama:provider:codex,brama:account:reader@example.invalid",
    ]);
    assert_success("record the account a credential belongs to", &accounted);

    let listed = fixture.run(&["list"]);
    assert_success("read the item's tags back", &listed);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("brama:account:reader@example.invalid"),
        "the recorded account survives the write: {}",
        String::from_utf8_lossy(&listed.stdout)
    );

    let unregistered = fixture.run(&["retag", "example-login", "--tags", "brama:owner:nobody"]);
    assert_eq!(unregistered.status.code(), Some(1));
    assert!(
        stderr(&unregistered).contains("claims a namespace that is not registered")
            && stderr(&unregistered).contains("brama:account:<account>"),
        "an unregistered namespace is refused and the registered ones are named: {}",
        stderr(&unregistered)
    );
}
