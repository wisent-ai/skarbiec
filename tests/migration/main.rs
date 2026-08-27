#[path = "../support/mod.rs"]
mod support;

use support::{assert_success, stderr, CliFixture};

#[test]
fn migrate_copies_live_items_preserves_destination_and_force_overwrites() {
    let fixture = CliFixture::new("migration");
    let source = fixture.root.join("source.json");
    let destination = fixture.root.join("destination.json");
    let owner = "Skarbiec migration test <skarbiec-migration-test@example.invalid>";

    assert_success(
        "initialize source",
        &fixture.run_with_vault(&source, &["init", owner]),
    );
    assert_success(
        "store source item",
        &fixture.run_with_vault(
            &source,
            &["set", "shared", "--type", "note", "value=from-source"],
        ),
    );
    assert_success(
        "store source-only item",
        &fixture.run_with_vault(
            &source,
            &["set", "source-only", "--type", "note", "value=copy-me"],
        ),
    );

    assert_success(
        "initialize destination",
        &fixture.run_with_vault(&destination, &["init", owner]),
    );
    assert_success(
        "store destination item",
        &fixture.run_with_vault(
            &destination,
            &["set", "shared", "--type", "note", "value=keep-me"],
        ),
    );

    let from = source.to_str().expect("source path is utf-8");
    let to = destination.to_str().expect("destination path is utf-8");
    let migrated = fixture.run(&["migrate", "--from", from, "--to", to]);
    assert_success("migrate without force", &migrated);

    let preserved = fixture.run_with_vault(&destination, &["get", "shared", "--field", "value"]);
    assert_success("read preserved destination item", &preserved);
    assert_eq!(String::from_utf8_lossy(&preserved.stdout), "keep-me\n");
    let copied = fixture.run_with_vault(&destination, &["get", "source-only", "--field", "value"]);
    assert_success("read copied source item", &copied);
    assert_eq!(String::from_utf8_lossy(&copied.stdout), "copy-me\n");

    let forced = fixture.run(&["migrate", "--from", from, "--to", to, "--force"]);
    assert_success("force migration", &forced);
    let overwritten = fixture.run_with_vault(&destination, &["get", "shared", "--field", "value"]);
    assert_success("read overwritten destination item", &overwritten);
    assert_eq!(
        String::from_utf8_lossy(&overwritten.stdout),
        "from-source\n"
    );

    let missing = fixture.run(&[
        "migrate",
        "--from",
        fixture
            .root
            .join("missing.json")
            .to_str()
            .expect("missing path is utf-8"),
        "--to",
        to,
    ]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(stderr(&missing).contains("missing.json"));
}
