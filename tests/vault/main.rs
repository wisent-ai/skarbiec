#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use support::{assert_success, CliFixture};

#[test]
fn init_creates_a_private_parent_and_persists_the_vault() {
    let mut fixture = CliFixture::new("vault");
    fixture.vault = fixture.root.join("fresh").join("vault.json");

    let initialized = fixture.run(&[
        "init",
        "Skarbiec vault test <skarbiec-vault-test@example.invalid>",
    ]);
    assert_success("initialize a vault below a missing parent", &initialized);

    let parent = fixture.vault.parent().expect("vault parent");
    assert!(fixture.vault.is_file(), "vault was not persisted");
    assert_eq!(
        fs::metadata(parent)
            .expect("vault parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}
