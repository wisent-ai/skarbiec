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

/// The vault a bare `skarbiec` opens is the one Stado declares for this
/// machine, not a built-in default. On 2026-09-16 one laptop held 663 items
/// at the declared path and 661 at the default, under one owner, because
/// every service received `SKARBIEC_VAULT_FILE` from Stado and every shell
/// received nothing.
#[test]
fn a_bare_command_opens_the_vault_stado_declares() {
    let fixture = CliFixture::new("decl");
    let declared = fixture.root.join("declared").join("skarbiec.vault.json");
    let initialized = fixture.run_with_vault(
        &declared,
        &["init", "Declared vault <skarbiec-declared@example.invalid>"],
    );
    assert_success("initialize the declared vault", &initialized);
    let stado_config = fixture.root.join("stado-config.json");
    fs::write(
        &stado_config,
        serde_json::json!({
            "schema_version": 1,
            "secrets": {"skarbiec": {"vault_file": declared.display().to_string()}}
        })
        .to_string(),
    )
    .expect("write the Stado declaration");

    let status = fixture.run_unpinned(
        &[("STADO_CONFIG", stado_config.to_str().unwrap())],
        &["status"],
    );
    assert_success("status through Stado's declaration", &status);
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status is JSON");
    assert_eq!(
        report["vault"].as_str(),
        Some(declared.to_str().unwrap()),
        "a bare command must open the declared vault: {report}"
    );

    let doctor = fixture.run_unpinned(
        &[("STADO_CONFIG", stado_config.to_str().unwrap())],
        &["doctor", "--json"],
    );
    let verdict: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).expect("doctor is JSON");
    let selection = verdict["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["check"] == "selection"))
        .unwrap_or_else(|| panic!("doctor reports the selection: {verdict}"));
    assert_eq!(
        selection["resolved"].as_str(),
        Some(declared.to_str().unwrap()),
        "{selection}"
    );
    assert!(
        selection["selected_by"]
            .as_str()
            .unwrap_or_default()
            .contains("secrets.skarbiec.vault_file"),
        "the doctor names the declaration that chose the vault: {selection}"
    );

    // A pinned process still wins over the declaration.
    fixture.init("Pinned vault <skarbiec-pinned@example.invalid>");
    let pinned = fixture.run_with_env(
        &[("STADO_CONFIG", stado_config.to_str().unwrap())],
        &["status"],
    );
    let pinned: serde_json::Value = serde_json::from_slice(&pinned.stdout).expect("status is JSON");
    assert_eq!(
        pinned["vault"].as_str(),
        Some(fixture.vault.to_str().unwrap()),
        "{pinned}"
    );

    // No declaration: the documented default, and the doctor says so.
    let missing = fixture.root.join("no-such-stado-config.json");
    let fallback = fixture.run_unpinned(
        &[("STADO_CONFIG", missing.to_str().unwrap())],
        &["doctor", "--json"],
    );
    let verdict: serde_json::Value =
        serde_json::from_slice(&fallback.stdout).expect("doctor is JSON");
    let selection = verdict["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["check"] == "selection"))
        .unwrap_or_else(|| panic!("doctor reports the selection: {verdict}"));
    assert_eq!(
        selection["resolved"].as_str(),
        Some(
            fixture
                .root
                .join(".local/share/skarbiec/skarbiec.vault.json")
                .to_str()
                .unwrap()
        ),
        "{selection}"
    );
    assert_eq!(
        selection["selected_by"].as_str(),
        Some("the HOME fallback"),
        "{selection}"
    );
}
