//! Declared route resolution, driven against the real binary and a real vault.
//!
//! The story these defend is one defect: resolution used to read meaning out of
//! an item id, so renaming an item changed which credential a name reached with
//! nothing raised anywhere. Each test drives `CARGO_BIN_EXE_skarbiec` against an
//! isolated vault and asserts the answer a consumer observes.

/// The refusals, in their own file: this area's stories and its refusal
/// sentences are read for different reasons, and each file stays inside the
/// repository's per-file line budget.
mod refusals;
#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;
use support::{assert_success, stderr, CliFixture};

const PROVIDER_ITEM: &str = "demo-openai-subscription";
const AGENT_ITEM: &str = "demo-agent-identity";
const LOGIN_ITEM: &str = "platform-admin-demo";
const HAND_RESOURCE: &str = "origin:https://dash.demo.invalid/password";

fn fixture() -> CliFixture {
    let fixture = CliFixture::new("routes");
    fixture.init("Skarbiec route test <skarbiec-route-test@example.invalid>");
    assert_success(
        "seed one declared provider credential",
        &fixture.run(&[
            "set",
            PROVIDER_ITEM,
            "--type",
            "api-key",
            "--tags=brama:subscription,brama:provider:openai,brama:id:sub-one",
            "api_key=live-openai-value",
        ]),
    );
    assert_success(
        "seed one declared agent signing identity",
        &fixture.run(&[
            "set",
            AGENT_ITEM,
            "--type",
            "internal-authority",
            "id=demo-agent",
            "agent_auth_secret=agent-signing-secret",
        ]),
    );
    assert_success(
        "seed one login item",
        &fixture.run(&[
            "set",
            LOGIN_ITEM,
            "--type",
            "login",
            "username=demo@example.invalid",
            "password=demo-password",
            "totp_secret=JBSWY3DPEHPK3PXP",
        ]),
    );
    fixture
}

fn answer(fixture: &CliFixture, args: &[&str]) -> Value {
    let output = fixture.run(args);
    assert_success(&format!("run skarbiec {}", args.join(" ")), &output);
    serde_json::from_slice(&output.stdout).expect("parse route answer")
}

fn route<'a>(document: &'a Value, resource: &str, field: &str) -> &'a Value {
    document["routes"]
        .as_array()
        .expect("routes array")
        .iter()
        .find(|row| row["resource"] == resource && row["field"] == field)
        .unwrap_or_else(|| panic!("no row for {resource}#{field} in {document}"))
}

#[test]
fn a_declared_route_resolves_to_the_item_and_field_the_declaration_names() {
    let fixture = fixture();

    let subscription = answer(&fixture, &["route", "resolve", "provider:openai:sub-one"]);
    let row = route(&subscription, "provider:openai:sub-one", "api_key");
    assert_eq!(row["item"], PROVIDER_ITEM);
    assert_eq!(row["declared_by"], "tags");
    assert_eq!(row["item_present"], true);
    assert_eq!(row["field_present"], true);

    // The provider family resolves to the same credential, because exactly one
    // item declares that provider. Nothing here is decided by a `-primary`
    // suffix on an id.
    let family = answer(&fixture, &["route", "resolve", "provider:openai"]);
    assert_eq!(
        route(&family, "provider:openai", "api_key")["item"],
        PROVIDER_ITEM
    );

    // An agent signing identity is answered by the item's own fields.
    let agent = answer(&fixture, &["route", "resolve", "agent:demo-agent"]);
    let row = route(&agent, "agent:demo-agent", "agent_auth_secret");
    assert_eq!(row["item"], AGENT_ITEM);
    assert_eq!(row["declared_by"], "fields");
    assert_eq!(row["field_present"], true);

    // Resolution wrote nothing: the declaration is the source, so no table is
    // needed for either name.
    let table = fixture.root.join("capability-routes.json");
    assert!(
        !table.exists(),
        "resolution must not write a route table: {}",
        table.display()
    );
}

#[test]
fn a_renamed_item_is_still_found_through_its_declaration() {
    let fixture = fixture();

    let before = answer(&fixture, &["route", "resolve", "provider:openai:sub-one"]);
    assert_eq!(
        route(&before, "provider:openai:sub-one", "api_key")["item"],
        PROVIDER_ITEM
    );
    assert_success(
        "rename the declared credential",
        &fixture.run(&["rename", PROVIDER_ITEM, "openai-renamed-by-hand"]),
    );

    let after = answer(&fixture, &["route", "resolve", "provider:openai:sub-one"]);
    let row = route(&after, "provider:openai:sub-one", "api_key");
    assert_eq!(row["item"], "openai-renamed-by-hand");
    assert_eq!(row["declared_by"], "tags");
    assert_eq!(row["field_present"], true);

    // And the whole surface still verifies: the predecessor reported this exact
    // state as two broken routes and could not repair them.
    let report = answer(&fixture, &["route", "verify"]);
    assert_eq!(report["broken"].as_array().expect("broken array").len(), 0);

    // The capability the gateway asks for is issued against the renamed item.
    let issued = answer(
        &fixture,
        &[
            "grant",
            "capability",
            "--agent",
            "demo-gateway",
            "--purpose",
            "route-test",
            "--resource",
            "provider:openai",
            "--target",
            "demo-host",
        ],
    );
    assert_eq!(issued["status"], "issued");
}

#[test]
fn a_login_resolves_to_the_fields_its_kind_declares_and_emits_them_owner_only() {
    let fixture = fixture();
    let directory = fixture.root.join("resolved");

    let name = format!("login:{LOGIN_ITEM}");
    let document = answer(
        &fixture,
        &[
            "route",
            "resolve",
            &name,
            "--emit",
            "--out",
            directory.to_str().expect("fixture path is utf-8"),
        ],
    );
    let row = route(&document, &name, "password");
    assert_eq!(row["item"], LOGIN_ITEM);
    assert_eq!(row["declared_by"], "kind");
    assert_eq!(row["exported"], "ADMIN_PASSWORD");
    assert_eq!(document["emitted"]["status"], "ready");

    let file = directory.join(format!("{LOGIN_ITEM}.env"));
    let body = fs::read_to_string(&file).expect("read emitted environment file");
    assert!(
        body.contains("ADMIN_EMAIL='demo@example.invalid'"),
        "{body}"
    );
    assert!(body.contains("ADMIN_PASSWORD='demo-password'"), "{body}");
    assert!(body.contains("ADMIN_TOTP='JBSWY3DPEHPK3PXP'"), "{body}");
    let mode = fs::metadata(&file)
        .expect("stat emitted file")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "an emitted credential file is owner-only");

    // The answer names variables and files, never a value.
    let printed = serde_json::to_string(&document).expect("serialize answer");
    assert!(!printed.contains("demo-password"), "{printed}");
}

#[test]
fn a_hand_declared_route_is_stated_once_and_reports_a_rename_by_name() {
    let fixture = fixture();

    let declared = answer(
        &fixture,
        &[
            "route",
            "declare",
            "--resource",
            HAND_RESOURCE,
            "--item",
            LOGIN_ITEM,
            "--field",
            "password",
            "--reason",
            "test: a sign-in form no item can declare",
        ],
    );
    assert_eq!(declared["declared"], true);
    assert_eq!(declared["item"], LOGIN_ITEM);

    let resolved = answer(&fixture, &["route", "resolve", HAND_RESOURCE]);
    let row = route(&resolved, HAND_RESOURCE, "password");
    assert_eq!(row["declared_by"], "table");
    assert_eq!(row["field_present"], true);

    // Restating exactly the same row writes nothing.
    let again = answer(
        &fixture,
        &[
            "route",
            "declare",
            "--resource",
            HAND_RESOURCE,
            "--item",
            LOGIN_ITEM,
            "--field",
            "password",
            "--reason",
            "test: idempotent restatement",
        ],
    );
    assert_eq!(again["declared"], false);

    // An exact-id row is the loud pattern: renaming the item fails verification
    // and names where the item went.
    assert_success(
        "rename the hand-declared item",
        &fixture.run(&["rename", LOGIN_ITEM, "platform-admin-demo-renamed"]),
    );
    let output = fixture.run(&["route", "verify"]);
    assert!(!output.status.success(), "verification must refuse");
    assert_eq!(
        stderr(&output),
        format!(
            "Error: 1 of 4 capability routes do not resolve: {HAND_RESOURCE}: vault item {LOGIN_ITEM} was renamed to platform-admin-demo-renamed"
        )
    );
}
