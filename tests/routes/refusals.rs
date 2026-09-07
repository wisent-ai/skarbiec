//! Every refusal this capability answers with, in its literal sentence.
//!
//! A refusal that will not say what it refused is what let a gateway record
//! `capability_issue_refused` with an empty detail for a month, so each of
//! these is pinned to the exact words a caller reads.

use crate::support::{assert_success, stderr};
use crate::{answer, fixture, HAND_RESOURCE, LOGIN_ITEM, PROVIDER_ITEM};

#[test]
fn every_refusal_says_exactly_what_it_refused() {
    let fixture = fixture();
    let login_of_a_provider = format!("login:{PROVIDER_ITEM}");
    let refusals: Vec<(Vec<&str>, String)> = vec![
        (
            vec!["route", "bogus"],
            "Error: unknown route command: bogus".to_string(),
        ),
        (
            vec!["route", "resolve", "provider:absent"],
            "Error: nothing declares provider:absent and no capability route names it".to_string(),
        ),
        (
            vec!["route", "resolve", &login_of_a_provider],
            format!(
                "Error: vault item {PROVIDER_ITEM} declares kind api-key, not login: only a login declares the fields a sign-in exports"
            ),
        ),
        (
            vec!["route", "resolve", "provider:openai", "--consumer", "nobody"],
            "Error: --token required with --consumer".to_string(),
        ),
        (
            vec!["route", "resolve", "--template", "/nonexistent/template.env"],
            "Error: route resolve --template requires --out".to_string(),
        ),
        (
            vec![
                "route",
                "declare",
                "--resource",
                "provider:openai",
                "--item",
                PROVIDER_ITEM,
                "--field",
                "api_key",
                "--reason",
                "test: refused because the item declares it",
            ],
            "Error: provider:openai is resolved from what an item declares, not from the table: tag the item instead".to_string(),
        ),
        (
            vec![
                "route",
                "declare",
                "--resource",
                HAND_RESOURCE,
                "--item",
                LOGIN_ITEM,
                "--field",
                "password",
            ],
            "Error: route declare requires an exact --reason".to_string(),
        ),
    ];

    for (args, expected) in refusals {
        let output = fixture.run(&args);
        assert!(
            !output.status.success(),
            "skarbiec {} must refuse",
            args.join(" ")
        );
        assert_eq!(stderr(&output), expected, "skarbiec {}", args.join(" "));
    }
}

#[test]
fn repointing_a_hand_declared_route_is_refused_rather_than_moved() {
    let fixture = fixture();
    assert_success(
        "state one hand-declared route",
        &fixture.run(&[
            "route",
            "declare",
            "--resource",
            HAND_RESOURCE,
            "--item",
            LOGIN_ITEM,
            "--field",
            "password",
            "--reason",
            "test: the row this refusal protects",
        ]),
    );

    let output = fixture.run(&[
        "route",
        "declare",
        "--resource",
        HAND_RESOURCE,
        "--item",
        PROVIDER_ITEM,
        "--field",
        "api_key",
        "--reason",
        "test: repointing a live route",
    ]);
    assert!(!output.status.success(), "a repoint must refuse");
    assert_eq!(
        stderr(&output),
        format!(
            "Error: capability route {HAND_RESOURCE} already maps {LOGIN_ITEM}#password: repointing a live route is not a declaration"
        )
    );
}

/// A field that exists and holds a placeholder is not a usable credential.
///
/// This story arrived with `routes verify` and moved here with it: the item is
/// found by its declaration now, so no row has to be written to ask the
/// question at all.
#[test]
fn verification_refuses_a_placeholder_credential_until_it_is_replaced() {
    let fixture = fixture();
    assert_success(
        "declare a provider whose secret is still a placeholder",
        &fixture.run(&[
            "set",
            "placeholder-provider",
            "--type",
            "api-key",
            "--tags=brama:provider:placeholder",
            "api_key=PROVIDER_API_KEY",
        ]),
    );

    let refused = fixture.run(&["route", "verify", "provider:placeholder"]);
    assert!(!refused.status.success(), "a placeholder must refuse");
    assert_eq!(
        stderr(&refused),
        "Error: 1 of 1 capability routes do not resolve: provider:placeholder: vault item placeholder-provider field api_key contains an uppercase placeholder, not a usable credential"
    );

    assert_success(
        "replace the placeholder with a real secret",
        &fixture.run(&[
            "set",
            "placeholder-provider",
            "--type",
            "api-key",
            "api_key=real-provider-secret",
        ]),
    );
    let report = answer(&fixture, &["route", "verify", "provider:placeholder"]);
    assert_eq!(report["checked"], 1);
    assert_eq!(report["broken"], serde_json::json!([]));
}

#[test]
fn two_items_declaring_one_provider_are_refused_rather_than_chosen_between() {
    let fixture = fixture();
    assert_success(
        "seed a second credential declaring the same provider",
        &fixture.run(&[
            "set",
            "demo-openai-second",
            "--type",
            "api-key",
            "--tags=brama:provider:openai",
            "api_key=second-openai-value",
        ]),
    );

    let output = fixture.run(&["route", "resolve", "provider:openai"]);
    assert!(
        !output.status.success(),
        "an ambiguous provider must refuse"
    );
    assert_eq!(
        stderr(&output),
        format!(
            "Error: 2 vault items declare provider:openai: demo-openai-second, {PROVIDER_ITEM}"
        )
    );
}

#[test]
fn the_six_replaced_verbs_are_gone_from_the_binary() {
    let fixture = fixture();

    let advertised = answer(&fixture, &["help"]);
    let commands = advertised["commands"].as_array().expect("advertised list");
    for gone in ["routes", "resolve", "expand"] {
        assert!(
            !commands.iter().any(|command| command == gone),
            "{gone} is still advertised"
        );
    }
    assert!(commands.iter().any(|command| command == "route"));

    for (verb, expected) in [
        ("routes", "Error: unknown command: routes"),
        ("resolve", "Error: unknown command: resolve"),
        ("expand", "Error: unknown command: expand"),
    ] {
        let output = fixture.run(&[verb]);
        assert!(!output.status.success(), "{verb} still answers");
        assert_eq!(stderr(&output), expected);
    }
}
