//! What a grant may declare, what the vault keeps of it, and how it is
//! edited or withdrawn.

use std::fs;


use crate::fixture::{fixture, mint, vault_tokens, CONSUMER, ITEM};
use crate::support::{assert_success, stderr};

#[test]
fn grant_issue_shows_the_grant_once_and_stores_only_its_hash() {
    let fixture = fixture();

    let response = mint(&fixture, "read:brama-router#api_key");
    assert_eq!(response["ok"], true);
    assert_eq!(response["consumer"], CONSUMER);
    assert_eq!(response["workload_bound"], false);
    assert_eq!(response["capabilities"][0]["action"], "read");
    assert_eq!(response["capabilities"][0]["item"], ITEM);
    assert_eq!(response["capabilities"][0]["field"], "api_key");

    let token = response["token"].as_str().expect("grant value shown once");
    assert_eq!(token.len(), 64, "grant is one 64-hex bearer");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

    // The vault retains the consumer's capability row and a hash — never the
    // grant value itself.
    let stored = vault_tokens(&fixture);
    let row = &stored[CONSUMER];
    assert_eq!(row["capabilities"][0]["item"], ITEM);
    let hash = row["hash"].as_str().expect("stored grant hash");
    assert_ne!(hash, token, "vault must not retain the presented grant");
    let vault_bytes = fs::read_to_string(&fixture.vault).expect("read vault state");
    assert!(
        !vault_bytes.contains(token),
        "grant value must not appear anywhere in the vault file"
    );

    // The listing repeats scope metadata and never a grant value.
    let output = fixture.run(&["grant", "list"]);
    assert_success("list consumers", &output);
    let listing = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(listing.contains(CONSUMER));
    assert!(!listing.contains(token));
    assert!(!listing.contains("\"token\""));
}

#[test]
fn grant_issue_refuses_inexact_unknown_or_dangling_capabilities() {
    let fixture = fixture();

    let cases: &[(&[&str], &str)] = &[
        (&["grant", "issue", CONSUMER], "--capabilities is required"),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "steal:brama-router#api_key",
            ],
            "unsupported capability action: steal",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "read:brama-*#api_key",
            ],
            "capabilities require exact resource and field names without globs",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "acquire:brama-router",
            ],
            "acquire capability requires one exact field",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "read:brama-router#api_key,read:brama-router#api_key",
            ],
            "duplicate capability: read:brama-router#api_key",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "read:niema#api_key",
            ],
            "capability names a missing item: niema",
        ),
        (
            &[
                "grant",
                "issue",
                CONSUMER,
                "--capabilities",
                "read:brama-router#niema",
            ],
            "capability names a missing field: brama-router#niema",
        ),
    ];

    for (args, sentence) in cases {
        let output = fixture.run(args);
        assert!(
            !output.status.success(),
            "refusal case unexpectedly succeeded: {args:?}"
        );
        let message = stderr(&output);
        assert!(
            message.contains(sentence),
            "refusal for {args:?} must say {sentence:?}, said {message:?}"
        );
    }

    // No refusal may leave a grant behind: the consumer never appears in the
    // vault's token map, whether that map is absent or empty.
    let stored = vault_tokens(&fixture);
    assert!(
        stored.is_null() || stored.as_object().is_some_and(|map| map.is_empty()),
        "refusals must not persist grants, vault kept {stored}"
    );
}

#[test]
fn grant_issue_refuses_grants_that_mix_incompatible_actions() {
    let fixture = fixture();

    // Driving a credential lifecycle never authorizes reading the value.
    let output = fixture.run(&[
        "grant",
        "issue",
        "mixer",
        "--capabilities",
        "read:brama-router#api_key,lifecycle:brama-router",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output)
        .contains("lifecycle capabilities cannot share a grant with read capabilities"));

    // One-use acquisition and standing direct access never share one bearer.
    let output = fixture.run(&[
        "grant",
        "issue",
        "mixer",
        "--capabilities",
        "acquire:brama-router#api_key,read:brama-router#username",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output)
        .contains("acquire capabilities cannot share a grant with direct capabilities"));
}
