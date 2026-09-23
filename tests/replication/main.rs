//! A replica host runs the same single `skarbiec serve` as every other host.
//! Replication is configured on the bond itself - its serve channel, its
//! interval and the owner-only file holding its bearer - and the running
//! service pulls it. There is no `sync-daemon` process to keep alive beside
//! the service, and no standalone `capability-serve` broker either.

#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;
use support::{assert_success, stderr, Broker, CliFixture};

/// The rows of one journal operation on this fixture, read through the product.
fn journal(fixture: &CliFixture, op: &str) -> Vec<Value> {
    let output = fixture.run(&["audit-query", "--op", op]);
    assert_success("query the replica's journal", &output);
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("audit-query prints one JSON object");
    report["entries"].as_array().cloned().unwrap_or_default()
}

/// The first rows of `op` the running service journals. Each query is a real
/// product run, which is what paces this loop; a service that exits first is
/// the failure, reported with its exit status.
fn await_journal(fixture: &CliFixture, service: &mut Broker, op: &str) -> Vec<Value> {
    loop {
        let rows = journal(fixture, op);
        if !rows.is_empty() {
            return rows;
        }
        if let Some(status) = service.exited() {
            panic!("the replica's service exited ({status}) before journalling {op}");
        }
    }
}

/// A source vault holding one item, and the bearer of a `sync:pull` grant a
/// replica may pull it with.
fn source_with_one_item() -> (CliFixture, String) {
    let source = CliFixture::new("srce");
    source.init("Source <skarbiec-source@example.invalid>");
    assert_success(
        "seed the source",
        &source.run(&[
            "set",
            "replicated-item",
            "--type",
            "note",
            "value=ciphertext-only",
        ]),
    );
    let issued = source.run(&["grant", "issue", "replica", "--capabilities", "sync:pull"]);
    assert_success("issue the replica's pull grant", &issued);
    let grant: Value = serde_json::from_slice(&issued.stdout).expect("grant is JSON");
    let token = grant["token"]
        .as_str()
        .expect("a sync grant hands out a bearer")
        .to_string();
    (source, token)
}

/// The owner-only file a bond names instead of carrying its bearer.
fn bearer_file(fixture: &CliFixture, token: &str) -> String {
    let path = fixture.root.join("replica-token");
    fs::write(&path, token).expect("write the bearer file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("make the bearer file owner-only");
    path.to_str().expect("fixture path is UTF-8").to_string()
}

#[test]
fn one_serve_process_pulls_the_bond_its_vault_configures() {
    let (source, token) = source_with_one_item();
    let source_service = source.serve();

    let replica = CliFixture::new("repl");
    replica.init("Replica <skarbiec-replica@example.invalid>");
    let token_file = bearer_file(&replica, &token);
    let channel = format!("serve:{}", source_service.url(""));
    let added = replica.run(&[
        "bond-add",
        "source",
        "--mode",
        "replica",
        "--role",
        "replica",
        "--channel",
        &channel,
        "--interval",
        "3600",
        "--token-file",
        &token_file,
        "--consumer",
        "replica",
    ]);
    assert_success("configure the bond the replica pulls", &added);

    // The ordinary service arguments: nothing on this command line names the
    // bond, its bearer or its consumer.
    let mut service = replica.serve();
    await_journal(&replica, &mut service, "replication-start");
    await_journal(&replica, &mut service, "pull");
    assert!(
        service.exited().is_none(),
        "the service must keep serving after its first pull"
    );

    let listed = replica.run(&["list", "--json"]);
    assert_success("list the pulled replica", &listed);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("replicated-item"),
        "the running service installed the source's document: {}",
        String::from_utf8_lossy(&listed.stdout)
    );

    let status = replica.run(&["sync-status", "--bond", "source"]);
    assert_success("report the bond", &status);
    let status: Value = serde_json::from_slice(&status.stdout).expect("sync-status is JSON");
    let bond = &status[0];
    assert_eq!(bond["pulled_by_service"], true, "{status}");
    assert_eq!(bond["token_file_error"], Value::Null, "{status}");
    assert_eq!(
        bond["channel"]["token_file"],
        token_file.as_str(),
        "{status}"
    );
    assert_eq!(bond["channel"]["consumer"], "replica", "{status}");
    assert!(bond["last_pull_at"].is_string(), "{status}");
    assert_eq!(bond["last_items_after"], 1, "{status}");
    assert_eq!(bond["remote_items"], 1, "{status}");
}

#[test]
fn a_pulled_bond_is_refused_before_it_is_written_when_the_service_could_not_pull_it() {
    let replica = CliFixture::new("brfs");
    replica.init("Replica <skarbiec-replica@example.invalid>");
    let token_file = bearer_file(&replica, "not-a-real-bearer");
    let serve_channel = "serve:http://127.0.0.1:9";
    let cases: &[(&[&str], &str)] = &[
        (
            &[
                "--channel",
                "git:origin",
                "--interval",
                "60",
                "--token-file",
                &token_file,
            ],
            "--token-file applies only to a serve channel: only serve channels are pulled",
        ),
        (
            &["--channel", serve_channel, "--token-file", &token_file],
            "--token-file requires --interval: serve pulls a bond on the bond's own interval",
        ),
        (
            &[
                "--channel",
                serve_channel,
                "--interval",
                "60",
                "--consumer",
                "replica",
            ],
            "--consumer names who pulls and requires --token-file",
        ),
        (
            &[
                "--channel",
                serve_channel,
                "--interval",
                "60",
                "--token-file",
                "replica-token",
            ],
            "credential token file must be an absolute path",
        ),
    ];
    for (extra, sentence) in cases {
        let mut args = vec![
            "bond-add", "refused", "--mode", "replica", "--role", "replica",
        ];
        args.extend_from_slice(extra);
        let refused = replica.run(&args);
        assert!(!refused.status.success(), "{args:?} must be refused");
        assert!(
            stderr(&refused).contains(sentence),
            "{args:?} must say `{sentence}`, said: {}",
            stderr(&refused)
        );
    }
    let bonds = replica.run(&["bond-list"]);
    assert_success("list bonds after the refusals", &bonds);
    let bonds: Value = serde_json::from_slice(&bonds.stdout).expect("bond-list is JSON");
    assert!(
        bonds.get("refused").is_none(),
        "a refused bond must not be written: {bonds}"
    );
}

#[test]
fn the_standalone_daemons_are_gone() {
    let fixture = CliFixture::new("gone");
    fixture.init("Removed daemons <skarbiec-removed@example.invalid>");
    for command in ["sync-daemon", "capability-serve"] {
        let refused = fixture.run(&[command]);
        assert!(!refused.status.success(), "{command} must not run");
        assert!(
            stderr(&refused).contains(&format!("unknown command: {command}")),
            "{command}: {}",
            stderr(&refused)
        );
    }
    let help = fixture.run(&["help"]);
    assert_success("print the advertised surface", &help);
    let help: Value = serde_json::from_slice(&help.stdout).expect("help is JSON");
    let commands = help["commands"].as_array().expect("help lists commands");
    for command in ["sync-daemon", "capability-serve"] {
        assert!(
            !commands.iter().any(|listed| listed == command),
            "{command} is still advertised: {help}"
        );
    }
}
