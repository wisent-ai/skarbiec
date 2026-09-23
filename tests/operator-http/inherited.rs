//! The ports retired units answered on, across restarts of the one process.

use super::CliFixture;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};

/// The label launchd starts the one Skarbiec process under.
const DECLARED_UNIT: &str = "com.wisent.always-on.skarbiec";

/// Started as its declared unit, the one process answers on every port a
/// retired unit answered on: on a host the previous release converged, the
/// ports its journal names; once they are kept beside the vault, on every
/// later start, whatever the journal holds. A hand-run serve binds only its
/// own port.
#[test]
fn the_declared_unit_answers_on_its_predecessors_ports_after_a_restart() {
    let fixture = CliFixture::new("ports");
    fixture.init("Ports Test <ports@test.local>");
    let inherited = free_port();
    // What the previous release journaled when it retired the keychain unit.
    let journal = fixture.root.join("audit.jsonl");
    let mut lines = OpenOptions::new()
        .append(true)
        .open(&journal)
        .expect("open the fixture's journal");
    writeln!(
        lines,
        r#"{{"at":"2026-09-23T10:40:51Z","extra":{{"ports":[{inherited}],"unit":"com.wisent.skarbiec"}},"hash":"retired","op":"unit-retired","prev":"retired"}}"#
    )
    .expect("journal the retired unit");
    drop(lines);

    let declared = [("XPC_SERVICE_NAME", DECLARED_UNIT)];
    let first = fixture.serve_with_env(&declared);
    assert_serves(inherited, "the journal named it");
    let record = fixture.root.join("vault.json.inherited-ports.json");
    let kept: Vec<u16> = serde_json::from_slice(
        &std::fs::read(&record).expect("the inherited ports are kept beside the vault"),
    )
    .expect("the record is a JSON list of ports");
    assert_eq!(kept, [inherited]);
    drop(first);

    std::fs::remove_file(&journal).expect("drop the journal that named the port");
    let restarted = fixture.serve_with_env(&declared);
    assert_serves(inherited, "only the record beside the vault names it");
    drop(restarted);

    let by_hand = fixture.serve();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, inherited)).is_err(),
        "a serve run by hand answered on a retired unit's port"
    );
    drop(by_hand);
}

/// A port nothing listens on, from the kernel.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .expect("reserve a port")
        .port()
}

fn assert_serves(port: u16, why: &str) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .unwrap_or_else(|error| panic!("nothing answers on {port} although {why}: {error}"));
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("send a health request");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    assert!(
        answer.contains("\"service\":\"skarbiec\""),
        "{port} did not answer as Skarbiec although {why}: {answer:?}"
    );
}
