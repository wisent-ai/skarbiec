//! An install that replaces the executable the one process runs.

use super::CliFixture;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::Path;

/// The label launchd starts the one Skarbiec process under.
const DECLARED_UNIT: &str = "com.wisent.always-on.skarbiec";

/// Started as its declared unit from an installed copy, the one process
/// serves until an install renames a new file over that copy; the next
/// connection it accepts ends it, with the replacement journaled, so launchd
/// starts the installed release. A serve run by hand keeps serving.
#[test]
fn the_declared_unit_ends_when_an_install_replaces_its_executable() {
    let fixture = CliFixture::new("image");
    fixture.init("Image Test <image@test.local>");
    let installed = fixture.root.join("bin").join("skarbiec");
    std::fs::create_dir_all(
        installed
            .parent()
            .expect("an installed path has a directory"),
    )
    .expect("create the install directory");
    std::fs::copy(env!("CARGO_BIN_EXE_skarbiec"), &installed).expect("install the built binary");

    let mut declared = fixture.serve_program(&installed, &[("XPC_SERVICE_NAME", DECLARED_UNIT)]);
    assert!(
        health(declared.port()).contains("\"service\":\"skarbiec\""),
        "the installed image did not serve"
    );
    install_over(&installed);
    let answer = health(declared.port());
    assert!(
        !answer.contains("\"service\":\"skarbiec\""),
        "the replaced image still answered: {answer:?}"
    );
    let status = declared.wait();
    assert!(
        !status.success(),
        "ending on a replaced image must not read as a clean stop: {status}"
    );
    let journal =
        std::fs::read_to_string(fixture.root.join("audit.jsonl")).expect("read the journal");
    assert!(
        journal.contains("\"op\":\"serve-replaced\""),
        "the replacement was not journaled"
    );
    drop(declared);

    let by_hand = fixture.serve_program(&installed, &[]);
    install_over(&installed);
    assert!(
        health(by_hand.port()).contains("\"service\":\"skarbiec\""),
        "a serve run by hand stopped when its file was replaced"
    );
}

/// Replace `installed` the way an installer does: a new file renamed over it.
fn install_over(installed: &Path) {
    let staged = installed.with_extension("staged");
    std::fs::copy(env!("CARGO_BIN_EXE_skarbiec"), &staged).expect("stage the new release");
    std::fs::rename(&staged, installed).expect("rename the new release over the installed one");
}

/// What one health request on `port` answers; empty when nothing answers.
fn health(port: u16) -> String {
    let Ok(mut stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) else {
        return String::new();
    };
    let _ =
        stream.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
}
