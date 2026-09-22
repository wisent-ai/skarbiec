use super::{request_credential, CliFixture};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::Command;

#[test]
fn http_and_capability_requests_share_the_service_process() {
    let fixture = CliFixture::new("service");
    fixture.init("Service Test <service@test.local>");
    let socket = fixture.root.join("cap.sock");
    let socket_text = socket.to_str().expect("fixture socket path is UTF-8");
    let broker = fixture.serve_with_env(&[("SKARBIEC_CAP_SOCKET", socket_text)]);

    // Completing HTTP, rather than only connecting to TCP, also proves that
    // startup finished binding all configured component listeners.
    request_credential(
        &broker,
        "set",
        "shared-service",
        r#""username":"operator","password":"persisted-secret""#,
    );
    let stored = fixture.run(&["get", "shared-service", "--field", "password"]);
    assert!(
        stored.status.success(),
        "{}",
        String::from_utf8_lossy(&stored.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&stored.stdout).trim(),
        "persisted-secret"
    );

    let status = fixture.run(&["capability-status", "--socket", socket_text]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("broker status JSON");
    assert_eq!(status["status"], "listening");
    assert_eq!(status["pid"], broker.pid());

    let different_state = fixture.root.join("different-capabilities.json");
    let mismatch = fixture.run_with_env(
        &[(
            "SKARBIEC_CAPABILITY_FILE",
            different_state.to_str().unwrap(),
        )],
        &["capability-status", "--socket", socket_text],
    );
    assert!(!mismatch.status.success());
    let diagnostic = String::from_utf8_lossy(&mismatch.stderr);
    assert!(
        diagnostic.contains("different state paths")
            && diagnostic.contains(different_state.to_str().unwrap()),
        "{diagnostic}"
    );
    assert!(
        !different_state.exists(),
        "inspection must not create replacement state"
    );

    let mut stream = UnixStream::connect(&socket).expect("connect to capability listener");
    stream.write_all(b"{}\n").expect("send malformed request");
    stream.shutdown(Shutdown::Write).expect("finish request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read refusal");
    let response: serde_json::Value = serde_json::from_str(&response).expect("JSON refusal");
    assert_eq!(response["status"], "denied");

    let descriptors = Command::new("lsof")
        .args(["-a", "-p", &broker.pid().to_string(), "-U", "-Fn"])
        .output()
        .expect("inspect real service socket ownership");
    assert!(
        descriptors.status.success(),
        "{}",
        String::from_utf8_lossy(&descriptors.stderr)
    );
    let owned = String::from_utf8_lossy(&descriptors.stdout);
    assert!(
        owned
            .lines()
            .any(|line| line.strip_prefix('n') == Some(socket_text)),
        "HTTP process does not own the capability socket: {owned}"
    );
}

fn capability_owner(fixture: &CliFixture, socket: &std::path::Path) -> u64 {
    let socket = socket.to_str().expect("fixture socket path");
    let output = fixture.run(&["capability-status", "--socket", socket]);
    eprintln!(
        "capability-status --socket {socket}: exit={:?}\n{}\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.status.success(), "broker status failed");
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("broker status");
    response["pid"].as_u64().expect("actual broker PID")
}

#[test]
fn atomic_socket_alias_handoff_reaches_the_new_broker_without_a_proxy() {
    let mut fixture = CliFixture::new("handoff");
    fixture.init("Socket Handoff <handoff@test.local>");
    let first_socket = fixture.root.join("first.sock");
    let second_socket = fixture.root.join("second.sock");
    let stable = fixture.root.join("stable.sock");
    let staged = fixture.root.join("staged.sock");
    let first = fixture.serve_with_env(&[("SKARBIEC_CAP_SOCKET", first_socket.to_str().unwrap())]);
    request_credential(&first, "set", "handoff", r#""password":"shared-state""#);
    assert_eq!(
        capability_owner(&fixture, &first_socket),
        u64::from(first.pid())
    );
    std::fs::hard_link(&first_socket, &stable).expect("publish the original native socket alias");
    assert_eq!(capability_owner(&fixture, &stable), u64::from(first.pid()));

    let reservation =
        std::net::TcpListener::bind("127.0.0.1:0").expect("independent candidate port");
    fixture.port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let second =
        fixture.serve_with_env(&[("SKARBIEC_CAP_SOCKET", second_socket.to_str().unwrap())]);
    let response = request_credential(&second, "get", "handoff", r#""field":"password""#);
    assert!(response.contains("shared-state"), "{response}");
    assert_eq!(
        capability_owner(&fixture, &second_socket),
        u64::from(second.pid())
    );
    std::fs::hard_link(&second_socket, &staged).expect("stage the replacement native socket");
    std::fs::rename(&staged, &stable).expect("atomically switch the public socket");
    assert_eq!(capability_owner(&fixture, &stable), u64::from(second.pid()));
    assert_eq!(
        capability_owner(&fixture, &first_socket),
        u64::from(first.pid())
    );
    drop(first);
    assert_eq!(capability_owner(&fixture, &stable), u64::from(second.pid()));
    let response = request_credential(&second, "get", "handoff", r#""field":"password""#);
    assert!(response.contains("shared-state"), "{response}");
}
