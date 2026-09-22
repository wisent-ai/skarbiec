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
