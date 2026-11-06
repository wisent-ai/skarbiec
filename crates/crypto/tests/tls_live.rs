//! The TLS 1.3 client against a real TLS 1.3 server: `openssl s_server`
//! serving the chains tests/vectors/x509/make.sh made, once per cipher suite
//! and with an ECDSA (P-384) and an RSA-PSS server key. Each connection
//! asks s_server's -www page over the channel and reads it back, so every
//! step — hello, keys, chain, CertificateVerify, both Finished, application
//! records both ways — is exercised by another implementation. A host the
//! certificate does not name and an untrusted root are refused.

use skarbiec_crypto::tls::handshake::{connect, TlsError};
use skarbiec_crypto::x509::Anchor;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/x509")
}

fn anchor(name: &str) -> Anchor {
    let path = fixtures().join(format!("{name}.der"));
    Anchor::from_der(&std::fs::read(&path).expect("fixture")).expect(name)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs() as i64
}

/// A PEM copy of a DER fixture, which s_server's -cert_chain takes.
fn pem(name: &str) -> PathBuf {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.pem"));
    let status = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in"])
        .arg(fixtures().join(format!("{name}.der")))
        .arg("-out")
        .arg(&out)
        .status()
        .expect("this test needs openssl on PATH, to run the TLS 1.3 server the client talks to");
    assert!(status.success(), "openssl could not convert {name}");
    out
}

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.child.kill().is_ok() {
            self.child.wait().expect("s_server ends");
        }
    }
}

/// s_server on a free loopback port, serving `leaf` (with `chain`) under
/// one `suite`, once it says it accepts.
fn serve(leaf: &str, chain: Option<&str>, suite: &str) -> Server {
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free loopback port")
        .port();
    let mut command = Command::new("openssl");
    command
        .args(["s_server", "-tls1_3", "-www", "-certform", "DER", "-cert"])
        .arg(fixtures().join(format!("{leaf}.der")))
        .arg("-key")
        .arg(fixtures().join(format!("{leaf}.key.pem")))
        .args(["-ciphersuites", suite, "-accept"])
        .arg(format!("127.0.0.1:{port}"));
    if let Some(chain) = chain {
        command.arg("-cert_chain").arg(pem(chain));
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("this test needs openssl on PATH, to run the TLS 1.3 server the client talks to");
    let stdout = child.stdout.take().expect("piped");
    let mut lines = BufReader::new(stdout).lines();
    loop {
        match lines.next() {
            Some(Ok(line)) if line.starts_with("ACCEPT") => break,
            Some(Ok(_)) => continue,
            other => panic!("s_server ended before it accepted: {other:?}"),
        }
    }
    // Keep draining what s_server prints, so it never blocks on a full pipe.
    std::thread::spawn(move || lines.for_each(drop));
    Server { child, port }
}

fn fetch(server: &Server, host: &str, anchors: &[Anchor]) -> Result<(String, String), TlsError> {
    let stream = TcpStream::connect(("127.0.0.1", server.port))?;
    let mut connection = connect(stream, host, anchors, now(), &[])?;
    connection.send(b"GET / HTTP/1.0\r\n\r\n")?;
    let mut page = Vec::new();
    while !String::from_utf8_lossy(&page).contains("</HTML>") {
        let chunk = connection.receive()?;
        if chunk.is_empty() {
            break;
        }
        page.extend_from_slice(&chunk);
    }
    Ok((
        connection.suite.to_string(),
        String::from_utf8_lossy(&page).into_owned(),
    ))
}

#[test]
fn every_suite_against_openssl_with_an_ecdsa_key() {
    let anchors = [anchor("root-rsa")];
    for suite in [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ] {
        let server = serve("leaf-p384", Some("inter-p256"), suite);
        let (chosen, page) = fetch(&server, "host.test", &anchors)
            .unwrap_or_else(|error| panic!("{suite}: {error}"));
        assert_eq!(chosen, suite);
        assert!(page.starts_with("HTTP/1.0 200 ok"), "{suite}: {page}");
        assert!(
            page.contains("TLSv1.3"),
            "{suite}: the page does not name TLS 1.3: {page}"
        );
    }
}

#[test]
fn an_rsa_pss_server_under_an_ed25519_root() {
    let server = serve("leaf-ed25519", None, "TLS_AES_128_GCM_SHA256");
    let (_, page) = fetch(&server, "host.test", &[anchor("root-ed25519")]).expect("rsa-pss server");
    assert!(page.contains("TLSv1.3"), "{page}");
}

#[test]
fn a_wrong_host_or_an_untrusted_root_is_refused() {
    let server = serve("leaf-p384", Some("inter-p256"), "TLS_AES_128_GCM_SHA256");
    match fetch(&server, "other.test", &[anchor("root-rsa")]) {
        Err(TlsError::Certificate(message)) => {
            assert!(message.contains("does not name other.test"), "{message}")
        }
        other => panic!("a host the certificate does not name was not refused: {other:?}"),
    }
    match fetch(&server, "host.test", &[anchor("root-ed25519")]) {
        Err(TlsError::Certificate(message)) => {
            assert!(message.contains("trusted roots"), "{message}")
        }
        other => panic!("an untrusted root was not refused: {other:?}"),
    }
}
