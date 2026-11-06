//! TLS 1.3 against the traces of RFC 8448 section 3, the simple 1-RTT
//! handshake: the X25519 shared secret, every secret of the key schedule,
//! the handshake and application traffic keys and IVs, both Finished
//! messages, and the server's protected handshake records and the client's
//! protected Finished opened and sealed byte for byte.

mod common;

use common::{hex, rfc_lines, to_hex};
use skarbiec_crypto::tls::record::{Protection, HANDSHAKE};
use skarbiec_crypto::tls::schedule::{traffic_key, Hash, Schedule};
use skarbiec_crypto::tls::suite::{Aead, TLS_AES_128_GCM_SHA256};
use skarbiec_crypto::x25519;

/// One step of a trace: who does it, what, and its named byte strings.
struct Step {
    title: String,
    fields: Vec<(String, Vec<u8>)>,
}

impl Step {
    fn get(&self, name: &str) -> &[u8] {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
            .unwrap_or_else(|| panic!("{}: no {name}", self.title))
    }
}

/// The steps of RFC 8448 from line `from` up to the section that ends it.
/// A field reads hex until it holds the octets its heading states, across
/// blank lines and page breaks, and is checked to hold exactly that many.
fn steps(lines: &[String], from: usize, to: usize) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    // The field being read: its name, the octets it states, what is read.
    let mut current: Option<(String, usize, Vec<u8>)> = None;
    for line in &lines[from..to] {
        let trimmed = line.trim();
        if let Some((name, want, bytes)) = current.as_mut() {
            if bytes.len() < *want {
                let groups: Vec<&str> = trimmed.split_whitespace().collect();
                if groups
                    .iter()
                    .all(|group| group.len() == 2 && group.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    bytes.extend(hex(trimmed));
                    continue;
                }
                assert!(
                    trimmed.is_empty(),
                    "{name}: {} of {want} octets, then {trimmed:?}",
                    bytes.len()
                );
                continue;
            }
            let (name, want, bytes) = current.take().expect("a field being read");
            assert_eq!(bytes.len(), want, "{name} holds more octets than it states");
            steps.last_mut().expect("a step").fields.push((name, bytes));
        }
        if trimmed.starts_with('{') {
            steps.push(Step {
                title: trimmed.trim_end_matches(':').to_string(),
                fields: Vec::new(),
            });
            continue;
        }
        // A field is `name (N octets):  hex`, its value empty when it says
        // `(empty)`; `salt:  0 (all zero octets)` and prose are not fields.
        let field = trimmed.split_once(" octets):").and_then(|(head, rest)| {
            let (name, count) = head.rsplit_once(" (")?;
            Some((name.to_string(), count.parse::<usize>().ok()?, rest.trim()))
        });
        if let Some((name, want, rest)) = field {
            let bytes = if rest == "(empty)" {
                Vec::new()
            } else {
                hex(rest)
            };
            current = Some((name, want, bytes));
        }
    }
    if let Some((name, want, bytes)) = current.take() {
        assert_eq!(bytes.len(), want, "{name}");
        steps.last_mut().expect("a step").fields.push((name, bytes));
    }
    steps
}

fn step<'a>(steps: &'a [Step], title: &str) -> &'a Step {
    steps
        .iter()
        .find(|step| step.title == title)
        .unwrap_or_else(|| panic!("RFC 8448 has no step {title:?}"))
}

#[test]
fn rfc8448_simple_1rtt() {
    let lines = rfc_lines("rfc/rfc8448.txt");
    let start = lines
        .iter()
        .position(|l| l.starts_with("3.  Simple 1-RTT Handshake"))
        .expect("section 3");
    let end = lines
        .iter()
        .position(|l| l.starts_with("4.  Resumed 0-RTT Handshake"))
        .expect("section 4");
    let steps = steps(&lines, start, end);
    let hash = Hash::Sha256;

    // The shared secret both sides agree from the two X25519 key pairs.
    let client_key = step(&steps, "{client}  create an ephemeral x25519 key pair");
    let server_key = step(&steps, "{server}  create an ephemeral x25519 key pair");
    let client_private: [u8; 32] = client_key.get("private key").try_into().expect("32");
    let server_public: [u8; 32] = server_key.get("public key").try_into().expect("32");
    assert_eq!(
        to_hex(&x25519::public_key(&client_private)),
        to_hex(client_key.get("public key"))
    );
    let shared =
        x25519::shared_secret(&client_private, &server_public).expect("a non-zero shared secret");
    let handshake_extract = step(&steps, "{server}  extract secret \"handshake\"");
    assert_eq!(
        to_hex(&shared),
        to_hex(handshake_extract.get("IKM")),
        "the X25519 shared secret"
    );

    let schedule = Schedule::new(hash, &shared);
    assert_eq!(
        to_hex(&schedule.handshake),
        to_hex(handshake_extract.get("secret")),
        "handshake secret"
    );
    let master = step(&steps, "{server}  extract secret \"master\"");
    assert_eq!(
        to_hex(&schedule.master),
        to_hex(master.get("secret")),
        "master secret"
    );

    // Handshake traffic secrets over ClientHello..ServerHello.
    let client_hello = step(
        &steps,
        "{client}  construct a ClientHello handshake message",
    )
    .get("ClientHello");
    let server_hello = step(
        &steps,
        "{server}  construct a ServerHello handshake message",
    )
    .get("ServerHello");
    let mut transcript = client_hello.to_vec();
    transcript.extend_from_slice(server_hello);
    let (c_hs, s_hs) = schedule.handshake_traffic(&hash.digest(&transcript));
    assert_eq!(
        to_hex(&c_hs),
        to_hex(step(&steps, "{server}  derive secret \"tls13 c hs traffic\"").get("expanded"))
    );
    assert_eq!(
        to_hex(&s_hs),
        to_hex(step(&steps, "{server}  derive secret \"tls13 s hs traffic\"").get("expanded"))
    );

    // The server's handshake traffic key and IV.
    let keys = step(
        &steps,
        "{server}  derive write traffic keys for handshake data",
    );
    let server_hs = traffic_key(hash, &s_hs, 16);
    assert_eq!(to_hex(&server_hs.key), to_hex(keys.get("key expanded")));
    assert_eq!(to_hex(&server_hs.iv), to_hex(keys.get("iv expanded")));

    // The server's protected flight opens to EncryptedExtensions,
    // Certificate, CertificateVerify and Finished.
    let encrypted_extensions = step(
        &steps,
        "{server}  construct an EncryptedExtensions handshake message",
    )
    .get("EncryptedExtensions");
    let certificate = step(
        &steps,
        "{server}  construct a Certificate handshake message",
    )
    .get("Certificate");
    let certificate_verify = step(
        &steps,
        "{server}  construct a CertificateVerify handshake message",
    )
    .get("CertificateVerify");
    let mut through_verify = transcript.clone();
    through_verify.extend_from_slice(encrypted_extensions);
    through_verify.extend_from_slice(certificate);
    through_verify.extend_from_slice(certificate_verify);
    let server_finished = schedule.finished(&s_hs, &hash.digest(&through_verify));
    let finished_step = step(&steps, "{server}  construct a Finished handshake message");
    let finished_message = finished_step.get("Finished");
    assert_eq!(
        to_hex(&server_finished),
        to_hex(&finished_message[4..]),
        "server Finished verify_data"
    );

    let flight = step(&steps, "{server}  send handshake record");
    let record = steps
        .iter()
        .filter(|step| step.title == "{server}  send handshake record")
        .nth(1)
        .unwrap_or(flight)
        .get("complete record");
    let mut server_in = Protection::new(|key| Aead::new(TLS_AES_128_GCM_SHA256, key), &server_hs);
    let head: [u8; 5] = record[..5].try_into().expect("header");
    let (content_type, content) = server_in
        .open(&head, &record[5..])
        .expect("the server's flight opens");
    assert_eq!(content_type, HANDSHAKE);
    let mut flight_plain = encrypted_extensions.to_vec();
    flight_plain.extend_from_slice(certificate);
    flight_plain.extend_from_slice(certificate_verify);
    flight_plain.extend_from_slice(finished_message);
    assert_eq!(
        to_hex(&content),
        to_hex(&flight_plain),
        "the server's protected flight"
    );

    // Application traffic secrets over the transcript through the server's Finished.
    let mut through_finished = through_verify.clone();
    through_finished.extend_from_slice(finished_message);
    let (c_ap, s_ap) = schedule.application_traffic(&hash.digest(&through_finished));
    assert_eq!(
        to_hex(&c_ap),
        to_hex(step(&steps, "{server}  derive secret \"tls13 c ap traffic\"").get("expanded"))
    );
    assert_eq!(
        to_hex(&s_ap),
        to_hex(step(&steps, "{server}  derive secret \"tls13 s ap traffic\"").get("expanded"))
    );

    // The client's Finished, sealed under its handshake key, byte for byte.
    let client_finished = schedule.finished(&c_hs, &hash.digest(&through_finished));
    let client_finished_step = step(&steps, "{client}  construct a Finished handshake message");
    let client_finished_message = client_finished_step.get("Finished");
    assert_eq!(
        to_hex(&client_finished),
        to_hex(&client_finished_message[4..]),
        "client Finished verify_data"
    );
    let client_hs = traffic_key(hash, &c_hs, 16);
    let mut client_out = Protection::new(|key| Aead::new(TLS_AES_128_GCM_SHA256, key), &client_hs);
    let sealed = client_out
        .seal(HANDSHAKE, client_finished_message)
        .expect("seal");
    let sent = steps
        .iter()
        .find(|step| {
            step.title == "{client}  send handshake record"
                && step
                    .fields
                    .iter()
                    .any(|(n, v)| n == "payload" && v.as_slice() == client_finished_message)
        })
        .expect("the client's Finished record");
    assert_eq!(
        to_hex(&sealed),
        to_hex(sent.get("complete record")),
        "the client's protected Finished"
    );
}
