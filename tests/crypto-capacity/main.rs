//! What a cheap tool waits for while decryptions are in flight.
//!
//! The vault runs every cryptographic operation as a child process under two
//! limits: a general one (`SKARBIEC_CRYPTO_CONCURRENCY`, default 8) and a
//! narrow one for `gpg` alone (`SKARBIEC_GPG_CONCURRENCY`, default 2). A `gpg`
//! child used to take the general permit and then wait for the narrow one, so
//! children doing no work held the whole general pool, and every tool that is
//! not `gpg` queued behind decryptions it has nothing to do with — `shasum`,
//! which is how a bearer is verified on every authenticated route, and
//! `openssl`, which is how a token is minted.
//!
//! On 2026-09-05 the fleet's four verifier sweeps read 48 mapped items through
//! one broker on `lukasz-macbook` while the queue agent asked the same broker
//! for the metadata of its own grant — a call that decrypts nothing. That call
//! took 14.4s, `GET /readyz` on the same broker took 9.7s, and Stado's
//! `agent-skarbiec` check reported `not measured: the probe did not answer
//! within 16s` about a broker answering every request with 200.
//!
//! Both facts are observed through the real broker over HTTP. `gpg` is
//! resolved through `PATH`, so a scripted `gpg` that sleeps before delegating
//! to the real one is what the broker spawns: the cryptography is real, its
//! duration is this test's to choose, and what is under test is the capacity
//! pool rather than GnuPG.

#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;
use support::{assert_success, CliFixture};

const CONSUMER: &str = "capacity-reader";
const ITEM: &str = "capacity-item";
/// How long each scripted `gpg` spends before doing the real work. Long
/// enough that a metadata call which waited for gpg capacity cannot answer
/// before the first decryption finishes.
const GPG_DELAY: Duration = Duration::from_secs(3);
/// More concurrent decryptions than the general pool has slots, which is the
/// state that used to starve every other tool.
const CONCURRENT_READS: usize = 10;

/// Where skarbiec itself looks for a cryptographic tool, so the stand-in can
/// delegate to the real one.
fn real_program(program: &str) -> PathBuf {
    std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain(
            [
                "/opt/homebrew/bin",
                "/usr/local/MacGPG2/bin",
                "/home/linuxbrew/.linuxbrew/bin",
                "/usr/local/bin",
                "/usr/bin",
                "/bin",
            ]
            .into_iter()
            .map(PathBuf::from),
        )
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("this host has no {program} to test the vault against"))
}

fn install_script(directory: &Path, name: &str, body: &str) {
    let path = directory.join(name);
    fs::write(&path, body).expect("write scripted cryptographic tool");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .expect("make scripted cryptographic tool executable");
}

fn curl(url: &str, consumer: &str, bearer: &str, body: &str) -> (u32, String, Duration) {
    let started = Instant::now();
    let output = Command::new("curl")
        .args([
            "-s",
            "-m",
            "120",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            "-X",
            "POST",
            url,
            "-H",
            &format!("X-Consumer: {consumer}"),
            "-H",
            &format!("Authorization: Bearer {bearer}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
        ])
        .output()
        .expect("run curl");
    let elapsed = started.elapsed();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let (payload, status) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (
        status.trim().parse().unwrap_or_default(),
        payload.to_string(),
        elapsed,
    )
}

#[test]
fn a_metadata_call_does_not_wait_for_decryptions_it_has_nothing_to_do_with() {
    let fixture = CliFixture::new("capacity");
    fixture.init("Skarbiec capacity test <skarbiec-capacity-test@example.invalid>");
    assert_success(
        "seed one readable item",
        &fixture.run(&["set", ITEM, "--type", "api-key", "api_key=sekret-123"]),
    );
    let minted = fixture.run(&[
        "token-mint",
        CONSUMER,
        "--capabilities",
        &format!("read:{ITEM}#api_key"),
    ]);
    assert_success("mint one scoped grant", &minted);
    let response: Value = serde_json::from_slice(&minted.stdout).expect("parse mint response");
    let bearer = response["token"]
        .as_str()
        .expect("grant value shown once")
        .to_string();

    // A `gpg` that takes its time, and the real one underneath it.
    let tools = fixture.root.join("slow-tools");
    fs::create_dir_all(&tools).expect("create scripted tool directory");
    let real_gpg = real_program("gpg");
    install_script(
        &tools,
        "gpg",
        &format!(
            "#!/bin/sh\n/bin/sleep {}\nexec {} \"$@\"\n",
            GPG_DELAY.as_secs(),
            real_gpg.display()
        ),
    );
    let path = format!(
        "{}:{}",
        tools.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let broker = fixture.serve_with_env(&[("PATH", &path)]);

    let read_url = broker.url("/v1/items/read");
    let list_url = broker.url("/v1/items/list");
    let read_body = format!(r#"{{"id":"{ITEM}","field":"api_key"}}"#);

    // Saturate the vault with decryptions: more of them than the general pool
    // has slots, each one parked in the scripted `gpg`.
    let readers: Vec<_> = (0..CONCURRENT_READS)
        .map(|_| {
            let url = read_url.clone();
            let consumer = CONSUMER.to_string();
            let bearer = bearer.clone();
            let body = read_body.clone();
            std::thread::spawn(move || curl(&url, &consumer, &bearer, &body))
        })
        .collect();
    // Long enough for every one of them to be inside `gpg`, well short of the
    // first one finishing.
    std::thread::sleep(GPG_DELAY / 3);

    let (status, payload, elapsed) = curl(&list_url, CONSUMER, &bearer, "{}");
    assert_eq!(status, 200, "metadata call refused: {payload}");
    assert!(
        elapsed < GPG_DELAY,
        "the metadata call took {elapsed:?} while {CONCURRENT_READS} decryptions were in \
         flight; it decrypts nothing, so anything at or beyond one gpg delay ({GPG_DELAY:?}) \
         means it waited for cryptographic capacity that gpg waiters were holding without \
         using"
    );

    // And the decryptions themselves still answer: the ordering change must
    // not have cost the crypto path its capacity.
    for reader in readers {
        let (status, payload, _) = reader.join().expect("reader thread");
        assert_eq!(status, 200, "decryption refused: {payload}");
        let answer: Value = serde_json::from_str(&payload).expect("parse read response");
        assert_eq!(answer["value"], "sekret-123");
    }
}
