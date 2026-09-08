//! What a cheap tool waits for while real decryptions are in flight.
//!
//! The vault runs every cryptographic operation as a child process under two
//! limits: a general one (`SKARBIEC_CRYPTO_CONCURRENCY`, default eight) and a
//! narrow one for `gpg` alone (`SKARBIEC_GPG_CONCURRENCY`, default two). A
//! `gpg` child used to take the general permit and then wait for the narrow
//! one, so children doing no work held the whole general pool, and every tool
//! that is not `gpg` queued behind decryptions it has nothing to do with:
//! `shasum`, which verifies a bearer on every authenticated route, and
//! `openssl`, which mints a token.
//!
//! On 2026-09-05 the fleet's four verifier sweeps read 48 mapped items through
//! one broker while the queue agent asked it for the metadata of its own grant
//! — a call that decrypts nothing. That call took 14.4s, `GET /readyz` took
//! 9.7s, and Stado's `agent-skarbiec` check reported `not measured: the probe
//! did not answer within 16s` about a broker answering everything with 200.
//!
//! The contention here is real and so is the cryptography. `CONCURRENT_READS`
//! grant-authorised reads of one real item run against a real broker holding
//! `GPG_SLOTS` slots, so real decryptions are queued while the metadata call
//! is answered. Nothing sleeps in place of work and nothing stands in for
//! `gpg`. The predecessor of this file put a `#!/bin/sh` wrapper running
//! `/bin/sleep` in front of the real `gpg` on the broker's `PATH`, which is a
//! deadline the test invented rather than one the product met. Only two
//! settings are raised from their defaults: more HTTP workers than readers,
//! because a request still waiting for a worker has not reached cryptographic
//! capacity at all, and the `gpg` limit the assertions reason about.
//!
//! Daemon recovery must not run, and the last assertion is that it did not.
//! `recoverable_gpg_failure` (src/core/crypto.rs) treats `gpg timed out`,
//! `Broken pipe`, `End of file` and `IPC connect call failed` as worth one
//! recovery, and `recover_gpg_daemons` performs it with `pkill -TERM/-KILL -x
//! gpg-agent`, `keyboxd`, `scdaemon` — no `-u`, no `GNUPGHOME` filter — so it
//! reaches out of this fixture and kills every agent on the account, the one
//! serving the operator's live vault included. Contention cannot reach that
//! path by construction: the seam's deadline is armed after both permits are
//! taken and measures one child's own runtime, so a queued read waits without
//! ageing toward it. The product records nothing when a recovery does run, so
//! this test observes the effect — this fixture's own agent would die with the
//! rest, and its pid is read from the real process table before the burst and
//! required to be the same live process after it. The refusal that deadline
//! itself produces is not covered here and is reported blocked for the same
//! reason: reaching it means answering `gpg timed out`.

#[path = "../support/mod.rs"]
mod support;

use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use serde_json::Value;
use support::{assert_success, CliFixture};

const CONSUMER: &str = "capacity-reader";
const ITEM: &str = "capacity-item";
const SECRET: &str = "sekret-123";
/// The `gpg` slots the broker is given, so the queue is the one the assertions
/// reason about rather than whatever the default happens to be.
const GPG_SLOTS: usize = 2;
/// Real concurrent decryptions: more than the general pool has slots, which is
/// the state that used to starve every other tool.
const CONCURRENT_READS: usize = 24;
/// How many decryptions must still be unanswered when the metadata call comes
/// back, for it to have overtaken a real queue rather than an idle broker.
const MUST_STILL_BE_WAITING: usize = 8;
/// More HTTP workers, and queue, than readers.
const HTTP_WORKERS: usize = 64;
/// How long the broker may take to answer part of the burst. Generous: a cold
/// fixture pays for gpg-agent's startup.
const QUEUE_TIMEOUT: Duration = Duration::from_secs(60);

/// One authenticated POST, with the status, the body, and how long the broker
/// took to answer it.
fn curl(url: &str, bearer: &str, body: &str) -> (u32, String, Duration) {
    let started = Instant::now();
    let output = Command::new("curl")
        .args(["-s", "-m", "120", "-o", "-", "-w", "\n%{http_code}"])
        .args(["-X", "POST", url])
        .args(["-H", &format!("X-Consumer: {CONSUMER}")])
        .args(["-H", &format!("Authorization: Bearer {bearer}")])
        .args(["-H", "Content-Type: application/json", "-d", body])
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

/// The live `gpg-agent` processes serving one `GNUPGHOME`, from the real
/// process table. A daemon names its home in its own argv, which is what tells
/// this fixture's agent apart from the operator's and from a sibling's.
fn agent_pids(gnupg: &Path) -> Vec<u32> {
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(format!("gpg-agent --homedir {}", gnupg.display()))
        .output()
        .expect("read this fixture's gpg-agent from the process table");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|pid| pid.parse().ok())
        .collect()
}

/// Every operation the journal recorded about this item, in order. Rows naming
/// another item are dropped; rows naming none are kept, because the broker
/// journals its own lifecycle without one.
fn journalled_ops(fixture: &CliFixture) -> Vec<String> {
    let body = std::fs::read_to_string(fixture.root.join("audit.jsonl"))
        .expect("read the fixture's audit journal");
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is one JSON object"))
        .filter(|entry| {
            let item = entry.pointer("/extra/item").and_then(Value::as_str);
            item.is_none() || item == Some(ITEM)
        })
        .filter_map(|entry| entry["op"].as_str().map(str::to_owned))
        .collect()
}

/// Wait until the broker has answered `at_least` of the reads in flight, so
/// the metadata call meets a `gpg` pool it is demonstrably working through. A
/// broker that never gets that far is a finding, not a reason to hang.
fn await_answers(answered: &AtomicUsize, at_least: usize) {
    let deadline = Instant::now() + QUEUE_TIMEOUT;
    while Instant::now() < deadline {
        if answered.load(Ordering::SeqCst) >= at_least {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!(
        "the broker answered fewer than {at_least} of {CONCURRENT_READS} reads within \
         {QUEUE_TIMEOUT:?}, so there was no queue to overtake and this measured nothing"
    );
}

#[test]
fn a_metadata_call_does_not_wait_for_decryptions_it_has_nothing_to_do_with() {
    let fixture = CliFixture::new("capacity");
    fixture.init("Skarbiec capacity test <skarbiec-capacity-test@example.invalid>");
    let field = format!("api_key={SECRET}");
    assert_success(
        "seed one readable item",
        &fixture.run(&["set", ITEM, "--type", "api-key", &field]),
    );
    let capability = format!("read:{ITEM}#api_key");
    let minted = fixture.run(&["grant", "issue", CONSUMER, "--capabilities", &capability]);
    assert_success("mint one scoped grant", &minted);
    let response: Value = serde_json::from_slice(&minted.stdout).expect("parse mint response");
    let bearer = response["token"]
        .as_str()
        .expect("grant value shown once")
        .to_string();

    let slots = GPG_SLOTS.to_string();
    let workers = HTTP_WORKERS.to_string();
    let broker = fixture.serve_with_env(&[
        ("SKARBIEC_GPG_CONCURRENCY", slots.as_str()),
        ("SKARBIEC_HTTP_WORKERS", workers.as_str()),
        ("SKARBIEC_HTTP_QUEUE", workers.as_str()),
    ]);
    let read_url = broker.url("/v1/items/read");
    let read_body = format!(r#"{{"id":"{ITEM}","field":"api_key"}}"#);

    // One read to warm the daemons, then one to measure: with nothing else in
    // flight, that is what one real decryption of this item costs on this
    // host, and it is the yardstick the durations below are read against.
    let (status, payload, _) = curl(&read_url, &bearer, &read_body);
    assert_eq!(status, 200, "the first read was refused: {payload}");
    let (status, payload, one_decryption) = curl(&read_url, &bearer, &read_body);
    assert_eq!(status, 200, "the measured read was refused: {payload}");
    assert!(payload.contains(SECRET), "the read returned {payload}");

    // The agent these decryptions talk to, recorded before the burst because
    // daemon recovery would kill it and this test must fail if that happens.
    let agent_before = agent_pids(&fixture.gnupg);
    assert!(
        !agent_before.is_empty(),
        "no gpg-agent serves {}, so a recovery that killed one could not be told \
         apart from a daemon that never started",
        fixture.gnupg.display()
    );

    let answered = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Barrier::new(CONCURRENT_READS + 1));
    let readers: Vec<_> = (0..CONCURRENT_READS)
        .map(|_| {
            let url = read_url.clone();
            let bearer = bearer.clone();
            let body = read_body.clone();
            let gate = Arc::clone(&gate);
            let answered = Arc::clone(&answered);
            std::thread::spawn(move || {
                gate.wait();
                let answer = curl(&url, &bearer, &body);
                answered.fetch_add(1, Ordering::SeqCst);
                answer
            })
        })
        .collect();

    gate.wait();
    let burst_started = Instant::now();
    await_answers(&answered, GPG_SLOTS);
    let (list_status, list_payload, list_took) = curl(&broker.url("/v1/items/list"), &bearer, "{}");
    let still_waiting = CONCURRENT_READS - answered.load(Ordering::SeqCst);
    let answers: Vec<_> = readers
        .into_iter()
        .map(|reader| reader.join().expect("reader thread"))
        .collect();
    let burst_took = burst_started.elapsed();

    // What this run measured, so a passing run says how much room the claim
    // had rather than only that it held.
    println!(
        "one decryption {one_decryption:?}; burst of {CONCURRENT_READS} behind {GPG_SLOTS} \
         gpg slots {burst_took:?}; metadata call {list_took:?} with {still_waiting} reads \
         still unanswered"
    );

    assert_eq!(list_status, 200, "metadata call refused: {list_payload}");
    assert!(
        list_payload.contains(ITEM),
        "the metadata call answered without the item it may see: {list_payload}"
    );
    assert!(
        still_waiting >= MUST_STILL_BE_WAITING,
        "only {still_waiting} of {CONCURRENT_READS} decryptions were unanswered when the \
         metadata call came back, so it met no queue; one decryption costs \
         {one_decryption:?} and the burst took {burst_took:?}"
    );
    assert!(
        list_took * 4 < burst_took,
        "the metadata call took {list_took:?} with {still_waiting} of {CONCURRENT_READS} \
         decryptions still queued behind {GPG_SLOTS} gpg slots, and the burst it overtook \
         took {burst_took:?}; it decrypts nothing, so a duration that close to the whole \
         backlog means it waited for capacity gpg waiters held without using"
    );
    // Four times one read, not twelve: the queue is twelve rounds deep behind
    // two slots, but a read also pays for a curl, a bearer verification and a
    // vault load, and on this host that put the whole burst at eight times one
    // read. This floor only has to rule out reads that never queued at all.
    assert!(
        burst_took >= one_decryption * 4,
        "{CONCURRENT_READS} reads finished in {burst_took:?} while one costs \
         {one_decryption:?}, so they were not serialised behind {GPG_SLOTS} gpg slots and \
         there was no contention to overtake"
    );

    // The decryptions themselves still answer, each with the stored value: the
    // ordering the fix changed must not cost the crypto path its capacity.
    for (status, payload, _) in &answers {
        assert_eq!(*status, 200, "decryption refused: {payload}");
        let answer: Value = serde_json::from_str(payload).expect("parse read response");
        assert_eq!(answer["value"], SECRET, "read returned {payload}");
    }

    // The journal is the durable record: one row per read that answered, and
    // no row saying an item this test could read was undecryptable.
    let ops = journalled_ops(&fixture);
    let reads = ops.iter().filter(|op| *op == "http-item-read").count();
    assert_eq!(
        reads,
        CONCURRENT_READS + 2,
        "the journal recorded {reads} reads of {ITEM} where {} answered: {ops:?}",
        CONCURRENT_READS + 2
    );
    assert!(
        !ops.iter().any(|op| op == "http-item-read-undecryptable"),
        "the broker journalled a read it could not decrypt, so this run met a \
         cryptographic failure and not only contention: {ops:?}"
    );

    // And no daemon recovery ran: it cannot run without `pkill -x gpg-agent`,
    // which would have taken this pid with it.
    let agent_after = agent_pids(&fixture.gnupg);
    assert!(
        agent_before.iter().any(|pid| agent_after.contains(pid)),
        "the gpg-agent serving {} at pid {agent_before:?} is gone and {agent_after:?} \
         serves it now, so this run entered daemon recovery: `recover_gpg_daemons` runs \
         `pkill -TERM/-KILL -x gpg-agent` with no -u and no GNUPGHOME filter, killing \
         every agent on this account including the one holding the operator's live \
         vault. That is a failure of this test, never something to retry past",
        fixture.gnupg.display()
    );
}
