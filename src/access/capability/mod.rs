// Capability broker: hand one field to one workload, once, without the workload
// ever holding a vault bearer.
//
// A capability is a promise made in advance by an operator ("this agent may read
// this resource, N times, until this instant") and redeemed later by a process
// that proves it is that agent. The proof is an Ed25519 signature over the exact
// request, so a stolen capability id is worthless without the workload key, and a
// captured request cannot be replayed: the nonce is recorded and refused twice.
//
// Why a socket rather than another CLI verb: the redeeming side is a browser
// trajectory mid-flight. It needs the secret in memory for the length of one form
// fill and must never receive a credential it could persist. A stream that yields
// exactly `secret_len` bytes and closes gives the caller nothing to keep, and gives
// us one place to spend the use count.
//
// Resources are indirect on purpose. The caller names `origin:https://…/password`,
// never an item and field, so the issuing operator -- not the workload -- decides
// which vault entry that stands for. capability-routes.json beside the vault is the
// only place the two vocabularies meet.
//
// `pending` is a first-class answer, not an error. A 2FA challenge resource is
// issued before the code exists, because the login that will need it is what causes
// Apple to send it. The redeeming side polls, the relay stores, the poll succeeds.
// Denying would force the caller to tell "not yet" from "never" by guessing.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use serde_json::Value;

const PROOF_DOMAIN: &[u8] = b"SKARBIEC-WORKLOAD-PROOF\0v1\0";
const WIRE_VERSION: &str = "skarbiec.redeem.v1";
const MAX_REQUEST_BYTES: u64 = 8 * 1024;
const MAX_TTL_SECONDS: u64 = 3600;
const NONCE_RETENTION_SECONDS: u64 = 2 * MAX_TTL_SECONDS;

const STATE_LOCK_STALE_SECONDS: u64 = 120;
const STATE_LOCK_RETRY_MILLIS: u64 = 5;
const STATE_LOCK_ATTEMPTS: usize = 6_000;

/// The `openssl` this build verifies proofs with.
///
/// Prefer an OpenSSL 3 build when one is installed, and let SKARBIEC_OPENSSL
/// name it when it lives somewhere else.
fn openssl_bin() -> String {
    if let Ok(configured) = std::env::var("SKARBIEC_OPENSSL") {
        if !configured.is_empty() {
            return configured;
        }
    }
    for candidate in [
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "openssl".to_string()
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "capability-serve" => Ok(Some(serve(flags)?)),
        "apple-challenge-put" => Ok(Some(challenge_put(_positionals)?)),
        _ => Ok(None),
    }
}

mod issue;
mod redeem;
mod state;

pub(super) use issue::issue;
pub(super) use state::{routes_path, write_private_file};

use redeem::{challenge_put, serve};
