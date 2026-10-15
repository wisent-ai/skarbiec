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

use anyhow::Result;
use serde_json::Value;

const PROOF_DOMAIN: &[u8] = b"SKARBIEC-WORKLOAD-PROOF\0v1\0";
const WIRE_VERSION: &str = "skarbiec.redeem.v1";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        // Redemption is served only by `skarbiec serve`, the host's one
        // Skarbiec process; there is no standalone broker command.
        "capability-status" => Ok(Some(status::inspect(flags)?)),
        "challenge-put" => Ok(Some(challenge_put(_positionals)?)),
        _ => Ok(None),
    }
}

mod issue;
mod redeem;
mod state;
mod status;

pub(super) use issue::issue;
pub(super) use state::{routes_path, write_private_file};

use redeem::challenge_put;
pub(crate) use redeem::CapabilityListener;
