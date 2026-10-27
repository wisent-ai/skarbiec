// The operator routes that reach another vault over its serve channel:
// donating one item to a remote owner's inbox and enrolling this owner's key
// with a source. Both read a bearer from a token file on the machine the API
// serves, so they run there and are never forwarded. `routes` asks this
// table before its own.

use anyhow::Result;
use serde_json::Value;

use super::calls::{access, bonds, flags, positionals};

pub(super) fn answer(path: &str, parsed: &Value) -> Result<Option<Value>> {
    let answer = match path {
        // `donate <id> --to <url> --consumer <name> --token-file <path>`: the
        // item is sealed to the remote owner's key before it leaves.
        "/v1/operator/items/donate" => access(
            "donate",
            &flags(parsed, &["to", "consumer", "token-file", "from"]),
            &positionals(parsed, &["id"])?,
        ),
        // `enroll --as <uid> --to <url> --token-file <path>`: register this
        // owner's key with a source and ask for the items named.
        "/v1/operator/bonds/enroll" => bonds(
            "enroll",
            &flags(parsed, &["as", "to", "token-file", "items", "consumer"]),
            &[],
        ),
        _ => return Ok(None),
    };
    answer.map(Some)
}
