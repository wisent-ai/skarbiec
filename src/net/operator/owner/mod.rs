// The operator routes that change who owns the vault and prepare the key an
// owner opens it with: `owner rotate <uid>` and `owner key mint|show <uid>`,
// the owner's lockdown withdrawing every grant at once, and the decision on
// an access request another host filed. `routes` asks this table before its
// own.

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

use super::calls::{access, flags, positionals, request, runtime};

/// The answer to an owner route, or `None` when `path` is not one.
pub(super) fn answer(path: &str, parsed: &Value) -> Result<Option<Value>> {
    let no_flags = HashMap::new();
    let answer = match path {
        // The desktop asks first: every ciphertext is rewrapped to the new owner.
        "/v1/operator/owner/rotate" => {
            access("owner", &no_flags, &[vec!["rotate".to_string()], positionals(parsed, &["uid"])?].concat())
        }
        // A vault moved to this host is opened by its owner's key here; the
        // desktop makes it before the move and shows its fingerprint.
        "/v1/operator/owner/key/mint" => access(
            "owner",
            &no_flags,
            &[vec!["key".to_string(), "mint".to_string()], positionals(parsed, &["uid"])?].concat(),
        ),
        "/v1/operator/owner/key/show" => access(
            "owner",
            &no_flags,
            &[vec!["key".to_string(), "show".to_string()], positionals(parsed, &["uid"])?].concat(),
        ),
        // Without yes it names the grants it would withdraw; the desktop
        // sends yes only from its own confirmation.
        "/v1/operator/lockdown" => runtime("lockdown", &flags(parsed, &["except", "yes"]), &[]),
        // The decider names themself (`by`) and states the lifetime and uses;
        // the register refuses anyone but an owner or admin holding their key.
        "/v1/operator/requests/approve" => request(
            "request approve",
            &flags(parsed, &["by", "ttl-seconds", "until-revoked", "uses"]),
            &positionals(parsed, &["id"])?,
        ),
        "/v1/operator/requests/deny" => request(
            "request deny",
            &flags(parsed, &["by", "reason"]),
            &positionals(parsed, &["id"])?,
        ),
        _ => return Ok(None),
    };
    answer.map(Some)
}
