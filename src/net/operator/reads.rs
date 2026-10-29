// The operator routes that read: one route to one backend command, each
// delegating to the dispatcher its command twin uses. `routes` asks here
// first and answers the mutations itself.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;

use super::calls::{
    access, bonds, flags, grant, inbox, optional, positionals, request, rotation, runtime, verbed,
};

/// The answer to a read route, or `None` when `path` is not one.
pub(super) fn answer(path: &str, parsed: &Value) -> Result<Option<Value>> {
    let none: Vec<String> = Vec::new();
    let no_flags = HashMap::new();
    let answer: Result<Value> = match path {
        "/v1/operator/items/get"
        | "/v1/operator/items/list"
        | "/v1/operator/items/set-json"
        | "/v1/operator/items/retag"
        | "/v1/operator/totp/seed-state" => crate::net::owner::local(path, parsed),
        "/v1/operator/items" => {
            crate::cmd_list(&HashMap::from([("all".to_string(), "true".to_string())]))
        }
        "/v1/operator/recipients" => access("recipient list", &no_flags, &none),
        // A public key only: no private material is ever exported.
        "/v1/operator/recipients/export" => access(
            "recipient export",
            &no_flags,
            &positionals(parsed, &["uid"])?,
        ),
        // Item ids only, read from the envelope: nothing is decrypted.
        "/v1/operator/recipients/items" => access(
            "recipient items",
            &no_flags,
            &positionals(parsed, &["uid"])?,
        ),
        "/v1/operator/browser-host" => crate::browser::host_status(),
        "/v1/operator/audit" => runtime(
            "audit list",
            &flags(
                parsed,
                &["op", "consumer", "item", "since", "until", "limit"],
            ),
            &none,
        ),
        "/v1/operator/audit/summary" => {
            runtime("audit summary", &flags(parsed, &["since", "until"]), &none)
        }
        "/v1/operator/chain" => runtime("audit verify", &flags(parsed, &["tail"]), &none),
        "/v1/operator/policy" => access("policy get", &no_flags, &none),
        "/v1/operator/grants" => grant(
            "list",
            &flags(
                parsed,
                &[
                    "item",
                    "expired",
                    "expiring-within",
                    "dangling",
                    "idle-since",
                ],
            ),
            &none,
        ),
        "/v1/operator/rotation" => rotation("list", &flags(parsed, &["due"]), &none),
        "/v1/operator/rotation/providers" => Ok(crate::runtime::rotate::providers()),
        "/v1/operator/doctor" => crate::runtime::doctor::report(None),
        "/v1/operator/status" => crate::core::items::status_json(),
        "/v1/operator/vaults" => crate::runtime::vaults::inventory(),
        "/v1/operator/donations" => inbox("donation list", &no_flags, &none),
        "/v1/operator/requests" => request("request list", &flags(parsed, &["state"]), &none),
        "/v1/operator/emergency" => access("emergency list", &no_flags, &none),
        "/v1/operator/recovery" => access("recovery status", &no_flags, &none),
        "/v1/operator/key-doctor" => access("keys", &no_flags, &["check".to_string()]),
        "/v1/operator/items/history" => {
            crate::cmd_history(&flags(parsed, &["changes"]), &positionals(parsed, &["id"])?)
        }
        "/v1/operator/tags" => crate::cli::tools::cmd_tags(&flags(parsed, &["all"])),
        "/v1/operator/items/readers" => crate::cmd_readers(&positionals(parsed, &["id"])?),
        "/v1/operator/items/duplicates" => crate::cmd_duplicates(),
        // Without apply the upgrade only reports what it would change.
        "/v1/operator/upgrade" => crate::core::items::upgrade(&no_flags),
        "/v1/operator/health" => runtime(
            "health",
            &flags(parsed, &["field", "breached", "saved-versions"]),
            &none,
        ),
        // Subjects, issuers and end dates, never the private key.
        "/v1/operator/certificates" => {
            runtime("certificates", &flags(parsed, &["expiring-before"]), &none)
        }
        // Fingerprints and expiry moments, never a key.
        "/v1/operator/keys" => runtime("keys", &flags(parsed, &["expiring-before"]), &none),
        // Issuers and moments of the stored JSON Web Tokens, never a token.
        "/v1/operator/items/token-expiry" => runtime(
            "expiry",
            &flags(parsed, &["before"]),
            &["tokens".to_string()],
        ),
        // Keys, grants and journal consumers for one item, never a value.
        "/v1/operator/items/exposure" => runtime(
            "exposure",
            &flags(parsed, &["since"]),
            &positionals(parsed, &["id"])?,
        ),
        // Names, usernames and domains, never a password or a one-time code.
        "/v1/operator/items/logins-for" => {
            runtime("login", &no_flags, &verbed("list", parsed, &["site"])?)
        }
        "/v1/operator/items/sites" => runtime("sites", &no_flags, &positionals(parsed, &["id"])?),
        // Password Manager Resources' list of pages is downloaded; nothing leaves.
        "/v1/operator/items/sites/change-pages" => runtime(
            "sites",
            &HashMap::from([("change-pages".to_string(), "true".to_string())]),
            &positionals(parsed, &["id"])?,
        ),
        "/v1/operator/items/notes" => runtime("notes", &no_flags, &positionals(parsed, &["id"])?),
        "/v1/operator/items/password-rules" => {
            runtime("password", &no_flags, &verbed("rules", parsed, &["id"])?)
        }
        // Where each item matched, never the value that did.
        "/v1/operator/items/find" => runtime(
            "find",
            &flags(parsed, &["notes"]),
            &positionals(parsed, &["text"])?,
        ),
        "/v1/operator/shares" => access("shares", &no_flags, &none),
        // The file lands on the machine the app runs on, at the absolute path
        // its save panel chose; a relative one would land in the serving
        // process's working directory, which nobody chose.
        "/v1/operator/items/export" => {
            let path = positionals(parsed, &["path"])?;
            if !path
                .iter()
                .all(|path| std::path::Path::new(path).is_absolute())
            {
                anyhow::bail!("path must be absolute: the export is written where the app chose, not in the server's working directory");
            }
            crate::cli::tools::export_value(
                &flags(
                    parsed,
                    &[
                        "browser-csv",
                        "bitwarden-csv",
                        "canonical",
                        "encrypt-to",
                        "kind",
                        "tag",
                        "updated-before",
                        "match",
                        "shared-with",
                        "pinned",
                    ],
                ),
                &path,
            )
        }
        // A count only: taking a code prints it, so that stays on the command line.
        "/v1/operator/items/recovery-codes" => {
            runtime("totp", &no_flags, &verbed("recovery", parsed, &["id"])?)
        }
        // Only the SHA-1 prefix leaves the host, as on the command line.
        "/v1/operator/items/breach-check" => runtime(
            "breach",
            &flags(parsed, &["field"]),
            &verbed("check", parsed, &["id"])?,
        ),
        "/v1/operator/items/expiry" => {
            runtime("expiry", &flags(parsed, &["before"]), &["list".to_string()])
        }
        "/v1/operator/items/pins" => crate::runtime::pins::list(),
        // The 2FA Directory's list of sites is downloaded; nothing leaves.
        "/v1/operator/items/codes-missing" => runtime("totp", &no_flags, &["missing".to_string()]),
        // Have I Been Pwned's list of breaches is downloaded whole; nothing leaves.
        "/v1/operator/items/site-breaches" => runtime("breach", &no_flags, &["sites".to_string()]),
        // With id, one item's moment, as its inspector asks; without, the list.
        "/v1/operator/items/password-age" => runtime(
            "password",
            &flags(parsed, &["set-before"]),
            &std::iter::once("age".to_string())
                .chain(optional(parsed, "id"))
                .collect::<Vec<_>>(),
        ),
        // One field of the login a site is signed in with, as `get` answers
        // one field: the forwarded `login get` of a host without the vault.
        "/v1/operator/items/site-get" => runtime(
            "login",
            &flags(parsed, &["field", "username"]),
            &verbed("get", parsed, &["site"])?,
        ),
        "/v1/operator/kit" => crate::runtime::kit::kit(),
        "/v1/operator/bonds" => bonds("bond list", &no_flags, &none),
        "/v1/operator/version" => crate::cmd_version(),
        "/v1/operator/route/resolve" => {
            let mut positionals = vec!["resolve".to_string()];
            // A body without `names` asks about no named route, as the
            // command line does without positionals; a `names` that is not
            // a list of text is refused, never read as empty.
            match parsed.get("names") {
                None => {}
                Some(Value::Array(names)) => {
                    for name in names {
                        let name = name.as_str().with_context(|| {
                            format!("route resolve: names holds {name}, which is not text")
                        })?;
                        positionals.push(name.to_string());
                    }
                }
                Some(other) => bail!("route resolve: names is {other}, not a list of text"),
            }
            let mut resolve_flags = HashMap::new();
            if let Some(consumer) = optional(parsed, "consumer") {
                resolve_flags.insert("consumer".to_string(), consumer);
            }
            // A console reads metadata only: no token is accepted here, so no
            // value can be materialized through this route.
            access("route", &resolve_flags, &positionals)
        }
        "/v1/operator/route/verify" => {
            // The report is the answer, broken rows included: a console came
            // for exactly the routes a bare refusal would throw away.
            crate::access::route::resolution::verify_report(optional(parsed, "consumer").as_deref())
        }
        _ => return Ok(None),
    };
    answer.map(Some)
}
