// One operator route to one backend command. Every arm names a command that
// exists, so a route that answers nothing is a bug in this table.

use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::HashMap;

use super::calls::{
    access, bonds, credential_operation, flags, grant, inbox, net, optional, positionals, request,
    rotation, runtime, text,
};
use crate::core;

pub(super) fn answer(path: &str, parsed: &Value) -> Result<Value> {
    let none: Vec<String> = Vec::new();
    let no_flags = HashMap::new();
    match path {
        // Reads, each delegating to the dispatcher its command twin uses.
        "/v1/operator/items/get" | "/v1/operator/items/list" | "/v1/operator/items/set-json" => {
            crate::net::owner::local(path, parsed)
        }
        "/v1/operator/items" => {
            crate::cmd_list(&HashMap::from([("all".to_string(), "true".to_string())]))
        }
        "/v1/operator/recipients" => access("recipient list", &no_flags, &none),
        "/v1/operator/audit" => runtime(
            "audit list",
            &flags(
                parsed,
                &["op", "consumer", "item", "since", "until", "limit"],
            ),
            &none,
        ),
        "/v1/operator/chain" => runtime("audit verify", &flags(parsed, &["tail"]), &none),
        "/v1/operator/policy" => access("policy get", &no_flags, &none),
        "/v1/operator/grants" => grant("list", &no_flags, &none),
        "/v1/operator/rotation" => rotation("list", &no_flags, &none),
        "/v1/operator/doctor" => crate::runtime::doctor::report(None),
        "/v1/operator/status" => crate::core::items::status_json(),
        "/v1/operator/vaults" => crate::runtime::vaults::inventory(),
        "/v1/operator/donations" => inbox("donation list", &no_flags, &none),
        "/v1/operator/requests" => request("request list", &flags(parsed, &["state"]), &none),
        "/v1/operator/emergency" => access("emergency list", &no_flags, &none),
        "/v1/operator/recovery" => access("recovery status", &no_flags, &none),
        "/v1/operator/key-doctor" => access("key-doctor", &no_flags, &none),
        "/v1/operator/bonds" => bonds("bond list", &no_flags, &none),
        "/v1/operator/version" => crate::cmd_version(),
        "/v1/operator/route/resolve" => {
            let mut positionals = vec!["resolve".to_string()];
            positionals.extend(
                parsed
                    .get("names")
                    .and_then(Value::as_array)
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default(),
            );
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
        // Mutations, one route per verb, bodies naming exact targets.
        "/v1/operator/vaults/create" => {
            crate::cmd_init(&no_flags, &positionals(parsed, &["owner"])?)
        }
        "/v1/operator/items/import" => core::importer::run(
            &flags(parsed, &["format", "conflict"]),
            &positionals(parsed, &["path"])?,
        ),
        "/v1/operator/items/trash" => crate::cmd_delete(&positionals(parsed, &["id"])?),
        "/v1/operator/items/reclaim" => crate::cmd_reclaim(&positionals(parsed, &["id"])?),
        "/v1/operator/items/restore" => crate::cmd_restore(&positionals(parsed, &["id"])?),
        // The desktop asks "Purge Permanently" before it sends this request.
        "/v1/operator/items/purge" => crate::cmd_purge(&positionals(parsed, &["id"])?, true),
        "/v1/operator/items/share" => {
            access("share", &no_flags, &positionals(parsed, &["id", "uid"])?)
        }
        "/v1/operator/items/revoke" => {
            access("revoke", &no_flags, &positionals(parsed, &["id", "uid"])?)
        }
        "/v1/operator/recipients/add" => access(
            "recipient add",
            &flags(parsed, &["import", "role"]),
            &positionals(parsed, &["uid"])?,
        ),
        // The desktop's Remove from vault sheet is the confirmation it sends.
        "/v1/operator/recipients/remove" => {
            let confirmed = HashMap::from([("yes".to_string(), "true".to_string())]);
            access(
                "recipient remove",
                &confirmed,
                &positionals(parsed, &["uid"])?,
            )
        }
        "/v1/operator/rotation/set" => rotation(
            "set",
            &flags(parsed, &["every-days", "provider", "consumer", "purpose"]),
            &positionals(parsed, &["item"])?,
        ),
        "/v1/operator/rotation/remove" => {
            rotation("remove", &no_flags, &positionals(parsed, &["item"])?)
        }
        "/v1/operator/rotation/run" => rotation("run", &flags(parsed, &["item"]), &none),
        "/v1/operator/grants/capability" => grant(
            "capability",
            &flags(
                parsed,
                &[
                    "agent",
                    "purpose",
                    "resource",
                    "target",
                    "ttl",
                    "max-uses",
                    "authorization-id",
                ],
            ),
            &none,
        ),
        "/v1/operator/grants/issue" => grant(
            "issue",
            &flags(
                parsed,
                &[
                    "capabilities",
                    "workload-public-key-file",
                    "ttl-seconds",
                    "until-revoked",
                    "audience",
                    "replace-capabilities",
                ],
            ),
            &positionals(parsed, &["consumer"])?,
        ),
        "/v1/operator/grants/ensure" => grant(
            "ensure",
            &flags(parsed, &["field", "token-file"]),
            &positionals(parsed, &["consumer", "item"])?,
        ),
        "/v1/operator/grants/narrow" => grant(
            "narrow",
            &flags(parsed, &["field"]),
            &positionals(parsed, &["consumer", "item"])?,
        ),
        // `--token-file` and never `--token`: the command line offers both, and
        // a loopback body is the one place a bearer must not travel, so a
        // console proves possession through the same owner-only file the
        // widening route already requires.
        "/v1/operator/grants/verify" => grant(
            "verify",
            &flags(parsed, &["action", "field", "token-file"]),
            &positionals(parsed, &["consumer", "item"])?,
        ),
        "/v1/operator/grants/revoke" => {
            grant("revoke", &no_flags, &positionals(parsed, &["consumer"])?)
        }
        "/v1/operator/donations/accept" => {
            inbox("donation accept", &no_flags, &positionals(parsed, &["id"])?)
        }
        "/v1/operator/donations/reject" => {
            inbox("donation reject", &no_flags, &positionals(parsed, &["id"])?)
        }
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
        "/v1/operator/credential" => {
            let operation = text(parsed, "operation")?;
            if ![
                "status", "acquire", "rotate", "resume", "get", "set", "set-json", "totp",
            ]
            .contains(&operation.as_str())
            {
                bail!(
                    "operator credential operation must be one of status, acquire, rotate, resume, get, set, set-json, totp"
                );
            }
            credential_operation(operation, parsed)
        }
        "/v1/operator/emergency/grant" => access(
            &leaf(path),
            &flags(parsed, &["activate-after"]),
            &positionals(parsed, &["grantee"])?,
        ),
        "/v1/operator/emergency/cancel" => {
            access(&leaf(path), &no_flags, &positionals(parsed, &["grantee"])?)
        }
        "/v1/operator/emergency/activate" => {
            access(&leaf(path), &no_flags, &positionals(parsed, &["grantee"])?)
        }
        "/v1/operator/recovery/drill" => {
            access(&leaf(path), &no_flags, &positionals(parsed, &["subject"])?)
        }
        "/v1/operator/policy/set" => access(
            "policy set",
            &no_flags,
            &positionals(parsed, &["key", "value"])?,
        ),
        "/v1/operator/policy/unset" => {
            access("policy unset", &no_flags, &positionals(parsed, &["key"])?)
        }
        // The candidate travels in the request body, never in a command's
        // argv, and the answer never repeats it.
        "/v1/operator/policy/check" => crate::access::policy::check(&text(parsed, "candidate")?),
        "/v1/operator/sync/init" => net(
            "mirror init",
            &no_flags,
            &positionals(parsed, &["endpoint"])?,
        ),
        "/v1/operator/sync/push" => net("mirror push", &flags(parsed, &["message"]), &none),
        "/v1/operator/sync/pull" => net("mirror pull", &flags(parsed, &["force"]), &none),
        "/v1/operator/route/declare" => access(
            "route",
            &flags(parsed, &["resource", "item", "field", "reason"]),
            &["declare".to_string()],
        ),
        "/v1/operator/route/withdraw" => access(
            "route",
            &flags(parsed, &["resource", "reason"]),
            &["withdraw".to_string()],
        ),
        _ => bail!("unknown operator route: {path}"),
    }
}

/// The backend leaf a route under a grouped object names: the path below
/// `/v1/operator/` with its separators read as spaces, so
/// `/v1/operator/emergency/grant` calls `emergency grant`.
fn leaf(path: &str) -> String {
    path.trim_start_matches("/v1/operator/").replace('/', " ")
}
