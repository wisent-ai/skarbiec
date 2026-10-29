// Access requests: an agent asks, a person decides, Skarbiec grants
// (docs/design/access-requests.md).
//
// `request file|list|show|approve|deny|withdraw|watch` is a group like
// `donation`: the object is the command and the verb its first positional,
// and the operator routes call the leaves by their whole name.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

mod decide;
mod file;
mod register;
mod watch;

pub(crate) use file::{Filing, Kind};

use crate::cli::args::{OrUsage, Usage};

const COMMANDS: &[&str] = &[
    "request file --kind secret|device|membership --resource <resource> --action <action> --reason <text> --agent <name> [--harness <name>] [--host <name>] [--person <name>] [--decider owner|admin|<uid>] [--dual-control] [--purpose <p> --target <t> --ttl-seconds <N> --max-uses <N> | --for-consumer <name>] [--to <base-url> --consumer <name> --token-file <path>]",
    "request list [--state pending|approved|denied|withdrawn]",
    "request show <request-id>",
    "request approve <request-id> --by <uid> (--ttl-seconds <N> | --until-revoked) [--uses <N>]",
    "request deny <request-id> --by <uid> [--reason <text>]",
    "request withdraw <request-id> --by <agent-or-uid>",
    "request watch --local --by <uid>",
];

const USAGE: &str = "request file records what an agent asks for, why and for whom, and journals it; with --to it files into another host's register through POST /v1/access-requests, authorized by a request:<kind> grant there. A secret request names a bounded capability (--purpose, --target and the asked --ttl-seconds and --max-uses) or a standing consumer grant (--for-consumer); device and membership requests are recorded for the product that owns them. request approve is taken by a recipient with role owner or admin whose secret key is on this host, and must state the lifetime (--ttl-seconds or --until-revoked) and, for a capability, --uses: a capability is issued with the request id as its authorization id, a standing grant's bearer is written to an owner-only file named in the answer. A dual-control request (asked so, or resolving to an item tagged dual-control) is granted only after two different deciders approved it, within the narrower of their bounds. request deny and request withdraw close a request and issue nothing. request watch --local shows each pending request in a macOS dialog and applies the answer.";

/// What the decider said about how long the grant lives.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lifetime {
    Seconds(u64),
    UntilRevoked,
}

impl Lifetime {
    pub(crate) fn from_flags(flags: &HashMap<String, String>) -> Result<Self> {
        let until_revoked = crate::cli::args::flag_set(flags, "until-revoked");
        match (flags.get("ttl-seconds"), until_revoked) {
            (Some(_), true) => bail!("--ttl-seconds and --until-revoked are exclusive"),
            (None, true) => Ok(Self::UntilRevoked),
            (Some(raw), false) => {
                let seconds: u64 = raw.parse().context("--ttl-seconds must be whole seconds")?;
                if seconds == 0 {
                    bail!("--ttl-seconds must be at least one second");
                }
                Ok(Self::Seconds(seconds))
            }
            (None, false) => bail!(
                "request approve requires the decider to state the lifetime: \
                 --ttl-seconds <N> or --until-revoked"
            ),
        }
    }

    fn json(self) -> Value {
        match self {
            Self::Seconds(seconds) => json!(seconds),
            Self::UntilRevoked => json!("until-revoked"),
        }
    }

    /// The lifetime an approval recorded, as [`Lifetime::json`] wrote it.
    fn from_json(value: &Value) -> Result<Self> {
        if let Some(seconds) = value.as_u64() {
            return Ok(Self::Seconds(seconds));
        }
        if *value == Self::UntilRevoked.json() {
            return Ok(Self::UntilRevoked);
        }
        bail!("an approval records the lifetime {value}, which is neither whole seconds nor until-revoked")
    }

    fn narrower(self, other: Self) -> Self {
        match (self, other) {
            (Self::Seconds(a), Self::Seconds(b)) => Self::Seconds(a.min(b)),
            (Self::Seconds(a), Self::UntilRevoked) | (Self::UntilRevoked, Self::Seconds(a)) => {
                Self::Seconds(a)
            }
            (Self::UntilRevoked, Self::UntilRevoked) => Self::UntilRevoked,
        }
    }
}

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command == "request" {
        let Some((verb, rest)) = positionals.split_first() else {
            return Err(Usage(
                "request needs a subcommand; `skarbiec request help` lists them".to_string(),
            )
            .into());
        };
        if verb == "help" {
            return Ok(Some(json!({"commands": COMMANDS, "usage": USAGE})));
        }
        return leaf(&format!("request {verb}"), flags, rest)?
            .ok_or_else(|| {
                Usage(format!(
                    "unknown request command: {verb}; `skarbiec request help` lists them"
                ))
                .into()
            })
            .map(Some);
    }
    leaf(command, flags, positionals)
}

fn id_and_by<'a>(
    flags: &'a HashMap<String, String>,
    positionals: &'a [String],
    usage: &str,
) -> Result<(&'a str, &'a str)> {
    let id = positionals.first().or_usage(usage)?;
    let by = flags
        .get("by")
        .filter(|by| by.as_str() != "true")
        .or_usage(&format!("{usage}: --by names who decides"))?;
    Ok((id, by))
}

fn leaf(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "request file" => {
            if let Some(to) = flags.get("to") {
                return file_remote(to, flags).map(Some);
            }
            let record = file::file(Filing::from_flags(flags, "cli")?, false)?;
            Ok(Some(json!({
                "ok": true,
                "status": "pending",
                "request_id": record["id"],
                "dual_control": record["dual_control"],
            })))
        }
        "request list" => {
            let doc = register::load()?;
            let state = flags.get("state").map(String::as_str);
            let listing: Vec<Value> = register::requests(&doc)
                .filter(|record| state.is_none_or(|state| record["state"] == state))
                .map(|record| {
                    json!({
                        "id": record["id"],
                        "requested_at": record["requested_at"],
                        "state": record["state"],
                        "kind": record["kind"],
                        "resource": record["resource"],
                        "action": record["action"],
                        "agent": record["requester"]["agent"],
                        "decider": record["decider"],
                        "dual_control": record["dual_control"],
                        "decisions": record["decisions"].as_array().map(Vec::len),
                    })
                })
                .collect();
            Ok(Some(json!(listing)))
        }
        "request show" => {
            let id = positionals
                .first()
                .or_usage("usage: request show <request-id>")?;
            Ok(Some(register::get(&register::load()?, id)?))
        }
        "request approve" => {
            let (id, by) = id_and_by(flags, positionals, "usage: request approve <request-id> --by <uid> (--ttl-seconds <N> | --until-revoked) [--uses <N>]")?;
            let lifetime = Lifetime::from_flags(flags)?;
            let uses = flags
                .get("uses")
                .map(|raw| raw.parse::<u64>().context("--uses must be a whole number"))
                .transpose()?;
            decide::approve(id, by, lifetime, uses).map(Some)
        }
        "request deny" => {
            let (id, by) = id_and_by(
                flags,
                positionals,
                "usage: request deny <request-id> --by <uid>",
            )?;
            let reason = flags.get("reason").map(String::as_str);
            decide::close(id, by, decide::Closing::Deny, reason).map(Some)
        }
        "request withdraw" => {
            let (id, by) = id_and_by(
                flags,
                positionals,
                "usage: request withdraw <request-id> --by <agent-or-uid>",
            )?;
            decide::close(id, by, decide::Closing::Withdraw, None).map(Some)
        }
        "request watch" => {
            if !crate::cli::args::flag_set(flags, "local") {
                bail!("request watch needs --local: the local dialog is the only channel this build delivers to");
            }
            let by = flags
                .get("by")
                .filter(|by| by.as_str() != "true")
                .or_usage("usage: request watch --local --by <uid>")?;
            watch::watch(by)?;
            Ok(Some(json!({"ok": true})))
        }
        _ => Ok(None),
    }
}

/// File into another host's register. The bearer is read from an owner-only
/// file and travels only in the request header, never in argv or the body.
fn file_remote(to: &str, flags: &HashMap<String, String>) -> Result<Value> {
    let consumer = flags
        .get("consumer")
        .or_usage("--to needs --consumer <name>")?;
    let token = crate::credential::bearer_from_file(flags, "request file --to")?;
    // Refuse here what the remote would refuse, before anything is sent.
    Filing::from_flags(flags, "http")?;
    let body: serde_json::Map<String, Value> = flags
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "to" | "consumer" | "token-file"))
        .map(|(name, value)| (name.replace('-', "_"), json!(value)))
        .collect();
    let (_status, response) = crate::net::serve::serve_request(
        to,
        "POST",
        "/v1/access-requests",
        consumer,
        &token,
        Some(&Value::Object(body)),
    )?;
    crate::runtime::audit::append(
        "access-request-sent",
        &json!({"to": to, "consumer": consumer, "request": response["request_id"]}),
    )?;
    Ok(response)
}

/// File a request that arrived over HTTP from `consumer`, whose
/// `request:<kind>` grant the route has already checked.
pub(crate) fn file_from_http(body: &Value, consumer: &str) -> Result<Value> {
    let mut body = body.clone();
    if body.get("agent").and_then(Value::as_str).is_none() {
        body["agent"] = json!(consumer);
    }
    let record = file::file(
        Filing::from_body(&body, &format!("http:{consumer}"))?,
        false,
    )?;
    Ok(json!({"ok": true, "status": "pending", "request_id": record["id"]}))
}

/// Every recorded request, for the broker surface.
pub(crate) fn snapshot() -> Result<Vec<Value>> {
    Ok(register::requests(&register::load()?).cloned().collect())
}

/// File a broker capability request, or answer the one already open.
pub(crate) fn file_broker(flags: &HashMap<String, String>) -> Result<Value> {
    file::file(Filing::from_flags(flags, "mcp")?, true)
}
