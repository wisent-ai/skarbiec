// Filing an access request. The command line, the broker MCP surface and the
// cross-host `POST /v1/access-requests` route all arrive here with the same
// flags, so a request means the same thing whoever filed it.
//
// A secret request names one of two grants, and the decider later states its
// lifetime: a bounded capability (`grant capability`, redeemable only with the
// request id signed into the proof) or a standing consumer grant (`grant
// issue`). Device and membership requests are recorded for the product that
// owns that authority (Tama, the organization) to act on once approved.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::num::NonZeroU64;

use super::register;
use crate::cli::args::OrUsage;
use crate::core::schema::{exact_component, exact_token};
use crate::core::{vault::Vault, vault_path};

/// What a request asks for: a vault secret, a permission on a device, or a
/// membership (an organization or another person's vault). The names are the
/// wire form `--kind`, the `kind` body field and `request:<kind>` grants carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Secret,
    Device,
    Membership,
}

impl Kind {
    const ALL: &'static [Kind] = &[Kind::Secret, Kind::Device, Kind::Membership];

    /// The kind a wire name means, or a refusal naming every kind.
    pub(crate) fn named(word: &str) -> Result<Self> {
        serde_json::from_value(json!(word)).map_err(|cause| {
            anyhow!(
                "{word:?} is no request kind ({cause}); a kind is one of {}",
                Self::listed(", ")
            )
        })
    }

    /// The wire name of this kind.
    pub(crate) fn name(self) -> Result<String> {
        match serde_json::to_value(self)? {
            Value::String(name) => Ok(name),
            other => bail!("request kind {self:?} serialized as {other}, not as a name"),
        }
    }

    /// Every kind's wire name joined by `separator`, or why one could not be named.
    pub(crate) fn listed(separator: &str) -> String {
        let named: Result<Vec<String>> = Self::ALL.iter().map(|kind| kind.name()).collect();
        match named {
            Ok(names) => names.join(separator),
            Err(cause) => format!("(the request kinds could not be named: {cause})"),
        }
    }
}

/// Who decides a request whose filing names no `--decider`: any owner or
/// admin, as docs/design/access-requests.md ("Implemented in Skarbiec") states.
const DEFAULT_DECIDER: &str = "admin";

/// The item tag by which a vault owner marks an item as needing two
/// different deciders (docs/design/access-requests.md, decision 3).
pub(super) const DUAL_CONTROL_TAG: &str = "dual-control";

const SECRET_FORMS: &str = "a secret request names either a bounded capability \
    (--purpose --target --ttl-seconds --max-uses, with --action read) or a standing \
    consumer grant (--for-consumer <name>)";

/// One request as filed, before it is recorded.
pub(crate) struct Filing {
    requester: Value,
    kind: Kind,
    resource: String,
    action: String,
    reason: String,
    decider: String,
    dual_control: bool,
    /// The vault item a secret request reaches, whose tags can require two
    /// deciders; none for a request that is no vault grant.
    item: Option<String>,
    grant: Value,
    via: String,
}

fn required<'a>(flags: &'a HashMap<String, String>, name: &str) -> Result<&'a str> {
    let value = flags
        .get(name)
        .map(String::as_str)
        .or_usage(&format!("request file requires --{name}"))?;
    if !exact_token(value) || value.trim() != value || value == "true" {
        bail!("--{name} must be one line of text without surrounding space");
    }
    Ok(value)
}

fn optional(flags: &HashMap<String, String>, name: &str) -> Result<Value> {
    match flags.get(name) {
        None => Ok(Value::Null),
        Some(value) if exact_token(value) && value != "true" => Ok(json!(value)),
        Some(_) => bail!("--{name} must be one line of text"),
    }
}

fn positive(flags: &HashMap<String, String>, name: &str) -> Result<NonZeroU64> {
    required(flags, name)?
        .parse()
        .with_context(|| format!("--{name} must be a whole number of at least one"))
}

/// The one vault item a capability resource resolves to. A resource nothing
/// declares, or two items declare, is refused with the resolution's own
/// sentence: a request for it could never be issued, and filing it would
/// skip the dual-control tag one of its candidates may carry.
fn resolved_item(resource: &str) -> Result<String> {
    match crate::access::route::resolution::coordinate_for(resource)? {
        Ok((item, _)) => Ok(item),
        Err(sentence) => bail!("--resource {resource} cannot be requested: {sentence}"),
    }
}

impl Filing {
    /// A filing from command-line flags; `via` names the surface it came in on.
    pub(crate) fn from_flags(flags: &HashMap<String, String>, via: &str) -> Result<Self> {
        let kind = Kind::named(required(flags, "kind")?)?;
        let decider = match flags.get("decider") {
            Some(named) => named.clone(),
            None => DEFAULT_DECIDER.to_string(),
        };
        if !exact_token(&decider) || decider == "true" {
            bail!("--decider names a recipient uid, or the role owner or admin");
        }
        let asked = [
            flags.get("purpose"),
            flags.get("target"),
            flags.get("ttl-seconds"),
            flags.get("max-uses"),
        ];
        let bounded = asked.iter().any(Option::is_some);
        let standing = flags.contains_key("for-consumer");
        let action = required(flags, "action")?.to_string();
        let resource = required(flags, "resource")?.to_string();
        let (grant, item) = match (kind, bounded, standing) {
            (Kind::Secret, true, false) => {
                if action != "read" {
                    bail!("a bounded capability redeems one value: --action must be read");
                }
                let mut grant = json!({
                    "form": "capability",
                    "purpose": required(flags, "purpose")?,
                    "target": required(flags, "target")?,
                    "ttl_seconds": positive(flags, "ttl-seconds")?,
                    "max_uses": positive(flags, "max-uses")?,
                });
                if let Some(depth) = flags.get("delegation-depth") {
                    let depth: u64 = depth
                        .parse()
                        .context("--delegation-depth must be a whole number")?;
                    grant["delegation_depth"] = json!(depth);
                }
                (grant, Some(resolved_item(&resource)?))
            }
            (Kind::Secret, false, true) => {
                let consumer = required(flags, "for-consumer")?;
                if !exact_component(consumer) {
                    bail!("--for-consumer must be one exact consumer name");
                }
                let item = match resource.split_once('#') {
                    Some((item, _field)) => item.to_string(),
                    None => resource.clone(),
                };
                (
                    json!({"form": "consumer", "consumer": consumer}),
                    Some(item),
                )
            }
            (Kind::Secret, _, _) => bail!("{SECRET_FORMS}"),
            (_, false, false) => (json!({"form": "record"}), None),
            (other, _, _) => bail!(
                "a {} request is recorded for its owning product and names no vault grant: \
                 drop --purpose, --target, --ttl-seconds, --max-uses and --for-consumer",
                other.name()?
            ),
        };
        Ok(Self {
            requester: json!({
                "agent": required(flags, "agent")?,
                "harness": optional(flags, "harness")?,
                "host": optional(flags, "host")?,
                "person": optional(flags, "person")?,
            }),
            resource,
            reason: required(flags, "reason")?.to_string(),
            dual_control: crate::cli::args::flag_set(flags, "dual-control"),
            kind,
            action,
            decider,
            item,
            grant,
            via: via.to_string(),
        })
    }

    /// A filing from a JSON body, read with the same rules as the flags.
    pub(crate) fn from_body(body: &Value, via: &str) -> Result<Self> {
        let mut flags = HashMap::new();
        for (key, value) in body.as_object().into_iter().flatten() {
            let rendered = match value {
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                Value::Bool(true) => "true".to_string(),
                _ => continue,
            };
            flags.insert(key.replace('_', "-"), rendered);
        }
        Self::from_flags(&flags, via)
    }
}

/// Whether the vault item a secret request reaches carries the owner's
/// dual-control tag. Device and membership resources are not vault items.
fn marked_dual_control(item: Option<&str>) -> Result<bool> {
    let Some(item) = item else {
        return Ok(false);
    };
    let vault = Vault::open(vault_path())?;
    Ok(vault
        .doc()
        .get("items")
        .and_then(|items| items.get(&item))
        .and_then(|record| record.get("tags"))
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|tag| tag == DUAL_CONTROL_TAG)))
}

/// The same question asked twice while the first is still open. Fields are
/// compared as stored, so a record missing one never matches a filing.
fn same_question(record: &Value, filing: &Filing) -> bool {
    record["state"] == "pending"
        && record["requester"]["agent"] == filing.requester["agent"]
        && record["kind"] == json!(filing.kind)
        && record["resource"] == json!(filing.resource)
        && record["action"] == json!(filing.action)
        && record["grant"]["form"] == filing.grant["form"]
        && record["grant"]["purpose"] == filing.grant["purpose"]
        && record["grant"]["target"] == filing.grant["target"]
        && record["grant"]["consumer"] == filing.grant["consumer"]
}

/// Record a filing and journal it. With `reuse_open`, an identical request
/// that is still pending is answered instead of filing a second one: an agent
/// asking again must not queue the same question for a person twice.
pub(crate) fn file(filing: Filing, reuse_open: bool) -> Result<Value> {
    let dual_control = filing.dual_control || marked_dual_control(filing.item.as_deref())?;
    let held = register::lock()?;
    let mut doc = register::load()?;
    if reuse_open {
        if let Some(open) = register::requests(&doc).find(|record| same_question(record, &filing)) {
            return Ok(open.clone());
        }
    }
    let record = json!({
        "id": register::new_id()?,
        "requested_at": crate::core::clock::now_iso(),
        "requester": filing.requester,
        "kind": filing.kind,
        "resource": filing.resource,
        "action": filing.action,
        "reason": filing.reason,
        "decider": filing.decider,
        "dual_control": dual_control,
        "grant": filing.grant,
        "via": filing.via,
        "state": "pending",
        "decisions": [],
        "issued": Value::Null,
    });
    doc["requests"]
        .as_array_mut()
        .context("request register has no requests list")?
        .push(record.clone());
    register::save(&doc, &held)?;
    crate::runtime::audit::append(
        "access-requested",
        &json!({
            "request": record["id"],
            "kind": record["kind"],
            "resource": record["resource"],
            "action": record["action"],
            "agent": record["requester"]["agent"],
            "decider": record["decider"],
            "dual_control": dual_control,
            "via": record["via"],
        }),
    )?;
    Ok(record)
}
