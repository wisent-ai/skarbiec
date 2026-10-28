// Deciding an access request: who may, what they must state, and the grant an
// approval issues.
//
// Only a vault recipient with role owner or admin decides, and only one whose
// secret key is in this host's keyring, so the person deciding is the person
// who holds that key here (docs/design/access-requests.md, decision 1). The
// decider states the lifetime and, for a capability, the number of uses; no
// default stands in for either. A dual-control request is granted only after
// two different deciders approved it, within the narrower of their bounds.
// A register record missing a field this reads is refused naming the field.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::num::NonZeroU64;

use super::register::{self, text};
use super::Lifetime;
use crate::core::{crypto, vault::Vault, vault_path};

/// A recipient's role as the vault's recipients table records it, and the
/// role a request names as its decider. Any other word is a member's role,
/// or, as a decider, one recipient's uid.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Role {
    Owner,
    Admin,
    #[serde(other)]
    Other,
}

/// The grant a request names (`grant.form` in the register).
#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Form {
    /// A bounded capability, redeemable with the request id.
    Capability,
    /// A standing consumer grant.
    Consumer,
    /// A device or membership request the owning product acts on.
    Record,
}

impl Form {
    /// The form a register record's grant names, or the refusal saying so.
    pub(super) fn of(record: &Value) -> Result<Self> {
        serde_json::from_value(record["grant"]["form"].clone()).with_context(|| {
            format!("access request {} names no readable grant form: {}", record["id"], record["grant"])
        })
    }
}

/// How a request is closed without a grant.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Closing {
    /// Any one eligible decider refuses it.
    Deny,
    /// The requesting agent, or an eligible decider, takes it back.
    Withdraw,
}

impl Closing {
    /// The decision's answer, the state it leaves and the journal op.
    fn words(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Closing::Deny => ("deny", "denied", "access-denied"),
            Closing::Withdraw => ("withdraw", "withdrawn", "access-withdrawn"),
        }
    }
}

/// Refuse anyone who may not decide this request, naming why.
fn authorize(record: &Value, by: &str) -> Result<()> {
    let id = text(record, "id")?;
    let state = text(record, "state")?;
    if state != "pending" {
        bail!("access request {id} is {state}, not pending");
    }
    let vault = Vault::open(vault_path())?;
    let recipient = vault
        .doc()
        .get("recipients")
        .and_then(|recipients| recipients.get(by))
        .with_context(|| format!("{by} is not a recipient of this vault and cannot decide"))?;
    let role: Role = serde_json::from_value(recipient["role"].clone())
        .with_context(|| format!("{by}'s recipient record holds no readable role"))?;
    if role == Role::Other {
        bail!("{by} has role {}: only a recipient with role owner or admin may decide", recipient["role"]);
    }
    let decider = text(record, "decider")?;
    let named = match serde_json::from_value::<Role>(record["decider"].clone())
        .with_context(|| format!("access request {id} names no readable decider"))?
    {
        Role::Admin => true,
        Role::Owner => role == Role::Owner,
        Role::Other => decider == by,
    };
    if !named {
        bail!("access request {id} is for {decider} to decide, not {by}");
    }
    let fingerprint = recipient["fingerprint"]
        .as_str()
        .with_context(|| format!("{by}'s recipient record holds no key fingerprint"))?;
    if !crypto::secret_key_present(fingerprint)? {
        bail!("{by}'s secret key is not in this host's keyring: decide where {by} holds it");
    }
    let decided = record["decisions"].as_array().into_iter().flatten().any(|decision| decision["by"] == by);
    if decided {
        bail!("{by} already decided access request {id}");
    }
    Ok(())
}

/// The uses a decider states, checked against the grant the request names.
fn uses_for(form: Form, uses: Option<u64>, lifetime: Lifetime) -> Result<Option<u64>> {
    match (form, uses) {
        (Form::Capability, None) => {
            bail!("a capability is redeemed a stated number of times: --uses <N> is required")
        }
        (Form::Capability, Some(_)) if lifetime == Lifetime::UntilRevoked => {
            bail!("a capability always expires: state --ttl-seconds <N> instead of --until-revoked")
        }
        (Form::Consumer, Some(_)) => bail!("a standing consumer grant is not counted in uses: drop --uses"),
        (_, Some(uses)) if NonZeroU64::new(uses).is_none() => bail!("--uses must be at least one"),
        (_, uses) => Ok(uses),
    }
}

/// Issue the grant the request names, within the bounds the deciders stated.
fn issue(record: &Value, lifetime: Lifetime, uses: Option<u64>) -> Result<Value> {
    let id = text(record, "id")?;
    let grant = &record["grant"];
    match Form::of(record)? {
        Form::Capability => {
            let Lifetime::Seconds(ttl) = lifetime else {
                bail!("a capability always expires");
            };
            let uses = uses.context("a capability needs a stated number of uses")?;
            let flags = HashMap::from([
                ("agent", text(&record["requester"], "agent")?.to_string()),
                ("purpose", text(grant, "purpose")?.to_string()),
                ("resource", text(record, "resource")?.to_string()),
                ("target", text(grant, "target")?.to_string()),
                ("ttl", ttl.to_string()),
                ("max-uses", uses.to_string()),
                ("authorization-id", id.to_string()),
            ])
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect();
            let issued = crate::access::grant::dispatch("grant", &flags, &["capability".into()])?
                .context("grant capability produced no answer")?;
            Ok(json!({
                "form": "capability",
                "capability_id": issued["capability_id"],
                "authorization_id": id,
                "expires_at": crate::core::clock::now_epoch().checked_add_unsigned(ttl),
            }))
        }
        Form::Consumer => {
            let consumer = text(grant, "consumer")?;
            let vault = Vault::open(vault_path())?;
            if vault.doc()["tokens"].get(consumer).is_some() {
                bail!(
                    "consumer {consumer} already holds a grant; approving would replace its bearer \
                     and capabilities. Deny this request and ask for a fresh consumer name, or \
                     revoke the existing grant first"
                );
            }
            let token_file = register::token_path(id);
            register::write_private(&token_file, crypto::random_token()?.as_bytes())?;
            let mut flags = HashMap::from([
                (
                    "capabilities".to_string(),
                    format!("{}:{}", text(record, "action")?, text(record, "resource")?),
                ),
                ("token-file".to_string(), token_file.display().to_string()),
            ]);
            match lifetime {
                Lifetime::Seconds(ttl) => flags.insert("ttl-seconds".into(), ttl.to_string()),
                Lifetime::UntilRevoked => flags.insert("until-revoked".into(), "true".into()),
            };
            let issued = crate::access::grant::dispatch("grant", &flags, &["issue".into(), consumer.into()]);
            let issued = match issued {
                Ok(answer) => answer.context("grant issue produced no answer")?,
                Err(error) => {
                    if let Err(cleanup) = std::fs::remove_file(&token_file) {
                        return Err(error.context(format!(
                            "the bearer written for this unissued grant could not be removed from {}: {cleanup}",
                            token_file.display()
                        )));
                    }
                    return Err(error);
                }
            };
            Ok(json!({
                "form": "consumer",
                "consumer": consumer,
                "capabilities": issued["capabilities"],
                "expires_at": issued["expires_at"],
                "token_file": token_file.display().to_string(),
            }))
        }
        // Device permissions and memberships are granted by the product that
        // owns them; the register is their record of what a person approved.
        Form::Record => Ok(json!({"form": "record", "owner_acts": text(record, "kind")?})),
    }
}

/// Record one approval; issue the grant once enough deciders approved.
pub(crate) fn approve(id: &str, by: &str, lifetime: Lifetime, uses: Option<u64>) -> Result<Value> {
    let held = register::lock()?;
    let mut doc = register::load()?;
    let record = register::find(&mut doc, id)?;
    authorize(record, by)?;
    let uses = uses_for(Form::of(record)?, uses, lifetime)?;
    let decision = json!({
        "by": by,
        "at": crate::core::clock::now_iso(),
        "answer": "approve",
        "lifetime": lifetime.json(),
        "uses": uses,
    });
    record["decisions"].as_array_mut().context("access request has no decisions list")?.push(decision);
    let approvals: Vec<&Value> =
        record["decisions"].as_array().into_iter().flatten().filter(|decision| decision["answer"] == "approve").collect();
    // Dual control needs a second decider: `authorize` refuses one who has
    // already decided, so every further approval is a different person.
    let granted = if record["dual_control"] == json!(true) {
        approvals.split_first().is_some_and(|(_, others)| !others.is_empty())
    } else {
        !approvals.is_empty()
    };
    if granted {
        let bound = approvals
            .iter()
            .map(|decision| Lifetime::from_json(&decision["lifetime"]))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .reduce(Lifetime::narrower)
            .context("access request granted without a recorded approval lifetime")?;
        let fewest = approvals.iter().filter_map(|decision| decision["uses"].as_u64()).min();
        let issued = issue(record, bound, fewest)?;
        record["issued"] = issued;
        record["state"] = json!("approved");
    }
    let answer = record.clone();
    register::save(&doc, &held)?;
    crate::runtime::audit::append(
        "access-approved",
        &json!({
            "request": id,
            "by": by,
            "lifetime": lifetime.json(),
            "uses": uses,
            "granted": granted,
            "capability_id": answer["issued"]["capability_id"],
            "consumer": answer["issued"]["consumer"],
        }),
    )?;
    Ok(json!({
        "ok": true,
        "request_id": id,
        "state": answer["state"],
        "status": if granted { "granted" } else { "awaiting-second-decider" },
        "issued": answer["issued"],
    }))
}

/// Deny (any one eligible decider) or withdraw (the requesting agent or an
/// eligible decider): either closes the request and issues nothing.
pub(crate) fn close(id: &str, by: &str, closing: Closing, reason: Option<&str>) -> Result<Value> {
    let held = register::lock()?;
    let mut doc = register::load()?;
    let record = register::find(&mut doc, id)?;
    let by_requester = closing == Closing::Withdraw && text(&record["requester"], "agent")? == by;
    if by_requester {
        let state = text(record, "state")?;
        if state != "pending" {
            bail!("access request {id} is {state}, not pending");
        }
    } else {
        authorize(record, by)?;
    }
    let (answer, state, op) = closing.words();
    record["decisions"].as_array_mut().context("access request has no decisions list")?.push(json!({
        "by": by,
        "at": crate::core::clock::now_iso(),
        "answer": answer,
        "lifetime": Value::Null,
        "uses": Value::Null,
        "reason": reason,
    }));
    record["state"] = json!(state);
    register::save(&doc, &held)?;
    crate::runtime::audit::append(op, &json!({"request": id, "by": by}))?;
    Ok(json!({"ok": true, "request_id": id, "state": state}))
}
