// Issuing one bounded redemption of a grant that already exists, and the
// refusal document an operator reads when the coordinate cannot be resolved.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::num::NonZeroU64;

use super::state::{acquire_state_lock, load_state, now_epoch, save_entry};
use crate::core::schema::exact_token;
use crate::core::{crypto, vault::Vault, vault_path};

/// A refusal the caller can act on, on stdout as well as in the error.
///
/// `grant capability` is run as a subprocess by the gateway that needs the
/// credential, and a refusal is rendered by `anyhow` on stderr. A gateway
/// reading the child's stdout therefore recorded `capability_issue_refused`
/// with an empty detail -- seven providers refused at once, and the operator
/// facing message carried nothing at all. A security refusal that will not say
/// what it refused is how a month of quarantined releases named the symptom
/// every time and the cause never.
///
/// So the reason goes to stdout as a document too, naming the coordinate and
/// the command that would repair it, exactly as `route verify` prints its
/// report before failing. The coordinate is configuration, not a secret, and
/// no value is ever read into it.
fn refused(
    resource: &str,
    coordinate: Option<(&str, &str)>,
    reason: &str,
    remedy: &str,
) -> anyhow::Error {
    let document = json!({
        "status": "refused",
        "command": "grant capability",
        "resource": resource,
        "item": coordinate.map(|(item, _)| item),
        "field": coordinate.map(|(_, field)| field),
        "reason": reason,
        "remedy": remedy,
    });
    if let Ok(text) = serde_json::to_string_pretty(&document) {
        println!("{text}");
    }
    anyhow!("grant capability refused for {resource}: {reason}; {remedy}")
}

/// One required flag of `grant capability`, refused by name when it is absent
/// and quoted when it is not one exact identifier.
fn exact_flag<'f>(flags: &'f HashMap<String, String>, name: &str) -> Result<&'f str> {
    match flags.get(name) {
        Some(value) if exact_token(value) => Ok(value),
        Some(value) => bail!("grant capability requires an exact --{name}, not {value:?}"),
        None => bail!("grant capability requires --{name}"),
    }
}

pub(in crate::access) fn issue(flags: &HashMap<String, String>) -> Result<Value> {
    let agent = exact_flag(flags, "agent")?;
    let purpose = exact_flag(flags, "purpose")?;
    let resource = exact_flag(flags, "resource")?;
    let target = exact_flag(flags, "target")?;
    // How long the capability lives and how many times it may be redeemed are
    // the issuer's to state on every issue; Skarbiec holds no default and no
    // ceiling for either.
    let ttl = flags
        .get("ttl")
        .context("grant capability requires --ttl: the capability's lifetime in whole seconds")?
        .parse::<NonZeroU64>()
        .context("--ttl must be whole seconds, at least one")?
        .get();
    let max_uses = flags
        .get("max-uses")
        .context(
            "grant capability requires --max-uses: how many times the capability may be redeemed",
        )?
        .parse::<NonZeroU64>()
        .context("--max-uses must be a whole number, at least one")?
        .get();
    // Without --authorization-id the capability is bound to no authorization,
    // stored as the empty identifier redemption compares against.
    let authorization_id = match flags.get("authorization-id") {
        Some(id) => id.clone(),
        None => String::new(),
    };
    if !authorization_id.is_empty() && !exact_token(&authorization_id) {
        bail!("--authorization-id must be one exact identifier");
    }
    // A capability whose resource resolves to nothing would be issued now and fail
    // only at redemption, inside a flow that has already spent its one Apple password
    // submit. Refuse at issue time. `challenge:` is the documented exception: its
    // value is written later, by the relay.
    //
    // The resolution asked here is the capability's own, so a resource is resolved
    // from what the vault declares -- including a provider whose item was renamed
    // after the grant was written, which used to be issued against a stale table row
    // and refused at the far end. A route can also resolve and the credential behind
    // it still hold nothing, so the credential itself is checked here too, in
    // `route verify`'s words.
    if !resource.starts_with("challenge:") {
        let (item, field) =
            match crate::access::route::resolution::coordinate_for(resource)? {
                Ok(coordinate) => coordinate,
                Err(problem) => return Err(refused(
                    resource,
                    None,
                    &problem,
                    "declare it with: skarbiec route declare --resource <resource> --item <item> \
                     --field <field> --reason <text>, or tag the item it should resolve from",
                )),
            };
        let vault = Vault::open(vault_path())?;
        let mut opened = HashMap::new();
        if let Some(problem) =
            crate::access::route::coordinate::coordinate(&vault, &mut opened, &item, &field, None)
                .problem
        {
            return Err(refused(
                resource,
                Some((&item, &field)),
                &problem,
                "inspect every route with: skarbiec route verify, or skarbiec doctor",
            ));
        }
    }

    let capability_id = crypto::sha256_hex(&crypto::random_token()?)?;
    let now = now_epoch()?;
    let expires_at = now
        .checked_add(ttl)
        .context("--ttl exceeds the representable capability expiry timestamp")?;
    let _state_lock = acquire_state_lock()?;
    let mut state = load_state()?;
    state["capabilities"][&capability_id] = json!({
        "agent": agent,
        "purpose": purpose,
        "resource": resource,
        "target": target,
        "authorization_id": authorization_id,
        "issued_at": now,
        "expires_at": expires_at,
        "remaining_uses": max_uses,
        "state": "issued",
    });
    save_entry(&state, &capability_id, None)?;
    Ok(json!({"capability_id": capability_id, "status": "issued"}))
}
