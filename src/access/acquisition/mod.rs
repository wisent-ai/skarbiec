// Field-bound, single-use acquisition bearers. Registered workload identities
// may request an acquisition but can never read directly.
//
// No lifetime is configured. A bearer lives until it is spent or until the
// acquire grant that lent it ends, whichever comes first: it can never
// outlive the authority behind it, and nothing shorter has a source. A
// workload proof is fresh when it was signed no later than now and no
// earlier than the newest proof this workload already spent; its nonce is
// remembered until the grant ends, so a proof is accepted once.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::access::grant;
use crate::core::{crypto, schema, vault::Vault, vault_path};

mod commands;
mod proof;
pub(crate) mod role;
mod state;
pub use commands::dispatch;

use proof::{
    exact_name, purge_expired, valid_nonce, valid_workload_id, validate_target,
    verify_workload_proof, workload_payload,
};
use state::{acquire_lock, load_state, now_epoch, save_state, state_path};

#[derive(Debug)]
pub(crate) struct AcquisitionFieldMissing;

impl std::fmt::Display for AcquisitionFieldMissing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("acquisition field does not exist on item")
    }
}

impl std::error::Error for AcquisitionFieldMissing {}

pub struct IssuedAcquisition {
    pub token: String,
    pub expires_at: u64,
}

/// One redeemed acquisition: the bound field, and the item's declared provider
/// when it declares one.
pub struct AcquiredField {
    pub value: Value,
    pub provider: Option<String>,
}

/// The provider this credential belongs to, as the item itself declares it.
///
/// A reset flow has to know whether an account is Entra or consumer Microsoft
/// before it can drive anything, and the authoritative statement of that is
/// `context.provider`, sealed inside the ciphertext. Returning only the field
/// left the caller no way to ask, so the caller kept its own copy of the
/// mapping -- a hardcoded list of item names in another repository, which is a
/// second source of truth this response's shape created.
///
/// `provider` alone, deliberately, not the context object. The rest of what
/// context carries is either a personal identifier (`account_ref` is an
/// account address, and on a `login` item it restates the sealed `username`
/// field the caller holds no capability for), a customer identifier
/// (`tenant_ref`), lifecycle bookkeeping the caller already minted
/// (`request_id`, `operation`), or trajectory input nothing here needs
/// (`login_url`, `domains`, `session_label`, `login_method`, `name`,
/// `source_kind`). Two further members -- the sealed directory identity and
/// the provider receipt -- are owned end to end by the credential lifecycle.
/// A caller that genuinely needs the whole object asks for it with
/// `read:<item>#context`, which is the capability that exists for it.
///
/// Bounded with the same predicate capability routing applies to a declared
/// provider tag, so a value carrying a newline cannot break the line a caller
/// logs it on. A provider that is missing, non-text or unbounded yields
/// `None`, and `None` omits the key entirely: absence has to stay absence, not
/// an empty string a caller could read as a declaration.
fn declared_provider(payload: &Value) -> Option<String> {
    schema::field(payload, "context")
        .ok()?
        .get("provider")
        .and_then(Value::as_str)
        .filter(|provider| schema::exact_token(provider))
        .map(str::to_string)
}

pub fn issue(
    consumer: &str,
    item: &str,
    field: &str,
    workload_id: &str,
    timestamp: u64,
    nonce: &str,
    signature: &str,
) -> Result<Option<IssuedAcquisition>> {
    if !exact_name(consumer)
        || !role::exact_coordinate(item)
        || !exact_name(field)
        || !valid_workload_id(workload_id)
        || !valid_nonce(nonce)
    {
        return Ok(None);
    }
    let vault = Vault::open(vault_path())?;
    let Some(lent) = grant::acquisition_grant(&vault, consumer, item, field) else {
        return Ok(None);
    };
    let now = now_epoch()?;
    if timestamp > now {
        return Ok(None);
    }
    let payload = workload_payload(consumer, item, field, workload_id, timestamp, nonce);
    if !verify_workload_proof(&lent.public_key, &payload, signature)? {
        return Ok(None);
    }
    // A missing field is returned only after the workload proves its identity.
    // The caller can then distinguish optional material from an authority
    // outage without turning the endpoint into a field-existence oracle.
    validate_target(&vault, &role::item_for(&vault, item)?, field)?;

    let path = state_path();
    let _lock = acquire_lock(&path)?;
    let mut state = load_state(&path)?;
    purge_expired(&mut state, now)?;
    // A proof older than the newest one this workload already spent is a
    // captured proof being replayed late, not the workload asking now.
    let newest = state
        .pointer(&format!(
            "/workloads/{}/newest",
            pointer_segment(workload_id)
        ))
        .and_then(Value::as_u64);
    if newest.is_some_and(|newest| timestamp < newest) {
        return Ok(None);
    }
    let proof_hash = crypto::sha256_hex(&format!("{workload_id}\0{nonce}"))?;
    let proofs = state
        .get_mut("proofs")
        .and_then(Value::as_object_mut)
        .context("acquisition proofs section")?;
    if proofs.contains_key(&proof_hash) {
        return Ok(None);
    }
    // The proof's nonce is refused as a replay for as long as the grant that
    // could accept it lasts.
    proofs.insert(proof_hash, json!(lent.expires_at));
    state
        .get_mut("workloads")
        .and_then(Value::as_object_mut)
        .context("acquisition workloads section")?
        .insert(
            workload_id.to_string(),
            json!({ "newest": timestamp, "expires_at": lent.expires_at }),
        );
    let expires_at = lent.expires_at;
    let token = crypto::random_token()?;
    let hash = crypto::sha256_hex(&token)?;
    let tokens = state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?;
    if tokens.contains_key(&hash) {
        bail!("acquisition token collision");
    }
    tokens.insert(
        hash,
        json!({
            "consumer": consumer,
            "item": item,
            "field": field,
            "expires_at": expires_at,
            "workload_id": workload_id,
        }),
    );
    save_state(&path, &state)?;
    Ok(Some(IssuedAcquisition { token, expires_at }))
}

pub fn consume(
    consumer: &str,
    presented: &str,
    item: &str,
    field: &str,
) -> Result<Option<AcquiredField>> {
    if !exact_name(consumer)
        || !role::exact_coordinate(item)
        || !exact_name(field)
        || presented.is_empty()
    {
        return Ok(None);
    }
    let hash = crypto::sha256_hex(presented)?;
    let path = state_path();
    let _lock = acquire_lock(&path)?;
    let mut state = load_state(&path)?;
    let now = now_epoch()?;
    let record = state
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get(&hash))
        .cloned();
    let Some(record) = record else {
        return Ok(None);
    };
    let expired = match record.get("expires_at").and_then(Value::as_u64) {
        Some(expiry) => expiry <= now,
        None => true,
    };
    if expired {
        state
            .get_mut("tokens")
            .and_then(Value::as_object_mut)
            .context("acquisition tokens section")?
            .remove(&hash);
        save_state(&path, &state)?;
        return Ok(None);
    }
    let bound = record.get("consumer").and_then(Value::as_str) == Some(consumer)
        && record.get("item").and_then(Value::as_str) == Some(item)
        && record.get("field").and_then(Value::as_str) == Some(field);
    if !bound {
        return Ok(None);
    }

    let vault = Vault::open(vault_path())?;
    // The token is bound to the coordinate the workload asked for; a role
    // coordinate reads the item playing that role now, so replacing the item
    // between issue and read hands over the new one.
    let item = role::item_for(&vault, item)?;
    let item = item.as_str();
    // While an adopt is in flight the operator-supplied candidate is the only
    // value that proves anything, and only the adopt verification path may
    // read it. Outside that exact window a candidate is unreadable and the
    // single-use bearer is left unspent.
    //
    // The payload comes back from both branches so provenance costs no
    // decryption the redemption was not already paying: the current branch
    // opens the item anyway to take the field out of it. Only the staged
    // branch, the adopt window, adds one open, and it adds it with `ok()` --
    // provenance must never turn a redemption that has already proved its
    // capability into a failure.
    let (value, payload) = match crate::credential::managed_read(&vault, item, field, consumer)? {
        crate::credential::ManagedRead::Staged(candidate) => (candidate, vault.get_item(item).ok()),
        crate::credential::ManagedRead::Refused => return Ok(None),
        crate::credential::ManagedRead::Current => {
            let payload = vault.get_item(item)?;
            let value = schema::field(&payload, field)
                .cloned()
                .context("acquisition field no longer exists on item")?;
            (value, Some(payload))
        }
    };
    let provider = payload.as_ref().and_then(declared_provider);
    state
        .get_mut("tokens")
        .and_then(Value::as_object_mut)
        .context("acquisition tokens section")?
        .remove(&hash);
    save_state(&path, &state)?;
    Ok(Some(AcquiredField { value, provider }))
}

/// A key as one segment of a JSON pointer (RFC 6901): `~` and `/` escaped.
fn pointer_segment(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}
