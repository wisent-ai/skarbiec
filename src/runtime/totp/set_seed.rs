// Storing one item's authenticator seed: the step after a provider shows its
// QR code. The seed arrives on standard input, as a Base32 secret or the
// whole otpauth:// address the QR code encodes, never in an argument, where
// it would sit in every process table on the host. Only the field changes;
// the item's other fields, tags and recipients stay as they were.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;

use crate::cli::args::OrUsage;
use crate::core::{schema, totp, vault::Vault, vault_path};

const SEED_FIELD: &str = "totp_secret";

/// `totp set <id>` with the seed on standard input.
pub fn run(positionals: &[String]) -> Result<Value> {
    let id = positionals
        .first()
        .or_usage("usage: totp set <item-id>  (the Base32 seed or the otpauth:// address on stdin)")?;
    let mut given = String::new();
    std::io::stdin()
        .read_to_string(&mut given)
        .context("the seed could not be read from standard input")?;
    store(id, &given)
}

/// Store `given` as `id`'s seed, after proving it computes a code the way
/// every reader will compute it. The answer carries that current code, so
/// it can be compared with the provider's or the authenticator's at once.
pub fn store(id: &str, given: &str) -> Result<Value> {
    let seed = given_seed(given)?;
    let now = crate::core::clock::epoch_seconds()?;
    let code = totp::code(&seed, now).map_err(|cause| anyhow::anyhow!("the seed was not stored: {cause}"))?;
    let mut vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "store an authenticator seed in")?;
    let mut payload = vault.get_item(id)?;
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{id} records no kind"))?
        .to_string();
    if !schema::kind_allows_field(&kind, SEED_FIELD) {
        bail!("a {kind} item has no {SEED_FIELD} field, so nothing was stored in {id}; a login or an identity holds the seed");
    }
    payload
        .get_mut("fields")
        .and_then(Value::as_object_mut)
        .with_context(|| format!("{id} has no fields object"))?
        .insert(SEED_FIELD.to_string(), json!(seed));
    let recipients = vault.item_recipient_uids(id)?;
    let tags = {
        let entry = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        crate::core::vault::entry_texts(id, entry, "tags")?
    };
    vault.set_item(id, &kind, &payload, &recipients, &tags)?;
    let revision = vault.item_revision(id)?;
    crate::runtime::audit::append("totp-seed-set", &json!({"item": id, "revision": revision}))?;
    Ok(json!({"ok": true, "item": id, "revision": revision, "current_code": code}))
}

/// The Base32 seed in `given`: the value itself, or the `secret` of an
/// otpauth://totp/ address whose algorithm, digits and period, when stated,
/// are the ones every reader computes with. Anything else is refused by
/// name, because a seed stored under other parameters yields codes the
/// provider never accepts. `totp set` and the importer both read seeds here.
pub(crate) fn given_seed(given: &str) -> Result<String> {
    let given = given.trim();
    if given.is_empty() {
        bail!("standard input held no seed; send the Base32 secret or the otpauth:// address");
    }
    let raw = match given.strip_prefix("otpauth://") {
        Some(rest) => {
            let Some(totp_address) = rest.strip_prefix("totp/") else {
                bail!("the address is not otpauth://totp/; only time-based codes are computed here");
            };
            let Some((_, query)) = totp_address.split_once('?') else {
                bail!("the otpauth:// address has no parameters, so it carries no secret");
            };
            let mut parameters: HashMap<String, String> = HashMap::new();
            for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                if parameters.insert(key.to_string(), value.to_string()).is_some() {
                    bail!("the otpauth:// address states {key} twice");
                }
            }
            if let Some(algorithm) = parameters.get("algorithm") {
                if !algorithm.eq_ignore_ascii_case("SHA1") {
                    bail!("the address asks for {algorithm}; codes here are computed with SHA1");
                }
            }
            if let Some(digits) = parameters.get("digits") {
                let stated: usize = digits
                    .parse()
                    .with_context(|| format!("the address states digits={digits}, which is not a number"))?;
                if stated != totp::DIGITS {
                    bail!("the address asks for {stated} digits; codes here have {}", totp::DIGITS);
                }
            }
            if let Some(period) = parameters.get("period") {
                let stated: u64 = period
                    .parse()
                    .with_context(|| format!("the address states period={period}, which is not a number of seconds"))?;
                if stated != totp::PERIOD_SECONDS {
                    bail!("the address asks for a {stated}-second period; codes here change every {} seconds", totp::PERIOD_SECONDS);
                }
            }
            parameters
                .remove("secret")
                .context("the otpauth:// address carries no secret parameter")?
        }
        None => given.to_string(),
    };
    let seed: String = raw
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if !super::base32_seed_shape(&seed) {
        bail!("the seed is not Base32 (letters A to Z and digits 2 to 7); nothing was stored");
    }
    Ok(seed)
}
