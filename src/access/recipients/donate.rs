// p2p outbound write: seal one item's fields JSON to the remote vault's owner
// key (fetched from its serve and imported here), then POST it as a donation.
// The remote side queues it in the inbox.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::OrUsage;
use crate::core::{crypto, vault::Vault, vault_path};

pub(super) fn donate(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let item_id = positionals.first().or_usage(
        "usage: donate <item-id> --to <base-url> --consumer <name> --token-file <path>",
    )?;
    let to = flags.get("to").or_usage("--to required")?;
    let consumer = flags.get("consumer").or_usage("--consumer required")?;
    let token = &crate::credential::bearer_from_file(flags, "donate")?;
    let vault = Vault::open(vault_path())?;
    let payload = vault.get_item(item_id)?;
    let item_kind = vault
        .doc()
        .get("items")
        .and_then(|items| items.get(item_id))
        .and_then(|item| item.get("kind"))
        .and_then(Value::as_str)
        .context("canonical item has no kind")?
        .to_string();
    let (_status, owner) =
        crate::net::bond::serve_request(to, "GET", "/v1/owner-pubkey", consumer, token, None)?;
    let armored = owner
        .get("armored")
        .and_then(Value::as_str)
        .context("remote did not return an owner public key")?;
    let fingerprint = owner
        .get("fingerprint")
        .and_then(Value::as_str)
        .context("remote owner key has no fingerprint")?;
    crypto::import_key(armored).context("import remote owner public key")?;
    let armor = crypto::encrypt_to(
        &[fingerprint.to_string()],
        &serde_json::to_string(&payload)?,
    )?;
    // `--from` names the sender the remote inbox shows; unnamed, the sender
    // is the consumer the bond authenticates as.
    let from = match flags.get("from") {
        Some(from) => from,
        None => consumer,
    };
    let (_status, response) = crate::net::bond::serve_request(
        to,
        "POST",
        "/v1/donations",
        consumer,
        token,
        Some(&json!({
            "consumer": consumer,
            "from": from,
            "item_id": item_id,
            "kind": item_kind,
            "armor": armor,
        })),
    )?;
    crate::runtime::audit::append(
        "donate",
        &json!({"to": to, "item": item_id, "consumer": consumer}),
    )?;
    Ok(response)
}
