// Moving an item to a new id, and the grants that name it.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

use super::args::{emit, flag_set};
use super::items::ensure_owner_mutation_allowed;

/// Change one item's id, keeping everything that is not the id.
///
/// There was no way to do this. The improvisation -- `get`, `set` under
/// the new id, `delete` the old -- is a copy wearing a rename's clothes: the
/// result starts at revision 1 with an empty history and a fresh `created_at`,
/// its tags are gone because a new id has no previous entry to preserve them
/// from, and it needs the plaintext in hand. Measured on a scratch vault, an
/// item at revision 3 with two historical versions came out at revision 1 with
/// none.
///
/// Owner-controlled items only, the same bar `retag` and `delete` apply. An
/// item the credential lifecycle or Weles controls is refused, because its
/// controller holds references keyed by the id and this command cannot update
/// them.
///
/// The references this does break -- capability routes, consumer grants,
/// acquisition bearers in flight -- break loudly, which is the accepted
/// tradeoff. What changes is that they are now traceable: the uid travels with
/// the item, so `route verify` reports a renamed item as renamed and names
/// where it went, instead of reporting it as missing and leaving an operator
/// unable to tell a rename from a purge. The grants it leaves naming the old
/// id are named in the answer, and `--move-grants` moves them with it.
pub(crate) fn cmd_rename(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    emit(&rename_value(flags, positionals)?)
}

/// The answer of `rename`, for the command line and `POST
/// /v1/operator/items/rename` alike. With `--move-grants` every grant that
/// named the old id is retargeted to the new one in the same call, keeping
/// its bearer; one that cannot be moved is named with its reason.
pub(crate) fn rename_value(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let [from, to, ..] = positionals else {
        return Err(super::args::Usage("usage: rename <id> <new-id> [--move-grants]".to_string()).into());
    };
    let mut vault = Vault::open(vault_path())?;
    ensure_owner_mutation_allowed(&vault, from, "rename")?;
    let item_uid = vault.rename_item(from, to)?;
    // A share that was to end on its own still ends, a recorded expiry still
    // warns and a rotation policy still rotates: each moves with the item
    // instead of staying under an id nothing answers.
    let carried_shares = crate::access::recipients::carry_share_ends(&mut vault, from, to);
    let carried_expiry = crate::runtime::expiry::follow_rename(&mut vault, from, to);
    let carried_pin = crate::runtime::pins::follow_rename(&mut vault, from, to)?;
    let carried_rotation = crate::credential::follow_rotation_rename(&mut vault, from, to);
    if carried_shares || carried_expiry || carried_pin || carried_rotation {
        vault.save()?;
    }
    // AWS profiles and kubeconfig users on this machine name the item by id
    // in the command they run; they are pointed at the new id, and one that
    // could not be — or a configuration that could not be read — is named
    // with why. The item is renamed already, so neither refuses the rename.
    let unread = |error: anyhow::Error| json!({"moved": [], "not_moved": [{"error": format!("{error:#}")}]});
    let aws_profiles = match crate::runtime::awscred::follow_rename(from, to) {
        Ok(answer) => answer,
        Err(error) => unread(error),
    };
    let kube_users = match crate::runtime::kubecred::follow_rename(from, to) {
        Ok(answer) => answer,
        Err(error) => unread(error),
    };
    // This host's alert names its webhook item by id too.
    let alert = match crate::runtime::alert::follow_rename(from, to) {
        Ok(moved) => json!({"moved": moved}),
        Err(error) => json!({"moved": false, "error": format!("{error:#}")}),
    };
    // The bindings files the CI and cluster secrets this host keeps set are
    // set from name the item by id too.
    let ci_bindings = match crate::runtime::cisecrets::follow_rename(from, to) {
        Ok(answer) => answer,
        Err(error) => unread(error),
    };
    // So do the bindings files this host knows of (bindings list).
    let bindings_files = match crate::runtime::bindings::follow_rename(from, to) {
        Ok(answer) => answer,
        Err(error) => unread(error),
    };
    // A grant names an item by id, so one written for the old id now reaches
    // nothing; the answer names those consumers, so the break is seen at the
    // rename and not when the consumer next fails.
    let stranded = grants_naming(&vault, from);
    crate::runtime::audit::append_sync(
        "item-renamed",
        &json!({"from": from, "to": to, "item_uid": item_uid}),
    )?;
    let mut moved = Vec::new();
    let mut not_moved = Vec::new();
    if flag_set(flags, "move-grants") {
        let target = HashMap::from([("from".to_string(), from.clone()), ("to".to_string(), to.clone())]);
        for consumer in &stranded {
            match crate::access::dispatch("grant", &target, &["retarget".to_string(), consumer.clone()]) {
                Ok(_) => moved.push(consumer.clone()),
                Err(error) => not_moved.push(json!({"consumer": consumer, "error": format!("{error:#}")})),
            }
        }
    }
    let machine_left = aws_profiles["not_moved"].as_array().is_some_and(|left| !left.is_empty())
        || kube_users["not_moved"].as_array().is_some_and(|left| !left.is_empty())
        || alert.get("error").is_some()
        || ci_bindings["not_moved"].as_array().is_some_and(|left| !left.is_empty())
        || bindings_files["not_moved"].as_array().is_some_and(|left| !left.is_empty());
    Ok(json!({
        "ok": not_moved.is_empty() && !machine_left,
        "from": from,
        "to": to,
        "item_uid": item_uid,
        "grants_naming_old_id": stranded,
        "grants_moved": moved,
        "grants_not_moved": not_moved,
        "rotation_policy_moved": carried_rotation,
        "aws_profiles": aws_profiles,
        "kubeconfig_users": kube_users,
        "alert": alert,
        "ci_bindings": ci_bindings,
        "bindings_files": bindings_files,
    }))
}

/// The consumers whose grant holds a capability naming `id` itself. A move
/// out of the live inventory (rename, trash) leaves each of them naming
/// nothing, so the command that does it says who.
pub(crate) fn grants_naming(vault: &Vault, id: &str) -> Vec<String> {
    vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, grant)| {
            grant
                .get("capabilities")
                .and_then(Value::as_array)
                .is_some_and(|capabilities| {
                    capabilities
                        .iter()
                        .any(|capability| capability.get("item").and_then(Value::as_str) == Some(id))
                })
        })
        .map(|(consumer, _)| consumer.clone())
        .collect()
}
