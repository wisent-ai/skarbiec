// The ssh adapter of `skarbiec rotate <id> --with ssh [--comment <text>] [--hosts <user@host,...>] [--github <owner/repo,...>] [--gitlab <group/project,...>] [--github-account] [--gitlab-account] [--github-signing]`:
// replace a key-pair item's SSH key with a fresh Ed25519 pair as a new
// revision, keeping the item's other fields, context, tags and recipients.
// The old private key stays in the item's saved versions, so a server not yet
// given the new public key can still be reached with `get <id> --at <stamp>`
// until it is; the answer prints both public keys — the line to remove from
// authorized_keys and the one to add — and never a private key. With --hosts
// the servers are changed too (`push`), with --github and --gitlab the
// repositories holding it as a deploy key, with --github-account and
// --gitlab-account the signed-in account's own SSH keys, and with
// --github-signing GitHub's list of the account's signing keys (`forges`):
// the vault takes the new key only once every host and place holds it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};

pub(crate) const USAGE: &str = "usage: rotate <id> --with ssh [--comment <text>] [--hosts <user@host,...>] [--github <owner/repo,...>] [--gitlab <group/project,...>] [--github-account] [--gitlab-account] [--github-signing]";
const PRIVATE: &str = "private_key";
const PUBLIC: &str = "public_key";
const KIND: &str = "key-pair";

/// The comment an OpenSSH public key line ends with: whatever follows its
/// type and its base64 key, `ssh-ed25519 <key> <comment>`.
fn comment_of(line: &str) -> Option<&str> {
    let (_kind, rest) = line.trim().split_once(' ')?;
    let (_key, comment) = rest.split_once(' ')?;
    Some(comment).filter(|comment| !comment.is_empty())
}

/// Replace `id`'s SSH key, as `rotate <id> --with ssh` asks.
pub(crate) fn rotate_item(flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    let mut payload = {
        let vault = Vault::open(vault_path())?;
        crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
        vault.get_item(id)?
    };
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .with_context(|| format!("{id} records no kind"))?;
    if kind != KIND {
        bail!("{id} is a {kind} item, not a {KIND}; rotate --with ssh replaces the SSH key a {KIND} item holds");
    }
    let fields = payload
        .get("fields")
        .and_then(Value::as_object)
        .with_context(|| format!("{id} has no fields object"))?;
    let retired = fields
        .get(PUBLIC)
        .and_then(Value::as_str)
        .map(str::to_string);
    let hosts: Vec<String> = match flags.get("hosts") {
        Some(listed) => listed
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    };
    if flags.contains_key("hosts") && hosts.is_empty() {
        return Err(Usage(format!("--hosts names no host; {USAGE}")).into());
    }
    if let Some(host) = hosts.iter().find(|host| host.starts_with('-')) {
        return Err(Usage(format!("--hosts {host} is not user@host; {USAGE}")).into());
    }
    use super::forges::{Forge, Place, Spot};
    let mut places: Vec<Place> = Vec::new();
    for forge in [Forge::GitHub, Forge::GitLab] {
        if crate::cli::args::flag_set(flags, forge.account_flag()) {
            places.push(Place {
                forge,
                spot: Spot::Account,
            });
        }
        let Some(listed) = flags.get(forge.flag()) else {
            continue;
        };
        let repos: Vec<&str> = listed
            .split(',')
            .map(str::trim)
            .filter(|repo| !repo.is_empty())
            .collect();
        if repos.is_empty() {
            return Err(Usage(format!("--{} names no repository; {USAGE}", forge.flag())).into());
        }
        for repo in repos {
            forge
                .checked(repo)
                .map_err(|error| Usage(format!("{error:#}; {USAGE}")))?;
            places.push(Place {
                forge,
                spot: Spot::Repo(repo.to_string()),
            });
        }
    }
    // GitHub keeps signing keys apart from sign-in keys; GitLab's account
    // keys carry both, so --gitlab-account covers signing there.
    if crate::cli::args::flag_set(flags, "github-signing") {
        places.push(Place {
            forge: Forge::GitHub,
            spot: Spot::Signing,
        });
    }
    let old_private = fields
        .get(PRIVATE)
        .and_then(Value::as_str)
        .map(str::to_string);
    // The old key's comment is kept unless one is given; a key with none
    // takes the item's id, as ssh new gives it.
    let comment = match (
        flags.get("comment"),
        retired.as_deref().and_then(comment_of),
    ) {
        (Some(given), _) => given.clone(),
        (None, Some(kept)) => kept.to_string(),
        (None, None) => id.to_string(),
    };
    let (private_key, public_key) = super::generate(&comment)?;
    // The forges' deploy keys first, then the servers: the vault takes the
    // new key only once every repository and every host holds it, and a
    // later refusal takes it back off the repositories it reached.
    let added = if places.is_empty() {
        Vec::new()
    } else {
        let old_public = retired.as_deref().with_context(|| {
            format!("{id} holds no public_key to find among the repositories' deploy keys")
        })?;
        super::forges::add_everywhere(&places, old_public, &public_key)?
    };
    let take_back = |error: anyhow::Error| -> anyhow::Error {
        match super::forges::take_back(&added).as_slice() {
            [] => error,
            left => error.context(format!(
                "the new key could not be taken back off {}",
                left.join("; ")
            )),
        }
    };
    // The workspace holding both keys is gone by return.
    let work = if hosts.is_empty() {
        None
    } else {
        let old_private = old_private
            .as_deref()
            .with_context(|| format!("{id} holds no private_key to reach the hosts with"))
            .map_err(take_back)?;
        let work = super::workspace(&vault_path()).map_err(take_back)?;
        super::push::add_everywhere(&work.0, &hosts, old_private, &private_key, &public_key)
            .map_err(take_back)?;
        Some(work)
    };
    let fields = payload
        .get_mut("fields")
        .and_then(Value::as_object_mut)
        .with_context(|| format!("{id} has no fields object"))?;
    fields.insert(PRIVATE.to_string(), json!(private_key));
    fields.insert(PUBLIC.to_string(), json!(public_key));
    let mut vault = Vault::open(vault_path())?;
    let recipients = vault.item_recipient_uids(id)?;
    let tags = {
        let entry = vault
            .doc()
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        crate::core::vault::entry_texts(id, entry, "tags")?
    };
    vault.set_item(id, KIND, &payload, &recipients, &tags)?;
    let revision = vault.item_revision(id)?;
    let repositories: Vec<String> = places.iter().map(|place| place.label()).collect();
    crate::runtime::audit::append(
        "ssh-key-rotated",
        &json!({"item": id, "revision": revision, "hosts": hosts, "repositories": repositories}),
    )?;
    let pushed = match (&work, retired.as_deref()) {
        (Some(work), Some(old_public)) => super::push::retire_everywhere(&work.0, &hosts, &private_key, old_public)?,
        (Some(_), None) => hosts.iter().map(|host| json!({"host": host, "retired_removed": false, "error": "the item held no public key to remove"})).collect(),
        (None, _) => Vec::new(),
    };
    let deploy_keys = super::forges::retire_everywhere(&added);
    drop(work);
    // git signing with the retired key would stop at the next commit; the
    // global setting follows the rotation when it named that key.
    let git_signing = match retired.as_deref() {
        Some(old_public) => crate::runtime::gitsign::follow_rotation(old_public, &public_key),
        None => json!({"moved": false}),
    };
    // The running agent would keep offering the retired key; it gets the
    // new one in its place when it held the old.
    let agent = match retired.as_deref() {
        Some(old_public) => crate::runtime::ssh_agent::follow_rotation(id, old_public),
        None => json!({"swapped": false}),
    };
    let all_retired = pushed
        .iter()
        .chain(deploy_keys.iter())
        .all(|place| place["retired_removed"] == json!(true));
    Ok(json!({
        "ok": all_retired,
        "item": id,
        "revision": revision,
        "public_key": public_key,
        "retired_public_key": retired,
        "hosts": pushed,
        "deploy_keys": deploy_keys,
        "git_signing": git_signing,
        "agent": agent,
        "next": "add public_key to every authorized_keys and forge that held retired_public_key and is not under hosts, --github or --gitlab, then remove that line; the old private key stays in the item's saved versions until then",
    }))
}
