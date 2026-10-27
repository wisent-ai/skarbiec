// The aws adapter of `skarbiec helper`: an AWS credential_process
// (https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html),
// so the AWS CLI and every AWS SDK read an access-key item's key from the
// vault each time they need it, and no key sits in ~/.aws/credentials.
// `helper answer aws <id>` prints the JSON the process protocol defines —
// Version, AccessKeyId, SecretAccessKey and, for a temporary key,
// SessionToken — and journals the read. `helper setup aws <id> --profile
// <name>` makes a profile in the AWS config file run it; `helper import aws
// <id> --profile <name>` moves a profile's key out of ~/.aws/credentials into
// a new item and sets it up; `helper unset aws --profile <name>` stops that;
// status names the profiles that run it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::Usage;
use crate::core::{vault::Vault, vault_path};

mod config;
mod import;

/// What doctor checks: the profiles AWS sends to this vault.
pub(crate) use config::profiles;

/// Point every AWS profile that reads `from` at `to` after a rename, as
/// setup would; each profile moved or not is named, never left silently
/// running a command for an id nothing answers.
pub(crate) fn follow_rename(from: &str, to: &str) -> Result<Value> {
    let (_, found) = profiles()?;
    let mut moved = Vec::new();
    let mut not_moved = Vec::new();
    for profile in found.iter().filter(|profile| profile.item == from) {
        match config::setup(to, &profile.name) {
            Ok(_) => moved.push(profile.name.clone()),
            Err(error) => not_moved.push(json!({"profile": profile.name, "error": format!("{error:#}")})),
        }
    }
    Ok(json!({"moved": moved, "not_moved": not_moved}))
}

pub(crate) const TOOL: &str = "aws";
pub(crate) const USAGE: &str = "usage: helper setup aws <id> --profile <name> | helper import aws <id> --profile <name> [--tags <tag,...>] | helper unset aws --profile <name> | helper answer aws <id>  (the AWS CLI's credential_process)";
const KIND: &str = "access-key";

/// setup, import and unset, the verb first.
pub(crate) fn person(flags: &HashMap<String, String>, positionals: &[String]) -> Result<Value> {
    let profile = || {
        flags
            .get("profile")
            .ok_or_else(|| Usage(format!("name the AWS profile with --profile; {USAGE}")))
    };
    match positionals {
        [action, id] if action == "setup" => {
            held(id)?;
            config::setup(id, profile()?)
        }
        [action, id] if action == "import" => import::import(id, profile()?, flags.get("tags")),
        [action] if action == "unset" => config::unset(profile()?),
        _ => Err(Usage(USAGE.to_string()).into()),
    }
}

/// The AWS CLI's side: the credential_process answer for the item its
/// profile names.
pub(crate) fn answer(_flags: &HashMap<String, String>, arguments: &[String]) -> Result<()> {
    let [id] = arguments else {
        return Err(Usage(USAGE.to_string()).into());
    };
    crate::cli::args::emit(&credential(id)?)
}

/// The profiles the AWS config file sends here, each with the item it reads
/// and whether the program its credential_process runs is still there.
pub(crate) fn status() -> Result<Value> {
    let (config, found) = profiles()?;
    let listed: Vec<Value> = found
        .iter()
        .map(|profile| json!({"profile": profile.name, "item": profile.item, "program": profile.program, "program_exists": profile.program.exists()}))
        .collect();
    Ok(json!({"config": config, "profiles": listed}))
}

/// The access-key item's fields, refusing an item of another kind.
fn held(id: &str) -> Result<Value> {
    let payload = Vault::open(vault_path())?.get_item(id)?;
    if payload["kind"] != json!(KIND) {
        bail!("{id} is a {} item; helper answer aws hands AWS the key an {KIND} item keeps", payload["kind"]);
    }
    Ok(payload["fields"].clone())
}

/// The credential_process answer for `id`.
fn credential(id: &str) -> Result<Value> {
    let fields = held(id)?;
    let text = |field: &str| fields[field].as_str().filter(|value| !value.is_empty()).map(str::to_string);
    let key = text("access_key_id").with_context(|| format!("{id} holds no access_key_id"))?;
    let secret = text("secret_access_key").with_context(|| format!("{id} holds no secret_access_key"))?;
    // The process protocol's one version.
    let version = std::iter::once(()).count();
    let mut answer = json!({"Version": version, "AccessKeyId": key, "SecretAccessKey": secret});
    if let Some(token) = text("session_token") {
        answer["SessionToken"] = json!(token);
    }
    crate::runtime::audit::append("aws-credential", &json!({"item": id, "key": key}))?;
    Ok(answer)
}
