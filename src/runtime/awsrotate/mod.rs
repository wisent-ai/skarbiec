// The aws adapter of `skarbiec rotate <id> --with aws [--delete-old]`: replace an AWS IAM user's
// access key kept in an access-key item, end to end. The aws CLI, signed in
// with the item's current key, names the user and makes a new key for it;
// the vault stores the new key as the item's next revision, so the old one
// stays in its saved versions; then the aws CLI, signed in with the new key,
// deactivates the old one — which proves AWS accepts the new key — and with
// --delete-old deletes it. When the new key is refused, it is deleted again
// with the old key and the item holds the old key again. Keys reach the aws
// CLI only through its environment; the answer names key ids, never a secret.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::core::{vault::Vault, vault_path};

pub(crate) const USAGE: &str = "usage: rotate <id> --with aws [--delete-old]";
const KEY_ID: &str = "access_key_id";
const SECRET: &str = "secret_access_key";
const SESSION: &str = "session_token";

/// Rotate `id`'s access key, as `rotate <id> --with aws` asks.
pub(crate) fn rotate_item(flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    rotate(id, crate::cli::args::flag_set(flags, "delete-old"))
}

/// An access key as the aws CLI takes it.
struct Key {
    id: String,
    secret: String,
}

/// Run `aws iam <args>` signed in with `key`, and answer its JSON.
fn iam(key: &Key, args: &[&str]) -> Result<Value> {
    let mut command = Command::new("aws");
    command
        .arg("iam")
        .args(args)
        .args(["--output", "json"])
        .env("AWS_ACCESS_KEY_ID", &key.id)
        .env("AWS_SECRET_ACCESS_KEY", &key.secret)
        // The item's key, not a profile or a session someone left set.
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_PROFILE");
    let output = stado_wait::output(&mut command).with_context(|| format!("run aws iam {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "aws iam {} signed in as {} ({}): {}",
            args.first().context("aws iam was given no operation")?,
            key.id,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    match text.trim().is_empty() {
        true => Ok(Value::Null),
        false => serde_json::from_str(&text).with_context(|| format!("read aws iam {}'s answer", args.join(" "))),
    }
}

fn held(id: &str) -> Result<Key> {
    let vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    let payload = vault.get_item(id)?;
    if payload["kind"] != json!("access-key") {
        bail!("{id} is a {} item; rotate --with aws replaces an access-key item's {KEY_ID} and {SECRET}", payload["kind"]);
    }
    let fields = &payload["fields"];
    if fields.get(SESSION).is_some_and(|token| token.as_str().is_some_and(|token| !token.is_empty())) {
        bail!("{id} holds a {SESSION}: it is a temporary key AWS hands out, which runs out by itself and cannot be rotated; rotate the user's long-lived key it came from");
    }
    let text = |field: &str| fields[field].as_str().map(str::to_string).with_context(|| format!("{id} holds no {field}"));
    Ok(Key { id: text(KEY_ID)?, secret: text(SECRET)? })
}

fn store(id: &str, key: &Key) -> Result<u64> {
    crate::runtime::revise::fields(id, &[(KEY_ID, &key.id), (SECRET, &key.secret)])
}

fn rotate(id: &str, delete_old: bool) -> Result<Value> {
    let old = held(id)?;
    let user = iam(&old, &["get-user"])?;
    let user = user["User"]["UserName"]
        .as_str()
        .with_context(|| format!("aws iam get-user named no user for {}; the root account's keys are not rotated here", old.id))?
        .to_string();
    let made = iam(&old, &["create-access-key", "--user-name", &user])?;
    let text = |field: &str| made["AccessKey"][field].as_str().map(str::to_string).with_context(|| format!("aws iam create-access-key answered no {field}"));
    let new = Key { id: text("AccessKeyId")?, secret: text("SecretAccessKey")? };
    let revision = match store(id, &new) {
        Ok(revision) => revision,
        Err(error) => {
            // The vault could not take it: the new key must not live on in AWS
            // unknown to anyone.
            return match iam(&old, &["delete-access-key", "--user-name", &user, "--access-key-id", &new.id]) {
                Ok(_) => Err(error.context(format!("{id} could not store the new key, so AWS's {} was deleted again", new.id))),
                Err(undo) => Err(error.context(format!(
                    "{id} could not store the new key and AWS's {} could not be deleted again ({undo:#}); delete it in the IAM console",
                    new.id
                ))),
            };
        }
    };
    if let Err(error) = iam(&new, &["update-access-key", "--user-name", &user, "--access-key-id", &old.id, "--status", "Inactive"]) {
        crate::runtime::audit::append("aws-rotate-failed", &json!({"item": id, "user": user, "key": new.id, "revision": revision}))?;
        let undone = iam(&old, &["delete-access-key", "--user-name", &user, "--access-key-id", &new.id]);
        let restored = store(id, &old);
        match (undone, restored) {
            (Ok(_), Ok(back)) => bail!(
                "{error:#}; AWS may not know the new key yet, so it was deleted again and {id} holds {} again at revision {back}; run rotate {id} --with aws again",
                old.id
            ),
            (Err(undo), Ok(back)) => bail!(
                "{error:#}; {id} holds {} again at revision {back}, but AWS's new key {} could not be deleted ({undo:#}); delete it in the IAM console",
                old.id,
                new.id
            ),
            (_, Err(undo)) => bail!(
                "{error:#}; {id} keeps the new key {} at revision {revision}, as the old key could not be written back ({undo:#}); the old one is the saved version before it",
                new.id
            ),
        }
    }
    let retired = match delete_old {
        true => {
            iam(&new, &["delete-access-key", "--user-name", &user, "--access-key-id", &old.id])
                .with_context(|| format!("{id} holds the new key {} and the old one {} is inactive, but it could not be deleted", new.id, old.id))?;
            "deleted"
        }
        false => "inactive",
    };
    crate::runtime::audit::append(
        "aws-key-rotated",
        &json!({"item": id, "user": user, "key": new.id, "retired": old.id, "retired_as": retired, "revision": revision}),
    )?;
    Ok(json!({"ok": true, "item": id, "user": user, "key": new.id, "retired": old.id, "retired_as": retired, "revision": revision}))
}
