// The gcp adapter of `skarbiec rotate <id> --with gcp [--delete-old]`: replace a Google Cloud service
// account key kept in a service-account item, end to end. gcloud, signed in
// with the item's current key, makes a new key for the service account the
// key belongs to; the vault stores the new key file as the item's next
// revision, so the old one stays in its saved versions; then gcloud, signed in
// with the new key, disables the old one — which proves Google accepts the new
// key — and with --delete-old deletes it. When the new key is refused, it is
// deleted again with the old key and the item holds the old key again.
//
// Keys reach gcloud only as owner-only files in a workspace beside the vault,
// removed before the answer, and gcloud runs with a configuration directory
// of its own inside it, so the user's gcloud accounts and settings are
// neither read nor changed. The answer names key ids, never a key.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::core::{vault::Vault, vault_path};

pub(crate) const USAGE: &str = "usage: rotate <id> --with gcp [--delete-old]";
const KIND: &str = "service-account";
const FIELD: &str = "credential_json";
const KEY_TYPE: &str = "service_account";

/// Rotate `id`'s service account key, as `rotate <id> --with gcp` asks.
pub(crate) fn rotate_item(flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    rotate(id, crate::cli::args::flag_set(flags, "delete-old"))
}

/// A service account key file as Google issues one: the file itself, its key
/// id, the account it belongs to and that account's project.
struct Key {
    file: String,
    id: String,
    account: String,
    project: String,
}

impl Key {
    fn read(text: &str, whose: &str) -> Result<Key> {
        let parsed: Value = serde_json::from_str(text).with_context(|| format!("{whose} is not a JSON key file"))?;
        if parsed["type"] != json!(KEY_TYPE) {
            bail!("{whose} is a {} credential, not a {KEY_TYPE} key file; rotate --with gcp replaces a service account's key", parsed["type"]);
        }
        let field = |name: &str| parsed[name].as_str().map(str::to_string).with_context(|| format!("{whose} names no {name}"));
        Ok(Key { file: text.to_string(), id: field("private_key_id")?, account: field("client_email")?, project: field("project_id")? })
    }
}

/// Run `gcloud iam service-accounts keys <args>` signed in with `key`, in
/// `work`; answers what gcloud printed.
fn keys(work: &Path, key: &Key, args: &[&str]) -> Result<String> {
    let signed_in = work.join(format!("{}.json", key.id));
    crate::core::vault::atomic_write(&signed_in, key.file.as_bytes())?;
    let mut command = Command::new("gcloud");
    command
        .args(["iam", "service-accounts", "keys"])
        .args(args)
        .arg(format!("--iam-account={}", key.account))
        .arg(format!("--project={}", key.project))
        .args(["--quiet", "--format=json"])
        // The item's key and a configuration of this call's own, never the
        // account gcloud is signed in as or the user's settings.
        .env("CLOUDSDK_CONFIG", work.join("gcloud"))
        .env("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", &signed_in)
        .env_remove("GOOGLE_APPLICATION_CREDENTIALS");
    let output = stado_wait::output(&mut command).with_context(|| format!("run gcloud iam service-accounts keys {}", args.join(" ")));
    let removed = std::fs::remove_file(&signed_in).with_context(|| format!("remove the key file {}", signed_in.display()));
    let output = output?;
    removed?;
    if !output.status.success() {
        bail!(
            "gcloud iam service-accounts keys {} signed in with key {} ({}): {}",
            args.first().context("gcloud was given no operation")?,
            key.id,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn held(id: &str) -> Result<Key> {
    let vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    let payload = vault.get_item(id)?;
    if payload["kind"] != json!(KIND) {
        bail!("{id} is a {} item; rotate --with gcp replaces a {KIND} item's {FIELD}", payload["kind"]);
    }
    let text = payload["fields"][FIELD].as_str().with_context(|| format!("{id} holds no {FIELD}"))?;
    Key::read(text, &format!("{id}'s {FIELD}"))
}

fn store(id: &str, key: &Key) -> Result<u64> {
    crate::runtime::revise::fields(id, &[(FIELD, &key.file)])
}

fn rotate(id: &str, delete_old: bool) -> Result<Value> {
    let old = held(id)?;
    let work = crate::runtime::keygen::workspace(&vault_path())?;
    let made_file = work.0.join("new.json");
    let made_path = made_file.to_string_lossy().into_owned();
    keys(&work.0, &old, &["create", made_path.as_str()])?;
    let made = std::fs::read_to_string(&made_file).with_context(|| format!("read the key gcloud wrote to {}", made_file.display()))?;
    std::fs::remove_file(&made_file).with_context(|| format!("remove {}", made_file.display()))?;
    let new = Key::read(&made, "the key gcloud made")?;
    let revision = match store(id, &new) {
        Ok(revision) => revision,
        Err(error) => {
            // The vault could not take it: the new key must not live on in
            // Google unknown to anyone.
            return match keys(&work.0, &old, &["delete", new.id.as_str()]) {
                Ok(_) => Err(error.context(format!("{id} could not store the new key, so Google's {} was deleted again", new.id))),
                Err(undo) => Err(error.context(format!(
                    "{id} could not store the new key and Google's {} could not be deleted again ({undo:#}); delete it under the service account's Keys in the Cloud console",
                    new.id
                ))),
            };
        }
    };
    if let Err(error) = keys(&work.0, &new, &["disable", old.id.as_str()]) {
        crate::runtime::audit::append("gcp-rotate-failed", &json!({"item": id, "account": new.account, "key": new.id, "revision": revision}))?;
        let undone = keys(&work.0, &old, &["delete", new.id.as_str()]);
        let restored = store(id, &old);
        match (undone, restored) {
            (Ok(_), Ok(back)) => bail!(
                "{error:#}; Google may not accept the new key yet, so it was deleted again and {id} holds {} again at revision {back}; run rotate {id} --with gcp again",
                old.id
            ),
            (Err(undo), Ok(back)) => bail!(
                "{error:#}; {id} holds {} again at revision {back}, but Google's new key {} could not be deleted ({undo:#}); delete it in the Cloud console",
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
            keys(&work.0, &new, &["delete", old.id.as_str()])
                .with_context(|| format!("{id} holds the new key {} and the old one {} is disabled, but it could not be deleted", new.id, old.id))?;
            "deleted"
        }
        false => "disabled",
    };
    drop(work);
    crate::runtime::audit::append(
        "gcp-key-rotated",
        &json!({"item": id, "account": new.account, "key": new.id, "retired": old.id, "retired_as": retired, "revision": revision}),
    )?;
    Ok(json!({
        "ok": true,
        "item": id,
        "account": new.account,
        "project": new.project,
        "key": new.id,
        "retired": old.id,
        "retired_as": retired,
        "revision": revision,
    }))
}
