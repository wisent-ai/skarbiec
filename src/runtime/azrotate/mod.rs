// The azure adapter of `skarbiec rotate <id> --with azure --tenant <tenant>
// (--end-date <YYYY-MM-DD> | --years <N>) [--delete-old]`: replace a Microsoft Entra application's client secret kept
// in an oauth-client item, end to end. The az CLI, signed in as whoever may
// manage the application's credentials, appends a new secret ending on the
// day named; the vault stores it as the item's next revision; then a sign-in
// as the service principal with the new secret, under an Azure configuration
// directory of this call's own, proves Microsoft accepts it, and with
// --delete-old the old secret — found by the leading characters Entra shows
// of it as its hint — is deleted. When the new secret does not sign in, it is
// deleted again and the item holds the old one again. Secrets reach az only
// through its environment, never an argument; the answer names key ids,
// never a secret.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;

use crate::cli::args::{OrUsage, Usage};
use crate::core::{vault::Vault, vault_path};

pub(crate) const USAGE: &str = "usage: rotate <id> --with azure --tenant <tenant id or domain> (--end-date <YYYY-MM-DD> | --years <N>) [--delete-old]";
const KIND: &str = "oauth-client";
const ID: &str = "client_id";
const SECRET: &str = "client_secret";
/// The shape --end-date takes: a digit where the template has a letter.
const DAY: &str = "YYYY-MM-DD";

/// Rotate `id`'s client secret, as `rotate <id> --with azure` asks.
pub(crate) fn rotate_item(flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    let tenant = flags.get("tenant").or_usage(USAGE)?;
    // A policy run again and again names how long each new secret lasts;
    // a single run may name the day it ends.
    let lasting = match (flags.get("end-date"), flags.get("years")) {
        (Some(end), None) => {
            let shaped = end.len() == DAY.len()
                && end.chars().zip(DAY.chars()).all(|(given, shape)| match shape {
                    '-' => given == '-',
                    _ => given.is_ascii_digit(),
                });
            if !shaped {
                return Err(Usage(format!("--end-date {end} is not a day as {DAY}; {USAGE}")).into());
            }
            ("--end-date", end.as_str())
        }
        (None, Some(years)) => {
            if !years.chars().all(|c| c.is_ascii_digit()) || years.trim_start_matches('0').is_empty() {
                return Err(Usage(format!("--years {years} is not a whole number of years above zero; {USAGE}")).into());
            }
            ("--years", years.as_str())
        }
        (Some(_), Some(_)) => return Err(Usage(format!("--end-date and --years both say when the new secret ends; give one; {USAGE}")).into()),
        (None, None) => return Err(Usage(format!("say when the new secret ends with --end-date or --years; {USAGE}")).into()),
    };
    rotate(id, tenant, lasting, crate::cli::args::flag_set(flags, "delete-old"))
}

/// Run `az <args>` as the account az is signed in as, answering its JSON.
fn az(args: &[&str]) -> Result<Value> {
    let output = stado_wait::output(Command::new("az").args(args).args(["--output", "json"])).with_context(|| format!("run az {}", args.join(" ")))?;
    if !output.status.success() {
        bail!("az {} ({}): {}", args.join(" "), output.status, String::from_utf8_lossy(&output.stderr).trim());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    match text.trim().is_empty() {
        true => Ok(Value::Null),
        false => serde_json::from_str(&text).with_context(|| format!("az {} answered something that is not JSON", args.join(" "))),
    }
}

/// Sign in as the service principal with `secret` under a configuration
/// directory of its own, proving Entra accepts the secret; the directory is
/// removed before this answers.
fn proves(client: &str, secret: &str, tenant: &str) -> Result<()> {
    let work = crate::runtime::keygen::workspace(&vault_path())?;
    let output = stado_wait::output(
        Command::new("az")
            .args(["login", "--service-principal", "--username", client, "--tenant", tenant, "--allow-no-subscriptions", "--output", "none"])
            .args(["--password", "env:AZURE_CLIENT_SECRET"])
            .env("AZURE_CONFIG_DIR", work.0.join("azure"))
            .env("AZURE_CLIENT_SECRET", secret),
    );
    drop(work);
    let output = output.context("run az login as the service principal")?;
    if !output.status.success() {
        bail!("az login as {client} ({}): {}", output.status, String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

fn held(id: &str) -> Result<(String, String)> {
    let vault = Vault::open(vault_path())?;
    crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
    let payload = vault.get_item(id)?;
    if payload["kind"] != json!(KIND) {
        bail!("{id} is a {} item; rotate --with azure replaces an {KIND} item's {SECRET}", payload["kind"]);
    }
    let text = |field: &str| payload["fields"][field].as_str().filter(|value| !value.is_empty()).map(str::to_string).with_context(|| format!("{id} holds no {field}"));
    Ok((text(ID)?, text(SECRET)?))
}

/// The key ids of the listed credentials whose hint `secret` begins with.
fn keys_of(listed: &Value, secret: &str) -> Vec<String> {
    listed
        .as_array()
        .into_iter()
        .flatten()
        .filter(|key| key["hint"].as_str().is_some_and(|hint| !hint.is_empty() && secret.starts_with(hint)))
        .filter_map(|key| key["keyId"].as_str().map(str::to_string))
        .collect()
}

fn rotate(id: &str, tenant: &str, (lasting, until): (&str, &str), delete_old: bool) -> Result<Value> {
    let (client, old) = held(id)?;
    let before = az(&["ad", "app", "credential", "list", "--id", &client])?;
    let old_keys = keys_of(&before, &old);
    let made = az(&["ad", "app", "credential", "reset", "--id", &client, "--append", "--display-name", "skarbiec", lasting, until])?;
    let new = made["password"].as_str().context("az ad app credential reset answered no password")?.to_string();
    let after = az(&["ad", "app", "credential", "list", "--id", &client])?;
    let known = keys_of(&before, &new);
    let new_key = keys_of(&after, &new)
        .into_iter()
        .find(|key| !known.contains(key))
        .context("the new secret does not appear among the application's credentials")?;
    // The end Entra recorded for the new secret, as its list answers it.
    let ends = after
        .as_array()
        .into_iter()
        .flatten()
        .find(|key| key["keyId"].as_str() == Some(new_key.as_str()))
        .map(|key| key["endDateTime"].clone())
        .context("the new secret's key is missing from the application's credentials")?;
    let take_back = || az(&["ad", "app", "credential", "delete", "--id", &client, "--key-id", &new_key]);
    let revision = match crate::runtime::revise::fields(id, &[(SECRET, &new)]) {
        Ok(revision) => revision,
        Err(error) => {
            return match take_back() {
                Ok(_) => Err(error.context(format!("{id} could not store the new secret, so Entra's {new_key} was deleted again"))),
                Err(undo) => Err(error.context(format!(
                    "{id} could not store the new secret and Entra's {new_key} could not be deleted again ({undo:#}); delete it under the application's Certificates & secrets"
                ))),
            };
        }
    };
    if let Err(error) = proves(&client, &new, tenant) {
        crate::runtime::audit::append("azure-rotate-failed", &json!({"item": id, "client": client, "key": new_key, "revision": revision}))?;
        let undone = take_back();
        let restored = crate::runtime::revise::fields(id, &[(SECRET, &old)]);
        match (undone, restored) {
            (Ok(_), Ok(back)) => bail!(
                "{error:#}; Entra may not accept the new secret yet, so it was deleted again and {id} holds the old one again at revision {back}; run rotate {id} --with azure again"
            ),
            (Err(undo), Ok(back)) => bail!(
                "{error:#}; {id} holds the old secret again at revision {back}, but Entra's new {new_key} could not be deleted ({undo:#}); delete it in the portal"
            ),
            (_, Err(undo)) => bail!(
                "{error:#}; {id} keeps the new secret {new_key} at revision {revision}, as the old one could not be written back ({undo:#}); it is the saved version before it"
            ),
        }
    }
    let mut retired = Vec::new();
    if delete_old {
        for key in &old_keys {
            az(&["ad", "app", "credential", "delete", "--id", &client, "--key-id", key])
                .with_context(|| format!("{id} holds the new secret {new_key}, but the old {key} could not be deleted"))?;
            retired.push(key.clone());
        }
    }
    crate::runtime::audit::append(
        "azure-secret-rotated",
        &json!({"item": id, "client": client, "key": new_key, "retired": retired, "revision": revision}),
    )?;
    Ok(json!({
        "ok": true,
        "item": id,
        "client": client,
        "key": new_key,
        "ends": ends,
        "old_keys": old_keys,
        "deleted": retired,
        "revision": revision,
        "next": match delete_old {
            true => "the old secret no longer signs in".to_string(),
            false => "the old secret still signs in until it ends or rotate --with azure --delete-old runs; every program signed in with it must read the new one from the vault".to_string(),
        },
    }))
}
