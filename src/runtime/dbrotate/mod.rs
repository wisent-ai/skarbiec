// The database adapter of `skarbiec rotate <id> --with database --url
// <postgresql://host[:port]/dbname | mysql://host[:port]/dbname> --length <N>`: rotate a database account's
// password end to end. The item — a login or host account holding the
// account's username and password — gets a generated value first, as a new
// revision, so the vault never loses the value that works: the old one stays
// in its saved versions. Then the server's client, signed in with the old
// password, sets the new one for the account that signed in, and a second
// sign-in with the new password proves it. When the server refuses either
// step, it is put back to the old password where it was changed and the old
// value is written back as the item's current revision; when the server
// cannot be put back, the item keeps the value the server now holds.

mod engines;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::cli::args::OrUsage;
use crate::core::{vault::Vault, vault_path};
use engines::Engine;
pub(crate) use engines::USAGE;

const USERNAME: &str = "username";
const PASSWORD: &str = "password";

/// Rotate `id`'s database password, as `rotate <id> --with database` asks.
pub(crate) fn rotate_item(flags: &HashMap<String, String>, id: &str) -> Result<Value> {
    let url = flags.get("url").or_usage(USAGE)?;
    let engine = Engine::parse(url, id)?;
    let length = flags.get("length").or_usage(USAGE)?;
    rotate(id, url, &engine, length)
}

fn store(id: &str, password: &str) -> Result<u64> {
    crate::runtime::revise::fields(id, &[(PASSWORD, password)])
}

fn rotate(id: &str, url: &str, engine: &Engine, length: &str) -> Result<Value> {
    let (user, old) = {
        let vault = Vault::open(vault_path())?;
        crate::cli::items::ensure_owner_mutation_allowed(&vault, id, "rotate")?;
        let payload = vault.get_item(id)?;
        let fields = &payload["fields"];
        let user = fields[USERNAME]
            .as_str()
            .filter(|user| !user.is_empty())
            .with_context(|| format!("{id} holds no {USERNAME}, the account to rotate"))?;
        let old = fields[PASSWORD]
            .as_str()
            .with_context(|| format!("{id} holds no {PASSWORD} to sign in with"))?;
        (user.to_string(), old.to_string())
    };
    // Letters and digits: every server and every connection string takes them.
    let generated = crate::cli::generate::generate_value(&HashMap::from([
        ("length".to_string(), length.to_string()),
        ("lower".to_string(), "true".to_string()),
        ("upper".to_string(), "true".to_string()),
        ("digits".to_string(), "true".to_string()),
    ]))?;
    let new = generated["password"]
        .as_str()
        .context("generate answered no password")?
        .to_string();
    let verdict = crate::access::policy::check(&new)?;
    if verdict["ok"] != json!(true) {
        bail!("a {length}-character value does not clear the vault policy ({}); nothing was changed. Ask for a longer one", verdict["rules"]);
    }
    let revision = store(id, &new)?;
    let changed = engine.run(&user, &old, &engine.alter(&new));
    let proven = match &changed {
        Ok(()) => engine.run(&user, &new, engine.proof()),
        Err(error) => Err(anyhow::anyhow!("{error:#}")),
    };
    let Err(error) = proven else {
        crate::runtime::audit::append(
            "db-rotated",
            &json!({"item": id, "url": url, "revision": revision}),
        )?;
        return Ok(
            json!({"ok": true, "item": id, "account": user, "url": url, "client": engine.client(), "revision": revision}),
        );
    };
    crate::runtime::audit::append(
        "db-rotate-failed",
        &json!({"item": id, "url": url, "revision": revision}),
    )?;
    // The server first, with the password it now takes; the vault then holds
    // whatever the server holds.
    if changed.is_ok() {
        if let Err(undo) = engine.run(&user, &new, &engine.alter(&old)) {
            bail!("{error:#}; the server holds the new password and could not be put back ({undo:#}), so {id} keeps it at revision {revision}");
        }
    }
    match store(id, &old) {
        Ok(back) => bail!("{error:#}; the server holds the old password, and so does {id} again at revision {back}"),
        Err(undo) => bail!(
            "{error:#}; the server holds the old password, but it could not be written back to {id} ({undo:#}); it is the saved version before revision {revision}"
        ),
    }
}
