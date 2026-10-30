//! `owner key mint|show <uid>`, `owner key export` and `owner key import
//! <file>`: the keys a vault is opened and sealed with, on this host.
//!
//! A vault moved to another host is opened there by its owner's secret key in
//! that host's key file, and every write there seals to every recipient's
//! and the recovery key, so that host needs their public halves too. `owner
//! rotate` deliberately makes no key and `recipient add` registers the key it
//! makes as a recipient of the local vault, so neither can prepare a
//! destination. `mint` makes the owner key with the parameters `init` uses;
//! `show` answers whether it is here; `export` writes every public key the
//! vault seals to as one block, and `import` adds a block's public keys to
//! this host's key file, refusing secret ones.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::crypto;

/// The command and leaf this module answers; every other command is another module's.
const COMMAND: &str = "owner key";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if let Some(rest) = crate::cli::args::verb(command, positionals, "owner", "rotate") {
        return rotate(rest).map(Some);
    }
    let Some(positionals) = crate::cli::args::verb(command, positionals, "owner", "key") else {
        return Ok(None);
    };
    if let Some(flag) = flags.keys().next() {
        bail!("{COMMAND} takes no flags; it was given --{flag}");
    }
    let (verb, rest) = positionals.split_first().with_context(|| {
        format!("{COMMAND} needs a verb: mint <uid>, show <uid>, export, or import <file>")
    })?;
    let answer = match (verb.as_str(), rest) {
        ("mint", [uid]) => mint(uid)?,
        ("show", [uid]) => show(uid)?,
        ("export", []) => export()?,
        ("import", [file]) => import(file)?,
        ("mint" | "show", _) => bail!("{COMMAND} {verb} takes exactly one <uid>"),
        ("export", _) => bail!("{COMMAND} export takes no argument: it reads the vault"),
        ("import", _) => {
            bail!("{COMMAND} import takes exactly one <file> (/dev/stdin reads standard input)")
        }
        (other, _) => bail!("{COMMAND} has no verb {other}; it has mint, show, export and import"),
    };
    Ok(Some(answer))
}

/// `owner rotate <new-owner-uid>`: move the vault to a new owner key.
/// Deliberately no key generation: a key minted here would be a key no
/// ciphertext was ever encrypted to. The new owner's key must already be in
/// the key file, imported or made on purpose beforehand (`owner key mint`).
fn rotate(positionals: &[String]) -> Result<Value> {
    let [uid] = positionals else {
        return Err(
            crate::cli::args::Usage("usage: owner rotate <new-owner-uid>".to_string()).into(),
        );
    };
    let fpr = crypto::fingerprint_for(uid)?.with_context(|| {
        format!(
            "no key in the key file for {uid}: import it (recipient add {uid} --import <pubkey-file>) \
             or make it (`skarbiec {COMMAND} mint {uid}`) first, then rotate"
        )
    })?;
    let mut vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
    let report = vault.rotate_owner(uid, &fpr)?;
    crate::runtime::audit::append("rotate-owner", &report)?;
    Ok(report)
}

/// Make the owner key for `uid` in this vault's key file. A uid that already
/// names a key here is refused: a second key under one uid would leave which
/// one opens the vault to the key file's order.
fn mint(uid: &str) -> Result<Value> {
    if let Some(existing) = crypto::fingerprint_for(uid)? {
        bail!(
            "{uid} already names key {existing} in this vault's key file; {COMMAND} mint makes a \
             key only for a uid that names none, and `skarbiec {COMMAND} show {uid}` reads it"
        );
    }
    let fingerprint = crypto::generate_key(uid)?;
    let report = describe(uid, &fingerprint)?;
    crate::runtime::audit::append(
        "owner-key mint",
        &json!({"uid": uid, "fingerprint": fingerprint}),
    )?;
    Ok(report)
}

/// The key `uid` names in this vault's key file, refused when there is none.
fn show(uid: &str) -> Result<Value> {
    let fingerprint = crypto::fingerprint_for(uid)?.with_context(|| {
        format!(
            "{uid} names no key in this vault's key file; `skarbiec {COMMAND} mint {uid}` makes one"
        )
    })?;
    describe(uid, &fingerprint)
}

/// The uid, its fingerprint, whether this host holds the secret half, and
/// the armored public key another host encrypts to.
fn describe(uid: &str, fingerprint: &str) -> Result<Value> {
    Ok(json!({
        "uid": uid,
        "fingerprint": fingerprint,
        "secret_key_present": crypto::secret_key_present(fingerprint)?,
        "public_key": crypto::export_public_key(fingerprint)?,
        "key_file": crypto::key_file().display().to_string(),
    }))
}

/// Every key the vault seals to — each recipient's and the recovery key —
/// with the uids naming it, and their public halves in one armored block.
/// A key the key file lacks is refused naming it: a block missing one would
/// let a destination seal writes that key could not open.
fn export() -> Result<Value> {
    let vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
    let mut named: Vec<(String, Vec<String>)> = Vec::new();
    let mut add = |fingerprint: &str, uid: &str| {
        let fingerprint = fingerprint.to_ascii_uppercase();
        match named.iter_mut().find(|(held, _)| *held == fingerprint) {
            Some((_, uids)) => uids.push(uid.to_string()),
            None => named.push((fingerprint, vec![uid.to_string()])),
        }
    };
    for (uid, entry) in vault.section("recipients", "uid -> recipient")? {
        let fingerprint = entry
            .get("fingerprint")
            .and_then(Value::as_str)
            .filter(|fingerprint| !fingerprint.is_empty())
            .with_context(|| {
                format!("recipient {uid} records no fingerprint, so its key cannot be exported")
            })?;
        add(fingerprint, uid);
    }
    let recovery = vault.recovery_fpr().to_string();
    if !recovery.is_empty() {
        add(&recovery, "recovery");
    }
    let fingerprints: Vec<String> = named
        .iter()
        .map(|(fingerprint, _)| fingerprint.clone())
        .collect();
    let public_keys = crypto::export_public_keys(&fingerprints).with_context(|| {
        format!(
            "this vault's key file {} lacks a key the vault seals to; bring it with `skarbiec keys \
             import` or `skarbiec {COMMAND} import <file>` before exporting",
            crypto::key_file().display()
        )
    })?;
    Ok(json!({
        "key_file": crypto::key_file().display().to_string(),
        "keys": named
            .iter()
            .map(|(fingerprint, uids)| json!({"fingerprint": fingerprint, "uids": uids}))
            .collect::<Vec<_>>(),
        "public_keys": public_keys,
    }))
}

/// Add the public keys an armored block holds to this vault's key file; no
/// vault is needed. A secret key block is refused.
fn import(file: &str) -> Result<Value> {
    let armored = std::fs::read_to_string(file).with_context(|| {
        format!("read the public key block {file}; name a readable file, or /dev/stdin")
    })?;
    let added = crypto::import_key(&armored)?;
    let mut imported = Vec::new();
    let mut already = Vec::new();
    for (fingerprint, changed) in added {
        if changed {
            imported.push(fingerprint);
        } else {
            already.push(fingerprint);
        }
    }
    crate::runtime::audit::append("owner-key import", &json!({"imported": imported}))?;
    Ok(json!({
        "key_file": crypto::key_file().display().to_string(),
        "imported": imported,
        "already": already,
    }))
}
