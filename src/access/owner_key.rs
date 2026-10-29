//! `owner key mint|show <uid>`: the key a vault owner opens the vault with, on
//! this host, without touching any vault.
//!
//! A vault moved to another host is opened there by its owner's secret key in
//! that host's keyring. `owner rotate` deliberately makes no key and
//! `recipient add` registers the key it makes as a recipient of the local
//! vault, so neither can prepare a destination. `mint` makes the key with the
//! parameters `init` uses and only that; `show` answers whether it is here.

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
    let (verb, rest) = positionals
        .split_first()
        .with_context(|| format!("{COMMAND} needs a verb: mint <uid> or show <uid>"))?;
    let [uid] = rest else {
        bail!("{COMMAND} {verb} takes exactly one <uid>");
    };
    let answer = match verb.as_str() {
        "mint" => mint(uid)?,
        "show" => show(uid)?,
        other => bail!("{COMMAND} has no verb {other}; it has mint and show"),
    };
    Ok(Some(answer))
}

/// `owner rotate <new-owner-uid>`: move the vault to a new owner key.
/// Deliberately no key generation: a key minted here would be a key no
/// ciphertext was ever encrypted to. The new owner's key must already be in
/// the keyring, imported or made on purpose beforehand (`owner key mint`).
fn rotate(positionals: &[String]) -> Result<Value> {
    let [uid] = positionals else {
        return Err(
            crate::cli::args::Usage("usage: owner rotate <new-owner-uid>".to_string()).into(),
        );
    };
    let fpr = crypto::fingerprint_for(uid)?.with_context(|| {
        format!(
            "no key in the keyring for {uid}: import it (recipient add {uid} --import <pubkey-file>) \
             or make it (`skarbiec {COMMAND} mint {uid}`) first, then rotate"
        )
    })?;
    let mut vault = crate::core::vault::Vault::open(crate::core::vault_path())?;
    let report = vault.rotate_owner(uid, &fpr)?;
    crate::runtime::audit::append("rotate-owner", &report)?;
    Ok(report)
}

/// Make the owner key for `uid` in this host's keyring. A uid that already
/// names a key here is refused: a second key under one uid would leave which
/// one opens the vault to the keyring's order.
fn mint(uid: &str) -> Result<Value> {
    if let Some(existing) = crypto::fingerprint_for(uid)? {
        bail!(
            "{uid} already names key {existing} in this host's keyring; {COMMAND} mint makes a \
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

/// The key `uid` names in this host's keyring, refused when there is none.
fn show(uid: &str) -> Result<Value> {
    let fingerprint = crypto::fingerprint_for(uid)?.with_context(|| {
        format!(
            "{uid} names no key in this host's keyring; `skarbiec {COMMAND} mint {uid}` makes one"
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
    }))
}
