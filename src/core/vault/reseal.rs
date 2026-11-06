//! `skarbiec reseal [--apply | --verify]`: the one-time move of every stored
//! ciphertext from OpenPGP, which gpg wrote, to Skarbiec's own sealed format.
//!
//! Every OpenPGP ciphertext an item holds (its current value, every saved
//! version, a staged value) is opened here and sealed again to the same
//! recipients' X25519 keys. Nothing is written until every one of them has
//! been, and before the write the vault file is copied, owner-only, to
//! `<vault>.pre-reseal-<stamp>`. The document records the run (`reseal`)
//! until every ciphertext it holds has been opened again from the file just
//! written; only then is the record cleared. A run that could not prove that
//! leaves the record, and every later `reseal --apply` is refused naming the
//! copy until `reseal --verify` proves it or the copy is restored.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::{obj_mut, Vault};
use crate::core::crypto::{self, Format};

/// The document section a run in progress is recorded in.
const RECORD: &str = "reseal";

/// One ciphertext an item holds, by where it sits.
struct Slot {
    id: String,
    /// `current`, `pending`, or the index of a saved version.
    place: Place,
    ciphertext: String,
}

#[derive(Clone, Copy)]
enum Place {
    Current,
    Pending,
    History(usize),
}

impl Place {
    fn name(self) -> String {
        match self {
            Place::Current => "current value".to_string(),
            Place::Pending => "staged value".to_string(),
            Place::History(index) => format!("saved version {index}"),
        }
    }
}

fn slots(vault: &Vault) -> Result<Vec<Slot>> {
    let mut found = Vec::new();
    for (id, item) in vault.section("items", "id -> item")? {
        let text = |value: Option<&Value>, place: Place| -> Result<Option<Slot>> {
            let Some(holder) = value else {
                return Ok(None);
            };
            let ciphertext = holder
                .get("ciphertext")
                .and_then(Value::as_str)
                .with_context(|| {
                    format!("vault item {id}'s {} holds no ciphertext", place.name())
                })?;
            Ok(Some(Slot {
                id: id.clone(),
                place,
                ciphertext: ciphertext.to_string(),
            }))
        };
        found.extend(text(item.get("current"), Place::Current)?);
        found.extend(text(
            item.get("pending").filter(|p| !p.is_null()),
            Place::Pending,
        )?);
        for (index, version) in super::items::stored_history(id, item)?.iter().enumerate() {
            found.extend(text(Some(version), Place::History(index))?);
        }
    }
    Ok(found)
}

/// Open every ciphertext the vault at `path` holds with this host's keys;
/// each one that does not open, with why.
fn unopened(path: &Path) -> Result<(usize, Vec<Value>)> {
    let vault = Vault::open(path.to_path_buf())?;
    let all = slots(&vault)?;
    let mut failed = Vec::new();
    for slot in &all {
        if let Err(error) = crypto::decrypt(&slot.ciphertext) {
            failed.push(json!({
                "item": slot.id,
                "where": slot.place.name(),
                "error": format!("{error:#}"),
            }));
        }
    }
    Ok((all.len(), failed))
}

fn copy_beside(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .with_context(|| format!("the vault path {} names no file", path.display()))?
        .to_string_lossy()
        .into_owned();
    let target = path.with_file_name(format!(
        "{name}.pre-reseal-{}",
        crate::core::clock::now_stamp()
    ));
    let mut input =
        File::open(path).with_context(|| format!("open the vault file {}", path.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(super::private_file_mode()?)
        .open(&target)
        .with_context(|| format!("create the copy {} kept before resealing", target.display()))?;
    std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copy the vault to {}", target.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync the copy {}", target.display()))?;
    Ok(target)
}

pub fn run(flags: &HashMap<String, String>) -> Result<Value> {
    if let Some(flag) = flags
        .keys()
        .find(|flag| !matches!(flag.as_str(), "apply" | "verify"))
    {
        return Err(crate::cli::args::Usage(format!(
            "reseal takes --apply or --verify; it was given --{flag}"
        ))
        .into());
    }
    let apply = crate::cli::args::flag_set(flags, "apply");
    let verify = crate::cli::args::flag_set(flags, "verify");
    if apply && verify {
        return Err(crate::cli::args::Usage(
            "reseal --apply reseals and proves; --verify only proves a run already made: name one"
                .to_string(),
        )
        .into());
    }
    let path = crate::core::vault_path();
    let mut vault = Vault::open(path.clone())?;
    crate::cli::items::ensure_not_replica(&vault, "reseal")?;
    let record = vault.doc().get(RECORD).cloned();
    if verify {
        return prove(&path, record);
    }
    if let Some(record) = &record {
        let backup = record["backup"].as_str().unwrap_or("<no copy recorded>");
        bail!(
            "a reseal started at {} has not proven that every ciphertext opens again ({}); the \
             vault as it was before it is kept at {backup}. Import the keys it names (`skarbiec \
             keys import`) and run `skarbiec reseal --verify`, or put the copy back with \
             `skarbiec backup restore {backup} --yes`",
            record["started_at"]
                .as_str()
                .unwrap_or("an unrecorded time"),
            record["last_failure"].as_str().unwrap_or("not proven yet"),
        );
    }
    let all = slots(&vault)?;
    let mut legacy = Vec::new();
    for slot in all {
        if crypto::format_of(&slot.ciphertext)
            .with_context(|| format!("vault item {}'s {}", slot.id, slot.place.name()))?
            == Format::OpenPgp
        {
            legacy.push(slot);
        }
    }
    // Every key an item is sealed to must be readable here, before anything
    // is opened: a recipient left out would lose its access silently.
    let mut recipients: HashMap<String, Vec<String>> = HashMap::new();
    let mut missing: Vec<String> = Vec::new();
    for slot in &legacy {
        if recipients.contains_key(&slot.id) {
            continue;
        }
        let fprs = vault.fprs_for(&vault.item_recipient_uids(&slot.id)?);
        for fpr in &fprs {
            if crypto::export_public_key(fpr).is_err() && !missing.contains(fpr) {
                missing.push(fpr.clone());
            }
        }
        recipients.insert(slot.id.clone(), fprs);
    }
    if !missing.is_empty() {
        bail!(
            "the key file {} holds no key {}, which items are sealed to; reseal would drop them. \
             Bring them with `skarbiec keys import` (or `recipient add <uid> --import <file>` for a \
             public key), then run reseal again",
            crypto::key_file().display(),
            missing.join(", ")
        );
    }
    if !apply {
        return Ok(json!({
            "ok": true,
            "applied": false,
            "openpgp_ciphertexts": legacy.len(),
            "items": recipients.len(),
            "next": "skarbiec reseal --apply",
        }));
    }
    let mut resealed = Vec::with_capacity(legacy.len());
    for slot in &legacy {
        let plain = crypto::decrypt(&slot.ciphertext).with_context(|| {
            format!(
                "open vault item {}'s {} to reseal it; nothing was written",
                slot.id,
                slot.place.name()
            )
        })?;
        let sealed = crypto::encrypt_to(&recipients[&slot.id], &plain)
            .with_context(|| format!("reseal vault item {}'s {}", slot.id, slot.place.name()))?;
        resealed.push(sealed);
    }
    let backup = copy_beside(&path)?;
    let items = obj_mut(&mut vault.doc, "items")?;
    for (slot, sealed) in legacy.iter().zip(resealed) {
        let item = items
            .get_mut(&slot.id)
            .with_context(|| format!("vault item {} went missing while resealing", slot.id))?;
        let holder = match slot.place {
            Place::Current => item.get_mut("current"),
            Place::Pending => item.get_mut("pending"),
            Place::History(index) => item
                .get_mut("history")
                .and_then(Value::as_array_mut)
                .and_then(|history| history.get_mut(index)),
        }
        .and_then(Value::as_object_mut)
        .with_context(|| {
            format!(
                "vault item {}'s {} went missing",
                slot.id,
                slot.place.name()
            )
        })?;
        holder.insert("ciphertext".to_string(), json!(sealed));
    }
    let started = crate::core::clock::now_iso();
    vault
        .doc
        .as_object_mut()
        .context("the vault document is not an object")?
        .insert(
            RECORD.to_string(),
            json!({"started_at": started, "backup": backup.display().to_string(), "resealed": legacy.len()}),
        );
    vault.save()?;
    crate::runtime::audit::append(
        "reseal",
        &json!({"resealed": legacy.len(), "backup": backup.display().to_string()}),
    )?;
    let record = Vault::open(path.clone())?.doc().get(RECORD).cloned();
    prove(&path, record)
}

/// Open every ciphertext again from the file on disk; clear the run's
/// record when all open, keep it naming the failures when not.
fn prove(path: &Path, record: Option<Value>) -> Result<Value> {
    let Some(record) = record else {
        let (opened, failed) = unopened(path)?;
        return Ok(
            json!({"ok": failed.is_empty(), "in_progress": false, "ciphertexts": opened, "unopened": failed}),
        );
    };
    let (count, failed) = unopened(path)?;
    let mut vault = Vault::open(path.to_path_buf())?;
    let document = vault
        .doc
        .as_object_mut()
        .context("the vault document is not an object")?;
    if failed.is_empty() {
        document.remove(RECORD);
        vault.save()?;
        crate::runtime::audit::append(
            "reseal-proven",
            &json!({"ciphertexts": count, "backup": record["backup"]}),
        )?;
        return Ok(json!({
            "ok": true,
            "proven": true,
            "ciphertexts": count,
            "backup": record["backup"],
            "note": "every ciphertext opens from the resealed vault; the copy made before is kept until you remove it",
        }));
    }
    let first = failed[0]["error"].as_str().unwrap_or("").to_string();
    if let Some(section) = document.get_mut(RECORD).and_then(Value::as_object_mut) {
        section.insert(
            "last_failure".to_string(),
            json!(format!(
                "{} ciphertext(s) did not open, first: {first}",
                failed.len()
            )),
        );
    }
    vault.save()?;
    let backup = record["backup"].as_str().unwrap_or("<no copy recorded>");
    bail!(
        "{} of {count} ciphertext(s) in the resealed vault do not open with this host's keys \
         (first: {first}); the vault as it was before is kept at {backup}: import the missing keys \
         and run `skarbiec reseal --verify`, or put the copy back with `skarbiec backup restore \
         {backup} --yes`",
        failed.len()
    )
}
