// One-time-code helper. For a canonical login item that stores a base32 seed,
// emit the CURRENT time-based code (via the standard oath toolkit) — like a
// password manager's built-in authenticator. The seed value itself is never
// emitted; only the short-lived code.
//
// This module also answers the vault's half of "is the stored authenticator
// seed still the one the account has enrolled". The vault cannot answer the
// whole question: whether a seed still MATCHES an enrolment is only observable
// where codes are submitted, which is the Weles reauth run history that
// `stado host weles-seed-freshness` reads. What the vault alone can prove is
// which of three states a login row is in, and those three have three
// different repairs, so they are never collapsed here.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{crypto, schema, vault::Vault, vault_path};

/// The exact operator path that stores a seed. Named in the diagnostic's own
/// output because a verdict an operator cannot act on is a verdict nobody
/// acts on. The seed arrives on standard input — never in an argument, where
/// it would sit in every process table on the host.
pub const SEED_REPAIR_COMMAND: &str = "printf '%s' '<seed from the authenticator app>' \
     | ACCOUNT=<login-item> skarbiec/scripts/store-login-totp-seed.sh";

/// What the vault can prove about one login row's authenticator seed.
///
/// `Present` is deliberately NOT "good": a seed that is present and stale
/// looks exactly like a seed that is present and correct from inside the
/// vault. Splitting present from good needs submitted-code evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedState {
    /// A non-empty seed. Whether it still matches the enrolment is unknown
    /// here.
    Present,
    /// The row's kind declares `totp_secret`, and the row carries no usable
    /// value for it — absent, empty, blank, or not a string. This is the
    /// condition earlier probing saw as `has_seed: false` on accounts that
    /// declare the field, and its repair is the same as a stale seed's:
    /// enrol, then store.
    DeclaredEmpty,
    /// The row's kind has no `totp_secret` field at all, so no sign-in of it
    /// was ever going to answer an authenticator prompt. Storing a seed here
    /// is refused by the schema; the row's kind is the thing that is wrong.
    FieldAbsent,
}

impl SeedState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::DeclaredEmpty => "declared_empty",
            Self::FieldAbsent => "field_absent",
        }
    }

    /// The repair for the states the vault can already settle. `Present` has
    /// none from here: the run history decides whether it needs one.
    pub fn repair(self) -> Option<&'static str> {
        match self {
            Self::Present => None,
            Self::DeclaredEmpty => Some(SEED_REPAIR_COMMAND),
            Self::FieldAbsent => Some(
                "this row's kind declares no totp_secret field; \
                 store the account as a `login` item before storing a seed",
            ),
        }
    }
}

fn load() -> Result<Vault> {
    Vault::open(vault_path())
}

/// The seed, if the row carries a usable one.
///
/// A field holding an empty or blank string is NOT a seed. It used to answer
/// `has_seed: true` here and then hand `oathtool` nothing, so an account with
/// a hollow field reported the same shape as a working one — which is part of
/// why a seed nobody could use went six days without being noticed.
fn seed_of(payload: &Value) -> Option<String> {
    schema::field(payload, "totp_secret")
        .ok()
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|seed| !seed.is_empty())
        .map(str::to_string)
}

/// Classify one canonical item payload. Reads the seed only to ask whether it
/// is there; the value never leaves this function.
pub fn seed_state(payload: &Value) -> SeedState {
    if seed_of(payload).is_some() {
        return SeedState::Present;
    }
    let declares = payload
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| schema::kind_declares_field(kind, "totp_secret"));
    if declares {
        SeedState::DeclaredEmpty
    } else {
        SeedState::FieldAbsent
    }
}

pub fn dispatch(
    command: &str,
    _flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "totp" => {
            let id = positionals.first().context("usage: totp <item-id>")?;
            let vault = load()?;
            let row = vault.get_item(id)?;
            match seed_of(&row) {
                Some(seed) => {
                    let code = crypto::totp_code(&seed);
                    let note = if code.is_none() {
                        json!("install oath-toolkit (oathtool) to compute codes")
                    } else {
                        Value::Null
                    };
                    Ok(Some(
                        json!({"item": id, "has_seed": true, "code": code, "note": note}),
                    ))
                }
                None => Ok(Some(json!({"item": id, "has_seed": false}))),
            }
        }
        // The seed-state read a diagnostic can call. Deliberately separate
        // from `totp`: `totp` computes and returns a live one-time code, and a
        // fleet-wide sweep that only wants to know whether a seed exists must
        // not mint codes into a control plane's output to find out.
        "totp-seed-state" => {
            let vault = load()?;
            // One item, or every login row in one vault open. The sweep form
            // exists because the caller is a fleet diagnostic: asking per row
            // over a host channel would open the vault once per account.
            let ids: Vec<String> = match positionals.first() {
                Some(id) => vec![id.clone()],
                None => vault
                    .list(false)
                    .iter()
                    .filter(|row| row.get("kind").and_then(Value::as_str) == Some("login"))
                    .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
                    .collect(),
            };
            let rows: Vec<Value> = ids
                .iter()
                .map(|id| match vault.get_item(id) {
                    Ok(row) => {
                        let state = seed_state(&row);
                        json!({
                            "item": id,
                            "kind": row.get("kind").cloned().unwrap_or(Value::Null),
                            "seed_state": state.as_str(),
                            // The repair names the account it is for; a
                            // command an operator has to edit before running
                            // is a command they run wrong.
                            "repair": state.repair().map(|repair| repair.replace("<login-item>", id)),
                        })
                    }
                    // A row this vault cannot open is reported as itself, not
                    // silently dropped and not guessed at: "no seed" and "the
                    // envelope is unreadable" have nothing in common.
                    Err(error) => json!({
                        "item": id,
                        "kind": Value::Null,
                        "seed_state": "unreadable",
                        "error": error.to_string(),
                    }),
                })
                .collect();
            if !positionals.is_empty() {
                return Ok(Some(rows.into_iter().next().unwrap_or(Value::Null)));
            }
            Ok(Some(json!({"rows": rows})))
        }
        _ => Ok(None),
    }
}
