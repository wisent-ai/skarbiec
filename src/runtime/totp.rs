// One-time-code helper. For a canonical login item that stores a base32 seed,
// emit the CURRENT time-based code in process, like a built-in authenticator.
// Only the short-lived code is emitted; the seed remains inside Skarbiec.
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

use crate::core::{schema, totp, vault::Vault, vault_path};

/// The exact operator path that stores a seed. Named in the diagnostic's own
/// output because a verdict an operator cannot act on is a verdict nobody
/// acts on. The seed arrives on standard input — never in an argument, where
/// it would sit in every process table on the host.
pub const SEED_REPAIR_COMMAND: &str =
    "send the complete updated login JSON with totp_secret on stdin to \
     skarbiec set-json <login-item> --type login; preserve the item's other fields";

/// What the vault can prove about one login row's authenticator seed.
///
/// `Present` is deliberately NOT "current": a valid seed that is stale looks
/// exactly like a valid seed that still matches the enrolment from inside the
/// vault. Splitting those states needs submitted-code evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedState {
    /// A Base32 value accepted by the real TOTP consumer, which produced one
    /// six-digit code.
    Present,
    /// A non-empty uppercase underscore-delimited placeholder, not a secret.
    Placeholder,
    /// A non-empty value that is not usable as a Base32 TOTP seed.
    Invalid,
    /// The row's kind declares `totp_secret`, and the row carries no usable
    /// value for it — absent, empty, blank, or not a string.
    DeclaredEmpty,
    /// The row's kind has no `totp_secret` field at all. Storing a seed here is
    /// refused by the schema; the row's kind is the thing that is wrong.
    FieldAbsent,
}

impl SeedState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Placeholder => "placeholder",
            Self::Invalid => "invalid",
            Self::DeclaredEmpty => "declared_empty",
            Self::FieldAbsent => "field_absent",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Present => {
                "totp_secret contains a usable Base32 seed that produced a six-digit TOTP code; whether it still matches the account enrolment is unknown"
            }
            Self::Placeholder => {
                "totp_secret contains an uppercase underscore-delimited placeholder, not a TOTP seed; no usable second-factor secret is stored"
            }
            Self::Invalid => {
                "totp_secret is non-empty but is not a usable Base32 TOTP seed and did not produce a six-digit code; no usable second-factor secret is stored"
            }
            Self::DeclaredEmpty => {
                "this item kind declares totp_secret, but the field is absent, empty, blank, or not text; no second-factor secret is stored"
            }
            Self::FieldAbsent => {
                "this item kind does not declare a totp_secret field; the item cannot store a TOTP second factor in its current shape"
            }
        }
    }

    /// Every settled failure carries the first correct operator action.
    pub fn repair(self) -> Option<&'static str> {
        match self {
            Self::Present => None,
            Self::Placeholder => Some(
                "replace the placeholder account values with a real account first; then enrol TOTP and send the complete updated login JSON with totp_secret on stdin to skarbiec set-json <login-item> --type login",
            ),
            Self::Invalid => Some(
                "replace the invalid totp_secret with the real Base32 seed from the account's authenticator enrolment; send the complete updated login JSON on stdin to skarbiec set-json <login-item> --type login",
            ),
            Self::DeclaredEmpty => Some(SEED_REPAIR_COMMAND),
            Self::FieldAbsent => Some(
                "this row's kind declares no totp_secret field; \
                 store the account as a `login` item before storing a seed",
            ),
        }
    }
}

mod seed;

pub(crate) use seed::base32_seed_shape;
use seed::{inspect_seed, load, seed_of};

/// Where one item's second factor actually lives, and the payload to judge.
///
/// A platform login carries its own `totp_secret` only while the seed has
/// nowhere better to be. When it names an identity in `context.identity`, the
/// factor belongs to that identity: one Google account holds the authenticator
/// and a dozen platform rows sign in as it. Resolving here rather than in each
/// caller keeps `totp` and `totp-seed-state` answering about the same seed.
struct Resolved {
    payload: Value,
    identity: Option<String>,
}

fn resolve(vault: &Vault, payload: Value) -> Resolved {
    if seed_of(&payload).is_some() {
        return Resolved {
            payload,
            identity: None,
        };
    }
    let Some(reference) = payload
        .get("context")
        .and_then(|context| context.get(schema::IDENTITY_REFERENCE))
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return Resolved {
            payload,
            identity: None,
        };
    };
    match vault.get_item(&reference) {
        Ok(identity_payload) => Resolved {
            payload: identity_payload,
            identity: Some(reference),
        },
        // The write path refuses a reference to an item that is not there, so
        // an unreadable identity is a key or envelope fault, not a dangling
        // name. The login's own payload is judged and the identity is still
        // named, so the report says which row could not be opened.
        Err(_) => Resolved {
            payload,
            identity: Some(reference),
        },
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
            let resolved = resolve(&vault, vault.get_item(id)?);
            let inspected = inspect_seed(&resolved.payload);
            let state = inspected.state;
            let repair_for = resolved.identity.clone().unwrap_or_else(|| id.to_string());
            Ok(Some(json!({
                "item": id,
                "identity": resolved.identity,
                "has_seed": state == SeedState::Present,
                "seed_state": state.as_str(),
                "description": state.description(),
                "code": inspected.code,
                "repair": state.repair().map(|repair| repair.replace("<login-item>", &repair_for)),
            })))
        }
        // The seed-state diagnostic validates the stored value through the same
        // real TOTP computation as `totp`, but never returns the short-lived
        // code or the seed itself.
        "totp-seed-state" => {
            let vault = load()?;
            // One item, or every row that can carry a factor in one vault
            // open: logins and the identities they sign in as. The sweep form
            // exists because the caller is a fleet diagnostic; asking per row
            // over a host channel would open the vault once per account.
            let ids: Vec<String> = match positionals.first() {
                Some(id) => vec![id.clone()],
                None => vault
                    .list(false)
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.get("kind").and_then(Value::as_str),
                            Some("login") | Some("identity")
                        )
                    })
                    .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_string))
                    .collect(),
            };
            let rows: Vec<Value> = ids
                .iter()
                .map(|id| match vault.get_item(id) {
                    Ok(row) => {
                        let kind = row.get("kind").cloned().unwrap_or(Value::Null);
                        let resolved = resolve(&vault, row);
                        let state = seed_state(&resolved.payload);
                        let repair_for =
                            resolved.identity.clone().unwrap_or_else(|| id.to_string());
                        json!({
                            "item": id,
                            "kind": kind,
                            // Which row the factor was judged from: this one,
                            // or the identity this one signs in as. Without it
                            // a sweep reports the same seed once per platform
                            // row and an operator counts one account many
                            // times.
                            "identity": resolved.identity,
                            "seed_state": state.as_str(),
                            "description": state.description(),
                            // The repair names the row that would carry the
                            // seed; a command an operator has to edit before
                            // running is a command they run wrong.
                            "repair": state.repair().map(|repair| repair.replace("<login-item>", &repair_for)),
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
