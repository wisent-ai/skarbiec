// The one question declared route resolution exists to answer: does this
// coordinate hand out a usable credential, and if not, in what words.
//
// Every surface asks it here -- `route resolve`, `route verify`, `doctor` and
// `grant capability` -- rather than carrying a second opinion about what a
// usable credential is.

use std::collections::HashMap;

use crate::core::{schema, vault::Vault};
use anyhow::Result;
use serde_json::Value;

/// What the vault answers for one coordinate.
///
/// `item_present` answers "can this host read this item at all" -- present in
/// the document, not in the trash, and it opened -- and `field_present`
/// answers only the field question, which it can never answer for an item that
/// did not open.
pub(crate) struct Coordinate {
    pub(crate) item_present: bool,
    pub(crate) field_present: bool,
    pub(crate) problem: Option<String>,
}

/// Whether a field holds nothing a consumer could authenticate with.
///
/// Emptiness is asked of the text redemption would hand out. A string is
/// served verbatim and a structured field as canonical JSON, so blank text and
/// a container whose every leaf is blank both carry no credential. A bool or a
/// number is never blank: it is short, not absent.
fn blank(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.trim().is_empty(),
        Value::Array(items) => items.iter().all(blank),
        Value::Object(fields) => fields.values().all(blank),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

/// Resolve one vault coordinate the way redemption would, and say what stopped
/// it.
///
/// Reporting an unopenable item as present used to leave both readers with one
/// sentence for two remedies: a desktop console rendering the live table saw
/// ten rows saying `item_present: true, field_present: false` on a host whose
/// `gpg` could not be spawned, which reads as ten items each missing the field
/// named beside it. It is now `item_present: false` for all ten, the cause is
/// named once per item, and a false `field_present` under a true
/// `item_present` means exactly one thing: the item opened and does not carry
/// a usable value at that field.
///
/// A field that is present and empty is a broken credential, not a working
/// one. It used to pass here -- only `null` was refused -- so a provider whose
/// secret had been emptied verified clean right up to the redemption that
/// needed it.
///
/// Items are opened at most once per `opened` map: several resources resolve
/// onto one login item, and each open is a gpg process.
pub(crate) fn coordinate(
    vault: &Vault,
    opened: &mut HashMap<String, Result<Value, String>>,
    item: &str,
    field: &str,
    item_uid: Option<&str>,
) -> Coordinate {
    let stored = vault.doc().get("items").and_then(|items| items.get(item));
    let mut problem = match stored {
        // A hand-declared row whose item is gone reported `no vault item X`,
        // which is the same sentence for a purge and for a rename -- and a
        // rename is the common case, because an id is a mutable name. The row
        // records the uid the item carried when it was declared, so the vault
        // can be asked where that identity went. A declared route needs none
        // of this: its tags and fields travel with the item.
        None => Some(
            item_uid
                .and_then(|uid| vault.id_for_item_uid(uid))
                .map(|found| format!("vault item {item} was renamed to {found}"))
                .unwrap_or_else(|| format!("no vault item {item}")),
        ),
        Some(record) if record.get("state").and_then(Value::as_str) == Some("trashed") => {
            Some(format!("vault item {item} is in trash"))
        }
        Some(_) => None,
    };
    let mut item_present = problem.is_none();
    let mut field_present = false;
    if item_present {
        let payload = opened
            .entry(item.to_string())
            .or_insert_with(|| vault.get_item(item).map_err(|error| error.to_string()));
        match payload {
            Err(detail) => {
                item_present = false;
                problem = Some(format!("vault item {item} does not open: {detail}"));
            }
            // Redemption hands out text, and a structured field is served as
            // its canonical JSON text. A field that cannot be text at all
            // (null) keeps its own sentence, because "not a text value" and
            // "empty" are different repairs: one was written wrong, the other
            // was emptied.
            Ok(payload) => match schema::field(payload, field) {
                Err(_) => problem = Some(format!("vault item {item} has no {field} field")),
                Ok(Value::Null) => {
                    problem = Some(format!(
                        "vault item {item} field {field} is not a text value"
                    ))
                }
                Ok(Value::String(text)) if schema::is_placeholder(text.trim()) => {
                    problem = Some(format!(
                        "vault item {item} field {field} contains an uppercase placeholder, not a usable credential"
                    ))
                }
                Ok(value) if blank(value) => {
                    problem = Some(format!(
                        "vault item {item} field {field} is present but empty"
                    ))
                }
                Ok(_) => field_present = true,
            },
        }
    }
    Coordinate {
        item_present,
        field_present,
        problem,
    }
}
