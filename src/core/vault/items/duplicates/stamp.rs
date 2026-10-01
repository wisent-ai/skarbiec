// Stamping the fingerprint onto items that predate it.
//
// The refusal in the write funnel only sees items that carry a fingerprint,
// and `duplicates` can only compare those. The vault on this fleet holds 658
// active items and every one of them was written before the field existed, so
// on the day the feature shipped the report answered "no duplicates" about a
// vault where one platform appears three times. An answer that covers nothing
// is worse than no answer, because it reads like reassurance.
//
// This is the pass that closes the gap: read each active item, compute the
// fingerprint of its payload under the vault's salt, and write the field into
// the envelope. The ciphertext, revision and history are untouched — the
// payload is not rewritten, only described. An item that cannot be read is
// reported with the error the decryption gave, never skipped in silence, and
// an item whose fingerprint matches another is stamped anyway: finding those
// pairs is the whole purpose, so refusing them here would hide them again.

use anyhow::Result;
use serde_json::{json, Map, Value};

use super::{fingerprint, FINGERPRINT_KEY};

/// What one pass would do or did.
pub(in crate::core::vault) struct Stamped {
    pub stamped: Vec<String>,
    pub unreadable: Vec<(String, String)>,
    pub already: usize,
    /// Each stamped item with the fingerprint computed for it.
    pub prints: Vec<(String, String)>,
}

impl Stamped {
    pub fn report(&self, applied: bool) -> Value {
        json!({
            "applied": applied,
            "stamped": self.stamped.len(),
            "items": self.stamped,
            "already_stamped": self.already,
            "unreadable": self
                .unreadable
                .iter()
                .map(|(id, error)| json!({"item": id, "error": error}))
                .collect::<Vec<Value>>(),
        })
    }
}

/// Computes the fingerprint of every active item that has none.
///
/// `read` is the vault's own decrypt-and-validate path, passed in so this
/// stays a pure pass over the document and can be exercised without a keyring.
pub(in crate::core::vault) fn plan<F>(items: &Map<String, Value>, salt: &str, read: F) -> Stamped
where
    F: Fn(&str) -> Result<Value>,
{
    let mut stamped = Vec::new();
    let mut unreadable = Vec::new();
    let mut already = 0;
    for (id, entry) in items {
        if entry.get("state").and_then(Value::as_str) != Some("active") {
            continue;
        }
        if entry.get(FINGERPRINT_KEY).is_some() {
            already += 1;
            continue;
        }
        match read(id).and_then(|payload| fingerprint(salt, &payload)) {
            Ok(print) => stamped.push((id.clone(), print)),
            Err(error) => unreadable.push((id.clone(), format!("{error:#}"))),
        }
    }
    Stamped {
        stamped: stamped.iter().map(|(id, _)| id.clone()).collect(),
        unreadable,
        prints: stamped,
        already,
    }
}
