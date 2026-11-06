// Who can open an item on this machine: the keys its current ciphertext is
// sealed to, beside whether this host's key file holds the secret half of
// each. Nothing is decrypted, so an item that will not open can be asked why.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::core::crypto;
use crate::core::vault::Vault;

impl Vault {
    /// The keys item `id`'s current revision is sealed to and, for each,
    /// which key it is and whether its secret half is in this host's key
    /// file. No key here means no read on this machine can open the item; a
    /// key here that still fails to open it points at the key file or its
    /// unlock phrase instead.
    pub fn readers(&self, id: &str) -> Result<Value> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let ciphertext = item
            .get("current")
            .and_then(|current| current.get("ciphertext"))
            .and_then(Value::as_str)
            .with_context(|| format!("item has no current ciphertext: {id}"))?;
        let format = match crypto::format_of(ciphertext).with_context(|| format!("item {id}"))? {
            crypto::Format::Sealed => "sealed",
            crypto::Format::OpenPgp => "openpgp",
        };
        let mut keys = Vec::new();
        for key_id in crypto::encrypted_to(ciphertext)
            .with_context(|| format!("read the recipients of {id}"))?
        {
            let (fingerprint, here) = match crypto::holder_of(&key_id)
                .with_context(|| format!("ask the key file which key {key_id} is"))?
            {
                Some((fingerprint, here)) => (Some(fingerprint), here),
                None => (None, false),
            };
            keys.push(
                json!({ "key_id": key_id, "fingerprint": fingerprint, "secret_key_here": here }),
            );
        }
        let openable = keys
            .iter()
            .any(|key| key["secret_key_here"] == Value::Bool(true));
        Ok(json!({ "id": id, "format": format, "encrypted_to": keys, "openable_here": openable }))
    }
}
