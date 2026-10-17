// Who can open an item on this machine: the keys its current ciphertext is
// encrypted to, beside whether this keyring holds the secret half of each.
// Nothing is decrypted, so an item that will not open can be asked why.

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::core::crypto;
use crate::core::vault::Vault;

impl Vault {
    /// The keys item `id`'s current revision is encrypted to and, for each,
    /// whether its secret half is in this machine's keyring. No key here
    /// means no read on this machine can open the item, whatever the agent's
    /// state; a key here that still fails to open it points at the agent or
    /// the keyring instead.
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
        let mut keys = Vec::new();
        for key_id in crypto::encrypted_to(ciphertext)
            .with_context(|| format!("read the session key packets of {id}"))?
        {
            let here = crypto::secret_key_present(&key_id)
                .with_context(|| format!("ask the keyring for the secret half of {key_id}"))?;
            keys.push(json!({ "key_id": key_id, "secret_key_here": here }));
        }
        let openable = keys
            .iter()
            .any(|key| key["secret_key_here"] == Value::Bool(true));
        Ok(json!({ "id": id, "encrypted_to": keys, "openable_here": openable }))
    }
}
