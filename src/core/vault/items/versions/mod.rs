// Reading one saved version of an item without making it current: the value
// a rotation replaced, the password before a bad change, looked at and
// copied without the new revision a restore writes.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::core::crypto;
use crate::core::vault::Vault;

impl Vault {
    /// The payload item `id` held in the saved version stamped `at`, the
    /// stamp `history` lists and `restore --at` takes. A stamp that names no
    /// version is refused with the stamps that do exist.
    pub fn version_payload(&self, id: &str, at: &str) -> Result<Value> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let history = super::stored_history(id, item)?;
        let Some(chosen) = history
            .iter()
            .find(|version| version.get("created_at").and_then(Value::as_str) == Some(at))
        else {
            let stamps: Vec<&str> = history
                .iter()
                .filter_map(|version| version.get("created_at").and_then(Value::as_str))
                .collect();
            if stamps.is_empty() {
                bail!("no version at {at} for {id}: {id} keeps no earlier version, only its current value");
            }
            bail!(
                "no version at {at} for {id}; its saved versions are at: {} (`skarbiec history {id}` lists them)",
                stamps.join(", ")
            );
        };
        let cipher = chosen
            .get("ciphertext")
            .and_then(Value::as_str)
            .with_context(|| format!("the version of {id} at {at} holds no ciphertext"))?;
        let plain = crypto::decrypt(cipher).with_context(|| format!("open the version of {id} at {at}"))?;
        serde_json::from_str(&plain).with_context(|| format!("the version of {id} at {at} is not JSON"))
    }

    /// Remove for good every saved version of item `id` stamped before
    /// `before`, keeping later ones and the current value; answers the stamps
    /// removed, oldest first. A version carrying no stamp cannot be placed
    /// before anything and is kept. The caller saves.
    pub fn forget_versions_before(&mut self, id: &str, before: &str) -> Result<Vec<String>> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let history = super::stored_history(id, item)?;
        let older = |version: &Value| {
            version
                .get("created_at")
                .and_then(Value::as_str)
                .is_some_and(|at| at < before)
        };
        let forgotten: Vec<String> = history
            .iter()
            .filter(|version| older(version))
            .filter_map(|version| version.get("created_at").and_then(Value::as_str).map(str::to_string))
            .collect();
        if forgotten.is_empty() {
            return Ok(forgotten);
        }
        let kept: Vec<Value> = history.into_iter().filter(|version| !older(version)).collect();
        self.doc
            .get_mut("items")
            .and_then(|items| items.get_mut(id))
            .and_then(Value::as_object_mut)
            .with_context(|| format!("vault item {id} is not an object"))?
            .insert("history".to_string(), Value::Array(kept));
        Ok(forgotten)
    }
}
