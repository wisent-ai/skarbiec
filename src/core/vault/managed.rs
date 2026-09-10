// Items a managed workload owns: tags, staged revisions, activation, discard
// and trashing. A staged revision exists so a rotation can be proven before it
// replaces the field anyone is reading.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::{current_envelope, entry_item_uid, mint_item_uid, now, obj_mut, ManagedWrite, Vault};
use crate::core::{crypto, schema};

impl Vault {
    /// Replace one item's tags without touching its payload.
    ///
    /// Tags sit beside the envelope, not inside it: they are how consumers
    /// enumerate what an item is, and nothing about the ciphertext, the
    /// recipient list or the revision depends on them. Setting them through
    /// `set_item_with_writer` would re-encrypt the payload to whatever
    /// recipients the entry carries now, which for an item written with an
    /// empty recipient list narrows access to a credential that is in use, and
    /// requires decrypting it first. This writes the metadata alone.
    pub fn set_item_tags(&mut self, id: &str, tags: &[String]) -> Result<()> {
        let mut entry = self
            .doc
            .get("items")
            .and_then(Value::as_object)
            .and_then(|items| items.get(id))
            .cloned()
            .with_context(|| format!("no item: {id}"))?;
        if entry.get("format").and_then(Value::as_u64) != Some(current_envelope()) {
            bail!("{id} still uses the legacy envelope; run migrate-v2 before updating it");
        }
        // `retag` is the one write whose entire subject is the tag list, so it
        // is the one that must not slip past the registry on its way around
        // `set_item_with_writer`. Same rule as there: a tag the item already
        // carries is preserved, not re-judged, so restoring a lost enumeration
        // tag onto an item that also carries an older unregistered one still
        // works.
        let written: Vec<Value> = tags.iter().cloned().map(Value::String).collect();
        let carried: &[Value] = entry
            .get("tags")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        schema::ensure_registered_tags(carried, &written)?;
        entry["tags"] = Value::Array(written);
        entry["updated_at"] = json!(now());
        // Lazy mint. `retag` mutates the envelope in place, so an existing uid
        // survives untouched; an item written before uids existed picks one up
        // here rather than waiting for the backfill. Every write is a chance to
        // stamp one, which is what makes the field arrive without anyone
        // running anything.
        if entry_item_uid(&entry).is_none() {
            entry["item_uid"] = json!(mint_item_uid()?);
        }
        obj_mut(&mut self.doc, "items").insert(id.to_string(), entry);
        self.save()
    }

    pub fn stage_managed_field(
        &mut self,
        id: &str,
        field: &str,
        value: Value,
        expected_revision: u64,
        write: ManagedWrite<'_>,
    ) -> Result<u64> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        if item.get("format").and_then(Value::as_u64) != Some(current_envelope()) {
            bail!("item uses the legacy envelope: {id} (run migrate-v2)");
        }
        if item.get("state").and_then(Value::as_str) != Some("active") {
            bail!("{id} is not active");
        }
        if item.get("revision").and_then(Value::as_u64) != Some(expected_revision) {
            bail!("item revision changed; reopen and retry the operation");
        }
        let management = item
            .get("management")
            .and_then(Value::as_object)
            .context("managed item has no management envelope")?;
        if management.get("mode").and_then(Value::as_str) != Some("managed")
            || management.get("controller").and_then(Value::as_str) != Some(write.controller)
        {
            bail!("{id} is controlled by a different management authority");
        }
        if item
            .get("current")
            .and_then(|current| current.get("written_by"))
            .and_then(Value::as_str)
            != Some(write.writer)
        {
            bail!("{id} may only be staged by its exact active writer");
        }
        if let Some(pending) = item.get("pending") {
            if pending.get("operation_id").and_then(Value::as_str) == write.operation_id {
                return pending
                    .get("revision")
                    .and_then(Value::as_u64)
                    .context("pending revision has no revision number");
            }
            bail!("{id} already has a different staged revision");
        }
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .context("canonical item has no kind")?
            .to_string();
        let recipients = self.item_recipient_uids(id);
        let mut payload = self.get_item(id)?;
        schema::fields(&payload)?;
        let same_as_current = schema::field(&payload, field).ok() == Some(&value);
        payload
            .get_mut("fields")
            .and_then(Value::as_object_mut)
            .context("canonical item has no mutable fields object")?
            .insert(field.to_string(), value);
        schema::validate_payload(&payload, &kind)?;
        let revision = expected_revision
            .checked_add(std::iter::once(()).count() as u64)
            .context("item revision overflow")?;
        let cipher = crypto::encrypt_to(
            &self.fprs_for(&recipients),
            &serde_json::to_string(&payload)?,
        )?;
        let stamp = now();
        obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .context("canonical item is not an object")?
            .insert(
                "pending".to_string(),
                json!({
                    "revision": revision,
                    "created_at": stamp,
                    "kind": kind,
                    "written_by": write.writer,
                    "operation_id": write.operation_id,
                    "field": field,
                    "same_as_current": same_as_current,
                    "ciphertext": cipher,
                }),
            );
        self.save()?;
        Ok(revision)
    }
    pub fn trash_managed_item(&mut self, id: &str, controller: &str, writer: &str) -> Result<()> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let management = item
            .get("management")
            .and_then(Value::as_object)
            .context("managed item has no management envelope")?;
        if item.get("state").and_then(Value::as_str) != Some("active")
            || management.get("mode").and_then(Value::as_str) != Some("managed")
            || management.get("controller").and_then(Value::as_str) != Some(controller)
            || item
                .get("current")
                .and_then(|current| current.get("written_by"))
                .and_then(Value::as_str)
                != Some(writer)
        {
            bail!("{id} is not controlled by this exact management writer");
        }
        if item.get("pending").is_some() {
            bail!("{id} has a staged revision; resolve it before removal");
        }
        let entry = obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .context("canonical item is not an object")?;
        entry.insert("state".to_string(), json!("trashed"));
        entry.insert("deleted_at".to_string(), json!(now()));
        self.save()
    }

    pub fn activate_staged_revision(
        &mut self,
        id: &str,
        operation_id: &str,
        field: &str,
        writer: &str,
    ) -> Result<u64> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let pending = item
            .get("pending")
            .cloned()
            .context("item has no staged revision")?;
        if pending.get("operation_id").and_then(Value::as_str) != Some(operation_id)
            || pending.get("field").and_then(Value::as_str) != Some(field)
            || pending.get("written_by").and_then(Value::as_str) != Some(writer)
        {
            bail!("staged revision does not belong to this operation and writer");
        }
        let revision = pending
            .get("revision")
            .and_then(Value::as_u64)
            .context("staged revision has no revision number")?;
        let mut history = item
            .get("history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        history.push(
            item.get("current")
                .cloned()
                .context("canonical item has no current revision")?,
        );
        let stamp = now();
        let entry = obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .context("canonical item is not an object")?;
        entry.insert("current".to_string(), pending);
        entry.insert("history".to_string(), Value::Array(history));
        entry.insert("revision".to_string(), json!(revision));
        entry.insert("updated_at".to_string(), json!(stamp));
        entry.remove("pending");
        self.save()?;
        Ok(revision)
    }

    pub fn discard_staged_revision(
        &mut self,
        id: &str,
        operation_id: &str,
        field: &str,
        writer: &str,
    ) -> Result<()> {
        let item = self
            .doc
            .get("items")
            .and_then(|items| items.get(id))
            .with_context(|| format!("no item: {id}"))?;
        let pending = item.get("pending").context("item has no staged revision")?;
        if pending.get("operation_id").and_then(Value::as_str) != Some(operation_id)
            || pending.get("field").and_then(Value::as_str) != Some(field)
            || pending.get("written_by").and_then(Value::as_str) != Some(writer)
        {
            bail!("staged revision does not belong to this operation and writer");
        }
        obj_mut(&mut self.doc, "items")
            .get_mut(id)
            .and_then(Value::as_object_mut)
            .context("canonical item is not an object")?
            .remove("pending");
        self.save()
    }
}
