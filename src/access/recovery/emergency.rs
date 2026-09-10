// Emergency access: a grant that waits out its delay in the open, can be
// cancelled while it waits, and is activated only when the wait is over.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::{ensure_section, load, now_iso};

pub(super) fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "emergency-grant" => {
            let grantee = positionals
                .first()
                .context("usage: emergency-grant <grantee> --activate-after <iso>")?;
            let activate_after = flags
                .get("activate-after")
                .context("--activate-after <iso8601> required")?;
            let mut vault = load()?;
            if vault.recipient_fpr(grantee).is_none() {
                return Ok(Some(
                    json!({"status": "blocked", "reason": "unknown_recipient", "grantee": grantee}),
                ));
            }
            let stamp = now_iso();
            ensure_section(vault.doc_mut(), "emergency").insert(
                grantee.clone(),
                json!({
                    "activate_after": activate_after,
                    "granted_at": stamp,
                    "status": "pending",
                }),
            );
            vault.save()?;
            crate::runtime::audit::append(
                "emergency-grant",
                &json!({"grantee": grantee, "activate_after": activate_after}),
            )?;
            Ok(Some(
                json!({"ok": true, "grantee": grantee, "activate_after": activate_after}),
            ))
        }
        "emergency-cancel" => {
            let grantee = positionals
                .first()
                .context("usage: emergency-cancel <grantee>")?;
            let mut vault = load()?;
            ensure_section(vault.doc_mut(), "emergency").remove(grantee);
            vault.save()?;
            crate::runtime::audit::append("emergency-cancel", &json!({"grantee": grantee}))?;
            Ok(Some(json!({"ok": true, "grantee": grantee})))
        }
        "emergency-list" => {
            let vault = load()?;
            Ok(Some(
                vault
                    .doc()
                    .get("emergency")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            ))
        }
        "emergency-activate" => {
            let grantee = positionals
                .first()
                .context("usage: emergency-activate <grantee>")?;
            let mut vault = load()?;
            let activate_after = vault
                .doc()
                .get("emergency")
                .and_then(|e| e.get(grantee))
                .and_then(|g| g.get("activate_after"))
                .and_then(Value::as_str)
                .with_context(|| format!("no emergency grant for {grantee}"))?
                .to_string();
            let current = now_iso();
            if current < activate_after {
                return Ok(Some(
                    json!({"status": "not_yet", "grantee": grantee, "activate_after": activate_after, "now": current}),
                ));
            }
            let ids: Vec<String> = vault
                .doc()
                .get("items")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter(|(_, item)| {
                            item.get("state").and_then(Value::as_str) == Some("active")
                        })
                        .map(|(id, _)| id.clone())
                        .collect()
                })
                .unwrap_or_default();
            let mut shared = Vec::new();
            for id in &ids {
                let item = vault
                    .doc()
                    .get("items")
                    .and_then(|m| m.get(id))
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let item_kind = item
                    .get("kind")
                    .and_then(Value::as_str)
                    .context("canonical item has no kind")?
                    .to_string();
                let tags: Vec<String> = item
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let payload = vault.get_item(id)?;
                let mut recipients = vault.item_recipient_uids(id);
                if !recipients.iter().any(|recipient| recipient == grantee) {
                    recipients.push(grantee.clone());
                }
                vault.set_item(id, &item_kind, &payload, &recipients, &tags)?;
                shared.push(id.clone());
            }
            ensure_section(vault.doc_mut(), "emergency")
                .get_mut(grantee)
                .and_then(Value::as_object_mut)
                .context("emergency entry")?
                .insert("status".to_string(), json!("activated"));
            vault.save()?;
            crate::runtime::audit::append(
                "emergency-activate",
                &json!({"grantee": grantee, "items": shared.len()}),
            )?;
            Ok(Some(
                json!({"ok": true, "grantee": grantee, "shared_items": shared}),
            ))
        }
        _ => Ok(None),
    }
}
