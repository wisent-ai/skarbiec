use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::{crypto, schema, vault::Vault};

#[derive(Debug)]
pub struct MigrationReport {
    pub items: usize,
    pub revisions: usize,
    pub grants: usize,
}

fn canonical_item_id(id: &str) -> String {
    id.strip_prefix("request:credential/")
        .map(|suffix| format!("operation:credential/{suffix}"))
        .unwrap_or_else(|| id.to_string())
}

fn exact_resource(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn decrypt_payload(ciphertext: &str, legacy_kind: &str) -> Result<(String, Value)> {
    let plain = crypto::decrypt(ciphertext).context("decrypt legacy revision")?;
    let legacy: Value = serde_json::from_str(&plain).context("parse legacy revision JSON")?;
    schema::migrate_legacy(legacy_kind, legacy)
}

fn operation_id(payload: &Value) -> Value {
    schema::field(payload, "context")
        .ok()
        .and_then(Value::as_object)
        .and_then(|context| context.get("request_id"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn recipient_fingerprints(vault: &Vault, entry: &Value) -> Vec<String> {
    let mut recipients: Vec<String> = entry
        .get("recipients")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    recipients.push(vault.owner_uid().to_string());
    let mut fingerprints = Vec::new();
    for uid in recipients {
        if let Some(fingerprint) = vault.recipient_fpr(&uid) {
            if !fingerprints.contains(&fingerprint) {
                fingerprints.push(fingerprint);
            }
        }
    }
    let recovery = vault.recovery_fpr().to_string();
    if !recovery.is_empty() && !fingerprints.contains(&recovery) {
        fingerprints.push(recovery);
    }
    fingerprints
}

fn canonical_revision(
    ciphertext: &str,
    legacy_kind: &str,
    fingerprints: &[String],
    revision: u64,
    created_at: Value,
    writer: &str,
) -> Result<(String, Value, Value)> {
    let (kind, payload) = decrypt_payload(ciphertext, legacy_kind)?;
    let canonical_ciphertext = crypto::encrypt_to(fingerprints, &serde_json::to_string(&payload)?)?;
    let record = json!({
        "revision": revision,
        "kind": kind,
        "created_at": created_at,
        "written_by": writer,
        "operation_id": operation_id(&payload),
        "ciphertext": canonical_ciphertext,
    });
    Ok((kind, payload, record))
}

fn migrate_item(vault: &Vault, id: &str, entry: &Value) -> Result<(Value, Vec<String>, usize)> {
    if entry.get("format").and_then(Value::as_u64) == Some(crate::core::vault::current_envelope()) {
        let payload = entry
            .get("current")
            .context("v2 item has no current revision")
            .and_then(revision_payload)?;
        let fields = schema::fields(&payload)?.keys().cloned().collect();
        return Ok((entry.clone(), fields, usize::MIN));
    }
    let legacy_kind = entry
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("opaque");
    let current_ciphertext = entry
        .get("current")
        .and_then(Value::as_str)
        .context("legacy item has no current ciphertext")?;
    let fingerprints = recipient_fingerprints(vault, entry);
    if fingerprints.is_empty() {
        bail!("{id} has no valid recipient fingerprint");
    }
    let writer = entry
        .get("written_by")
        .and_then(Value::as_str)
        .unwrap_or_else(|| vault.owner_uid());
    let mut history = Vec::new();
    let mut revision: u64 = std::iter::once(()).count().try_into()?;
    if let Some(legacy_history) = entry.get("history").and_then(Value::as_array) {
        for legacy_revision in legacy_history {
            let ciphertext = legacy_revision
                .get("cipher")
                .or_else(|| legacy_revision.get("ciphertext"))
                .and_then(Value::as_str)
                .context("legacy history revision has no ciphertext")?;
            let created_at = legacy_revision
                .get("at")
                .or_else(|| legacy_revision.get("created_at"))
                .cloned()
                .unwrap_or(Value::Null);
            let (_, _, record) = canonical_revision(
                ciphertext,
                legacy_kind,
                &fingerprints,
                revision,
                created_at,
                writer,
            )?;
            history.push(record);
            revision = revision
                .checked_add(std::iter::once(()).count().try_into()?)
                .context("revision overflow")?;
        }
    }
    let current_at = entry
        .get("updated_at")
        .or_else(|| entry.get("created_at"))
        .cloned()
        .unwrap_or(Value::Null);
    let (kind, payload, current) = canonical_revision(
        current_ciphertext,
        legacy_kind,
        &fingerprints,
        revision,
        current_at.clone(),
        writer,
    )?;
    let tags: Vec<Value> = entry
        .get("tags")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // `managed:weles` is a reserved tag: the CLI and `import` refuse it by name,
    // so only an authenticated Weles managed write ever put it on a legacy item.
    // That tag is therefore the item's own declaration that Weles controls it.
    // The writer identity recorded beside it is a mutable name, and testing it
    // for a `weles-` prefix meant renaming a consumer silently stripped the
    // declared tag and downgraded the item's management authority from managed
    // to owner or external, with nothing raised. The declaration decides.
    let managed_by_weles = tags.iter().any(|tag| tag.as_str() == Some("managed:weles"));
    let management = if kind == "credential-operation" {
        json!({
            "mode": "managed",
            "controller": "skarbiec-credential-lifecycle"
        })
    } else if managed_by_weles {
        json!({"mode": "managed", "controller": "weles"})
    } else if writer == vault.owner_uid() {
        json!({"mode": "owner", "controller": vault.owner_uid()})
    } else {
        json!({"mode": "external", "controller": writer})
    };
    let state = if entry
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        "trashed"
    } else {
        "active"
    };
    let canonical = json!({
        "format": crate::core::vault::current_envelope(),
        "kind": kind,
        "state": state,
        "revision": revision,
        "management": management,
        "created_at": entry.get("created_at").cloned().unwrap_or(current_at.clone()),
        "updated_at": current_at,
        "deleted_at": entry.get("deleted_at").cloned().unwrap_or(Value::Null),
        "recipients": entry.get("recipients").cloned().unwrap_or_else(|| json!([])),
        "tags": tags,
        "current": current,
        "history": history,
    });
    let fields = schema::fields(&payload)?.keys().cloned().collect();
    Ok((canonical, fields, revision as usize))
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let (mut pattern_index, mut value_index, mut star, mut retry) =
        (usize::MIN, usize::MIN, None, usize::MIN);
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index = pattern_index.saturating_add(std::iter::once(()).count());
            value_index = value_index.saturating_add(std::iter::once(()).count());
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star = Some(pattern_index);
            pattern_index = pattern_index.saturating_add(std::iter::once(()).count());
            retry = value_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index.saturating_add(std::iter::once(()).count());
            retry = retry.saturating_add(std::iter::once(()).count());
            value_index = retry;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index = pattern_index.saturating_add(std::iter::once(()).count());
    }
    pattern_index == pattern.len()
}

fn canonical_field(name: &str, fields: &[String]) -> Result<String> {
    if name == "metadata" {
        return Ok("context".to_string());
    }
    if fields.iter().any(|field| field == name) {
        return Ok(name.to_string());
    }
    let aliases: &[&str] = match name {
        "email" | "login_email" | "login-email" => &["username"],
        "login_password" | "login-password" => &["password"],
        "google_totp_secret" | "totp-secret" => &["totp_secret"],
        "api_token" | "api-token" => &["api_key", "token"],
        "key_id" | "key-id" => &["access_key_id"],
        "secret_key" | "secret-key" => &["secret_access_key"],
        _ => &[],
    };
    let matches: Vec<&str> = aliases
        .iter()
        .copied()
        .filter(|alias| fields.iter().any(|field| field == alias))
        .collect();
    match matches.as_slice() {
        [field] => Ok((*field).to_string()),
        [] => bail!("legacy capability field has no canonical target: {name}"),
        _ => bail!("legacy capability field is ambiguous: {name}"),
    }
}

fn future_contract_field(item: &str, requested: Option<&str>) -> Option<&'static str> {
    let microsoft_password = item.starts_with("weles-microsoft-") && item.ends_with("-password");
    if microsoft_password
        && requested
            .is_none_or(|field| matches!(field, "password" | "login_password" | "login-password"))
    {
        Some("password")
    } else {
        None
    }
}

fn supported_action(action: &str) -> bool {
    matches!(
        action,
        "read"
            | "stage"
            | "rotate"
            | "verify"
            | "share"
            | "trash"
            | "purge"
            | "admin"
            | "acquire"
            | "revoke"
            | "sync"
            | "enroll"
            | "donate"
    )
}

fn expand_capability(
    raw_action: &str,
    target: &str,
    item_fields: &BTreeMap<String, Vec<String>>,
    output: &mut BTreeSet<String>,
) -> Result<()> {
    let action = match raw_action {
        "write" => "stage",
        "delete" => "trash",
        action => action,
    };
    if !supported_action(action) {
        bail!("unsupported legacy grant action: {raw_action}");
    }
    let (item_pattern, requested_field) = target
        .split_once('#')
        .map_or((target, None), |(item, field)| (item, Some(field)));
    let wildcard = item_pattern.contains('*') || item_pattern.contains('?');
    let canonical_pattern = canonical_item_id(item_pattern);
    let matches: Vec<(&String, &Vec<String>)> = item_fields
        .iter()
        .filter(|(item, _)| glob_matches(&canonical_pattern, item))
        .collect();
    if matches.is_empty() {
        if !wildcard {
            if let Some(field) = future_contract_field(&canonical_pattern, requested_field) {
                output.insert(format!("{action}\u{0}{canonical_pattern}\u{0}{field}"));
                return Ok(());
            }
        }
        if action == "read" && requested_field.is_none() && !wildcard {
            output.insert(format!("{action}\u{0}{canonical_pattern}\u{0}"));
            return Ok(());
        }
        if !matches!(action, "stage" | "rotate" | "verify" | "acquire")
            && requested_field.is_none()
            && !wildcard
        {
            output.insert(format!("{action}\u{0}{canonical_pattern}\u{0}"));
            return Ok(());
        }
        // Same reasoning as a grant to a field that no longer exists: a grant
        // naming an item the vault no longer holds has nothing on the other
        // side of it, and aborting here made one stale entry enough to keep
        // every legacy item in the store unreadable permanently. Dropping is
        // faithful and can only narrow access; the line names what went so it
        // can be re-granted deliberately.
        eprintln!("dropping legacy capability {action} {target}: no canonical item of that name");
        return Ok(());
    }
    for (item, fields) in matches {
        if let Some(requested_field) = requested_field {
            // A grant naming a field the item no longer carries cannot be
            // carried forward: there is nothing on the other side of it. It used
            // to abort the whole migration, so one dangling grant left every
            // legacy item in the store unreadable for good -- `key_type` on an
            // ssh item whose canonical fields are the two keys did exactly that
            // here. Dropping the grant is the faithful move and the safe
            // direction: it can only narrow access, never widen it, and the
            // line names what was dropped so the operator can re-grant it.
            let Ok(field) = canonical_field(requested_field, fields) else {
                eprintln!(
                    "dropping legacy capability {action} {item}#{requested_field}: \
                     no canonical field of that name (item carries {})",
                    fields.join(",")
                );
                continue;
            };
            if field == "context" && action != "read" {
                bail!("context metadata may only be named by read capabilities");
            }
            output.insert(format!("{action}\u{0}{item}\u{0}{field}"));
        } else if matches!(action, "read" | "stage" | "rotate" | "verify" | "acquire") {
            for field in fields {
                output.insert(format!("{action}\u{0}{item}\u{0}{field}"));
            }
        } else {
            output.insert(format!("{action}\u{0}{item}\u{0}"));
        }
    }
    Ok(())
}

fn migrate_grants(
    tokens: &mut Map<String, Value>,
    item_fields: &BTreeMap<String, Vec<String>>,
) -> Result<usize> {
    let mut migrated = usize::MIN;
    for (consumer, entry) in tokens.iter_mut() {
        let object = entry
            .as_object_mut()
            .context("token entry is not an object")?;
        let mut expanded = BTreeSet::new();
        if let Some(capabilities) = object.get("capabilities").and_then(Value::as_array) {
            for capability in capabilities {
                let action = capability
                    .get("action")
                    .and_then(Value::as_str)
                    .context("capability has no action")?;
                let item = capability
                    .get("item")
                    .and_then(Value::as_str)
                    .context("capability has no item")?;
                let target = capability
                    .get("field")
                    .and_then(Value::as_str)
                    .map_or_else(|| item.to_string(), |field| format!("{item}#{field}"));
                expand_capability(action, &target, item_fields, &mut expanded)?;
            }
        }
        if let Some(scopes) = object.get("scopes").and_then(Value::as_array) {
            for scope in scopes {
                let scope = scope.as_str().context("legacy scope is not a string")?;
                let (action, target) = scope.split_once(':').unwrap_or(("read", scope));
                expand_capability(action, target, item_fields, &mut expanded)?;
            }
        }
        let has_workload_key = object
            .get("workload_public_key")
            .and_then(Value::as_str)
            .is_some();
        if let Some(scopes) = object.get("acquisition_scopes").and_then(Value::as_array) {
            for scope in scopes {
                let item = scope
                    .get("item")
                    .and_then(Value::as_str)
                    .context("legacy acquisition scope has no item")?;
                let field = scope
                    .get("field")
                    .and_then(Value::as_str)
                    .context("legacy acquisition scope has no field")?;
                let action = if has_workload_key { "acquire" } else { "read" };
                expand_capability(
                    action,
                    &format!("{item}#{field}"),
                    item_fields,
                    &mut expanded,
                )?;
            }
        }
        let capabilities: Vec<Value> = expanded
            .into_iter()
            .filter_map(|encoded| {
                let mut parts = encoded.split('\0');
                let action = parts.next()?;
                let item = parts.next()?;
                let field = parts.next().filter(|field| !field.is_empty());
                Some(json!({"action": action, "item": item, "field": field}))
            })
            .collect();
        let has_acquire = capabilities
            .iter()
            .any(|capability| capability.get("action").and_then(Value::as_str) == Some("acquire"));
        if has_acquire
            && capabilities.iter().any(|capability| {
                capability.get("action").and_then(Value::as_str) != Some("acquire")
            })
        {
            bail!("{consumer} mixes acquisition and direct capabilities");
        }
        if has_acquire {
            object.insert("hash".to_string(), Value::Null);
        } else {
            object.insert("workload_public_key".to_string(), Value::Null);
        }
        object.remove("scopes");
        object.remove("acquisition_scopes");
        object.insert("capabilities".to_string(), Value::Array(capabilities));
        object
            .entry("audience".to_string())
            .or_insert_with(|| json!(consumer));
        object
            .entry("expires_at".to_string())
            .or_insert_with(|| json!(u64::MAX));
        object
            .entry("workload_public_key".to_string())
            .or_insert(Value::Null);
        migrated = migrated.saturating_add(std::iter::once(()).count());
    }
    Ok(migrated)
}

fn revision_payload(revision: &Value) -> Result<Value> {
    let cipher = revision
        .get("ciphertext")
        .and_then(Value::as_str)
        .context("v2 revision has no ciphertext")?;
    let plain = crypto::decrypt(cipher)?;
    serde_json::from_str(&plain).context("v2 revision payload is not JSON")
}

fn validate_v2(vault: &Vault) -> Result<()> {
    let items = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .context("vault items section is not an object")?;
    for (id, item) in items {
        if item.get("format").and_then(Value::as_u64)
            != Some(crate::core::vault::current_envelope())
        {
            bail!("{id} is not a v2 envelope");
        }
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .context("v2 item has no kind")?;
        let current = item
            .get("current")
            .and_then(Value::as_object)
            .context("v2 item has no current revision")?;
        if current.get("kind").and_then(Value::as_str) != Some(kind) {
            bail!("{id} current revision kind differs from its envelope");
        }
        let current_value = Value::Object(current.clone());
        let payload = revision_payload(&current_value)?;
        schema::validate_payload(&payload, kind)?;
        let management = item
            .get("management")
            .and_then(Value::as_object)
            .context("v2 item has no management object")?;
        let mode = management
            .get("mode")
            .and_then(Value::as_str)
            .context("v2 item management has no mode")?;
        if !matches!(mode, "owner" | "managed" | "external") {
            bail!("{id} has an invalid management mode");
        }
        let controller = management
            .get("controller")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("v2 item management has no controller")?;
        if kind == "credential-operation"
            && (mode != "managed" || controller != "skarbiec-credential-lifecycle")
        {
            bail!("{id} credential operation is not lifecycle-managed");
        }
        let mut previous_revision = u64::MIN;
        for revision in item
            .get("history")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(std::iter::once(&current_value))
        {
            let number = revision
                .get("revision")
                .and_then(Value::as_u64)
                .context("v2 revision has no number")?;
            if number <= previous_revision {
                bail!("{id} revisions are not strictly increasing");
            }
            previous_revision = number;
            let revision_kind = revision
                .get("kind")
                .and_then(Value::as_str)
                .context("v2 revision has no kind")?;
            let revision_payload = revision_payload(revision)?;
            schema::validate_payload(&revision_payload, revision_kind)?;
        }
        if item.get("revision").and_then(Value::as_u64) != Some(previous_revision) {
            bail!("{id} envelope revision does not match current revision");
        }
    }
    let tokens = vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .context("vault tokens section is not an object")?;
    for (consumer, entry) in tokens {
        if entry.get("scopes").is_some() || entry.get("acquisition_scopes").is_some() {
            bail!("{consumer} retains legacy scopes");
        }
        let capabilities = entry
            .get("capabilities")
            .and_then(Value::as_array)
            .context("v2 grant has no capabilities array")?;
        let has_acquire = capabilities
            .iter()
            .any(|capability| capability.get("action").and_then(Value::as_str) == Some("acquire"));
        if has_acquire
            && entry
                .get("workload_public_key")
                .and_then(Value::as_str)
                .is_none()
        {
            bail!("{consumer} acquire grant has no workload public key");
        }
        if capabilities.iter().any(|capability| {
            capability
                .get("action")
                .and_then(Value::as_str)
                .is_some_and(|action| !supported_action(action))
        }) {
            bail!("{consumer} has an unsupported capability action");
        }
        if has_acquire
            && capabilities.iter().any(|capability| {
                capability.get("action").and_then(Value::as_str) != Some("acquire")
            })
        {
            bail!("{consumer} mixes acquisition and direct capabilities");
        }
        for capability in capabilities {
            let action = capability
                .get("action")
                .and_then(Value::as_str)
                .context("capability has no action")?;
            let item = capability
                .get("item")
                .and_then(Value::as_str)
                .context("capability has no exact item")?;
            if !exact_resource(item) || item.contains('*') || item.contains('?') {
                bail!("{consumer} has a non-exact capability resource");
            }
            let field = capability.get("field").and_then(Value::as_str);
            if matches!(action, "acquire" | "stage" | "rotate" | "verify") && field.is_none() {
                bail!("{consumer} field action has no exact field");
            }
            if let Some(field) = field {
                if let Some(current) = items.get(item).and_then(|entry| entry.get("current")) {
                    let payload = revision_payload(current)?;
                    if schema::field(&payload, field).is_err() {
                        bail!("{consumer} capability names a missing field");
                    }
                } else if future_contract_field(item, Some(field)) != Some(field) {
                    bail!("{consumer} field capability item has no canonical contract");
                }
                if field == "context" && action != "read" {
                    bail!("{consumer} mutation capability targets context metadata");
                }
            } else if matches!(action, "share" | "trash" | "purge" | "admin")
                && !items.contains_key(item)
            {
                bail!("{consumer} item action names a missing item");
            }
        }
    }
    Ok(())
}
pub fn migrate(vault: &mut Vault) -> Result<MigrationReport> {
    let source_items = vault
        .doc()
        .get("items")
        .and_then(Value::as_object)
        .cloned()
        .context("vault items section is not an object")?;

    let mut canonical_items = Map::new();
    let mut item_fields = BTreeMap::new();
    let mut revisions = usize::MIN;
    for (id, entry) in &source_items {
        let (canonical, fields, count) =
            migrate_item(vault, id, entry).with_context(|| format!("migrate item {id}"))?;
        let canonical_id = canonical_item_id(id);
        if canonical_items.contains_key(&canonical_id) {
            bail!("migration produces duplicate canonical item id: {canonical_id}");
        }
        canonical_items.insert(canonical_id.clone(), canonical);
        item_fields.insert(canonical_id, fields);
        revisions += count;
    }
    let mut tokens = vault
        .doc()
        .get("tokens")
        .and_then(Value::as_object)
        .cloned()
        .context("vault tokens section is not an object")?;
    let grants = migrate_grants(&mut tokens, &item_fields)?;
    let document = vault
        .doc_mut()
        .as_object_mut()
        .context("vault document is not an object")?;
    document.insert("version".to_string(), json!("v2"));
    document.insert("items".to_string(), Value::Object(canonical_items));
    document.insert("tokens".to_string(), Value::Object(tokens));
    validate_v2(vault)?;
    vault.save()?;
    Ok(MigrationReport {
        items: source_items.len(),
        revisions,
        grants,
    })
}
