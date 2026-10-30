// `backup restore <file> [--yes]`: put a copy back as the live vault, after
// a disk failed, a bad import or a change that should not have been made. The
// copy is read as a vault first; without --yes the answer only says what it
// holds and which live items of the current vault it does not, so nothing is
// lost unseen. With --yes the current vault is first kept beside itself as
// `<vault>.pre-restore.<stamp>`, owner-only, and the copy is then written in
// its place atomically, so a restore is itself undone by restoring that.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

use crate::core::{clock, vault::Vault, vault_path};

fn live_ids(vault: &Vault) -> Vec<String> {
    vault
        .list(false)
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

pub(super) fn restore(file: &Path, confirmed: bool) -> Result<Value> {
    let copy = Vault::open(file.to_path_buf()).with_context(|| {
        format!(
            "{} does not read as a Skarbiec vault; nothing was restored",
            file.display()
        )
    })?;
    let restored = live_ids(&copy);
    let live = vault_path();
    let present = crate::core::is_present(&live, "live vault")?;
    let current = if present {
        live_ids(&Vault::open(live.clone())?)
    } else {
        Vec::new()
    };
    let lost: Vec<&String> = current.iter().filter(|id| !restored.contains(id)).collect();
    if !confirmed {
        return Ok(json!({
            "ok": true,
            "confirmed": false,
            "backup": file.display().to_string(),
            "live_items": restored.len(),
            "would_lose": lost,
        }));
    }
    crate::core::vault::fence::check_write(&live)?;
    let bytes =
        std::fs::read(file).with_context(|| format!("read the backup {}", file.display()))?;
    let kept = if present {
        Some(keep_aside(&live)?)
    } else {
        None
    };
    crate::core::vault::atomic_write(&live, &bytes).with_context(|| {
        format!(
            "write the backup {} over {}",
            file.display(),
            live.display()
        )
    })?;
    crate::runtime::audit::append(
        "vault-restored",
        &json!({"backup": file.display().to_string(), "kept_aside": kept, "lost": lost}),
    )?;
    Ok(json!({
        "ok": true,
        "confirmed": true,
        "backup": file.display().to_string(),
        "live_items": restored.len(),
        "lost": lost,
        "kept_aside": kept,
    }))
}

/// The live vault, copied owner-only beside itself before a restore replaces
/// it; the path is the answer, so the restore can be undone.
fn keep_aside(live: &Path) -> Result<String> {
    let mut name = live.as_os_str().to_owned();
    name.push(format!(".pre-restore.{}", clock::now_stamp()));
    let aside = std::path::PathBuf::from(name);
    let held =
        std::fs::read(live).with_context(|| format!("read the live vault {}", live.display()))?;
    crate::core::vault::atomic_write(&aside, &held).with_context(|| {
        format!(
            "keep the live vault aside at {}; nothing was restored",
            aside.display()
        )
    })?;
    Ok(aside.display().to_string())
}
