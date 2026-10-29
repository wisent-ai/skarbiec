// `skarbiec backup <directory>` keeps a copy of the vault file where the
// owner chooses — an external disk, a synced folder — and `skarbiec backup
// check <file> [--open]` says whether a copy would restore. The vault file is
// ciphertext, so the copy is too: it opens only with the keys the vault
// itself needs. A copy is written owner-only beside nothing it could replace,
// synced, then read back as a vault before the command answers, so a copy
// that could not restore is never reported as made. Restoring is pointing
// SKARBIEC_VAULT_FILE at the copy, or `migrate --from <copy>`.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::cli::args::{flag_set, Usage};
use crate::core::{clock, vault::Vault, vault_path};

mod diff;
mod restore;
mod scheduled;

pub use scheduled::scheduled_pass;

const USAGE: &str = "usage: backup <directory> | backup check <file> [--open] | backup diff <file> | backup restore <file> [--yes] | backup schedule [<directory>] | backup unschedule";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    positionals: &[String],
) -> Result<Option<Value>> {
    if command != "backup" {
        return Ok(None);
    }
    let answer = match positionals {
        [verb, file] if verb == "check" => check(Path::new(file), flag_set(flags, "open"))?,
        [verb, file] if verb == "diff" => diff::diff(Path::new(file))?,
        [verb, file] if verb == "restore" => restore::restore(Path::new(file), flag_set(flags, "yes"))?,
        [verb, directory] if verb == "schedule" => scheduled::schedule(Path::new(directory))?,
        [verb] if verb == "schedule" => scheduled::current()?,
        [verb] if verb == "unschedule" => scheduled::unschedule()?,
        // A bare word reaches `make`, which refuses anything not absolute.
        [directory] => make(Path::new(directory))?,
        _ => return Err(Usage(USAGE.to_string()).into()),
    };
    Ok(Some(answer))
}

/// What a vault file holds, read as a vault: its live and trashed items, and
/// with `open` each live item that would not decrypt with the keys here.
fn describe(path: &Path, open: bool) -> Result<Value> {
    let copy = Vault::open(path.to_path_buf())
        .with_context(|| format!("{} does not read as a Skarbiec vault", path.display()))?;
    let live: Vec<String> = copy
        .list(false)
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let all = copy.list(true).len();
    let unreadable: Vec<Value> = if open {
        live.iter()
            .filter_map(|id| match copy.get_item(id) {
                Ok(_) => None,
                Err(error) => Some(json!({"item": id, "error": format!("{error:#}")})),
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(json!({
        "live_items": live.len(),
        "trashed_items": all - live.len(),
        "opened": open,
        "unreadable": unreadable,
    }))
}

fn make(directory: &Path) -> Result<Value> {
    if !directory.is_absolute() {
        return Err(Usage(format!(
            "backup takes an absolute directory, not {}: a relative one would land wherever the command ran",
            directory.display()
        ))
        .into());
    }
    if !crate::core::file_type(directory, "the backup directory")?.is_some_and(|kind| kind.is_dir()) {
        bail!("{} is not a directory here; nothing was copied", directory.display());
    }
    let source = vault_path();
    // Read as a vault first: a file that does not open is not worth keeping.
    Vault::open(source.clone())?;
    let name = match source.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => bail!("the vault path {} names no file", source.display()),
    };
    let target: PathBuf = directory.join(format!("{name}.{}", clock::now_stamp()));
    let mut input = File::open(&source).with_context(|| format!("open the vault file {}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(crate::core::vault::private_file_mode()?)
        .open(&target)
        .with_context(|| format!("create the backup {}", target.display()))?;
    let bytes = std::io::copy(&mut input, &mut output).with_context(|| format!("copy the vault to {}", target.display()))?;
    output.sync_all().with_context(|| format!("sync the backup {}", target.display()))?;
    let held = describe(&target, false)?;
    crate::runtime::audit::append(
        "vault-backed-up",
        &json!({"backup": target.display().to_string(), "bytes": bytes}),
    )?;
    Ok(json!({"ok": true, "backup": target.display().to_string(), "bytes": bytes, "holds": held}))
}

fn check(file: &Path, open: bool) -> Result<Value> {
    let held = describe(file, open)?;
    let readable = held
        .get("unreadable")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    Ok(json!({"ok": readable, "backup": file.display().to_string(), "holds": held}))
}
