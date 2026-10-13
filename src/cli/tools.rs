// The commands that do not read one item: generating a value, exporting a
// runtime view of the vault, and reporting which build this is.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::{items, vault_path};

use super::args::{emit, flag_set, OrUsage};

pub(crate) fn cmd_generate(flags: &HashMap<String, String>) -> Result<()> {
    if flag_set(flags, "passphrase") {
        let count: usize = flags
            .get("words")
            .or_usage("usage: generate --passphrase --words N --separator TEXT")?
            .parse()
            .or_usage("--words must be a number")?;
        // What joins the words is the caller's choice, as the count is.
        let sep = flags
            .get("separator")
            .or_usage("usage: generate --passphrase --words N --separator TEXT")?;
        return emit(&json!({"passphrase": items::generate_passphrase(count, sep)?}));
    }
    let length: usize = flags
        .get("length")
        .or_usage("usage: generate --length N [--symbols]")?
        .parse()
        .or_usage("--length must be a number")?;
    let value = items::generate_password(
        length,
        flag_set(flags, "lower"),
        flag_set(flags, "upper"),
        flag_set(flags, "digits"),
        flag_set(flags, "symbols"),
    )?;
    emit(&json!({"password": value}))
}

// Bridge for consumers that read a JSON-array file (via an env-configured path):
// decrypt every live item and write the array
// to an owner-only file. The vault stays the source of truth; this materializes
// a runtime view for a consumer that cannot yet call resolve per item.
pub(crate) fn cmd_export(flags: &HashMap<String, String>, positionals: &[String]) -> Result<()> {
    let out = positionals
        .first()
        .or_else(|| flags.get("out"))
        .or_usage("usage: export <out-file.json>")?;
    let vault = Vault::open(vault_path())?;
    let mut rows: Vec<Value> = Vec::new();
    for entry in vault.list(false) {
        if let Some(id) = entry.get("id").and_then(Value::as_str) {
            rows.push(vault.get_item(id)?);
        }
    }
    // Decrypted items: the file is written owner-only from the first byte
    // (atomic_write), never readable under the umask and narrowed afterwards by
    // a chmod whose failure went unread while the export reported ok.
    let target = std::env::current_dir()
        .context("the working directory cannot be read to place the export")?
        .join(out);
    crate::core::vault::atomic_write(
        &target,
        serde_json::to_string(&Value::Array(rows.clone()))?.as_bytes(),
    )
    .with_context(|| format!("write export {}", target.display()))?;
    emit(&json!({"ok": true, "exported": rows.len(), "out": out}))
}

/// Report what this binary is, so a supervisor never has to identify a build by
/// counting the commands it answers — which is what the July incident actually
/// resorted to, twice, on a broker that had been replaced by hand.
///
/// `release` is the versioned coordinate the artifact was published at, and
/// `commit` is the source revision it was built from. Both are baked in at build
/// time by the publishing pipeline. A source build has neither and says so rather
/// than guessing, because an unpublished binary claiming a release coordinate is
/// worse than one admitting it has no provenance.
///
/// The coordinate alone would only identify bytes. Publishing refuses a tree with
/// uncommitted changes, so a released coordinate resolves to a revision anyone can
/// check out and rebuild — which is the difference between an artifact that is a
/// source of truth and one that is merely unique.
pub(crate) fn cmd_version() -> Result<Value> {
    let release = option_env!("SKARBIEC_RELEASE_URI");
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "release": release,
        "commit": option_env!("SKARBIEC_RELEASE_COMMIT"),
        // `release` is the word a supervisor compares against, not a synonym it
        // has to learn: a host software report classifies each file it finds as
        // `release` or `unmanaged`, and this field is how a Skarbiec binary
        // answers that question about itself. The earlier value, `published`,
        // described the same state in a second vocabulary, which left the
        // reporting side matching on a string no other surface used.
        "provenance": match release {
            Some(_) => "release",
            None => "source build",
        },
    }))
}
