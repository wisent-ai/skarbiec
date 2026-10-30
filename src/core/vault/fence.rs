//! The write fence a vault move stands behind: `skarbiec fence arm
//! --transaction T` records the transaction and when it began beside the
//! vault (`<vault without .json>.fence.json`, so it travels with the vault),
//! and while it stands every vault write is refused naming it, except a
//! write that names the same transaction with `--fence T` — the move's own
//! steps. Every read the HTTP API answers carries the fence while it stands,
//! so a consumer knows writes are held. `fence lift --transaction T` ends it.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::{Path, PathBuf};

thread_local! {
    /// The transaction this invocation's writes belong to (`--fence T`).
    static PASS: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Let this thread's writes pass a fence armed for `transaction`.
pub fn pass(transaction: &str) {
    PASS.with(|cell| *cell.borrow_mut() = Some(transaction.to_string()));
}

/// Where the fence of the vault at `vault` is kept.
pub fn path_for(vault: &Path) -> PathBuf {
    vault.with_extension("fence.json")
}

/// The fence standing on the vault at `vault`: `{transaction, since}`, or
/// none.
pub fn current(vault: &Path) -> Result<Option<Value>> {
    let path = path_for(vault);
    let Some(text) = crate::core::read_present(&path, "the vault's write fence")? else {
        return Ok(None);
    };
    let fence: Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "the vault's write fence {} is not JSON, so whether writes are held cannot be read; \
             `skarbiec fence lift --transaction <T>` with the move's transaction removes it",
            path.display()
        )
    })?;
    match (
        fence.get("transaction").and_then(Value::as_str),
        fence.get("since").and_then(Value::as_str),
    ) {
        (Some(_), Some(_)) => Ok(Some(fence)),
        _ => bail!(
            "the vault's write fence {} names no transaction or no time; `skarbiec fence lift \
             --transaction <T>` with the move's transaction removes it",
            path.display()
        ),
    }
}

/// Add the standing fence, `{transaction, since}`, to a read's answer as
/// `fence`; an answer while none stands carries no `fence` member.
pub fn annotate(answer: &mut Value) -> Result<()> {
    if let Some(fence) = current(&crate::core::vault_path())? {
        answer["fence"] = fence;
    }
    Ok(())
}

/// Refuse a write to the vault at `vault` while a fence stands, unless this
/// thread's writes carry its transaction.
pub fn check_write(vault: &Path) -> Result<()> {
    let Some(fence) = current(vault)? else {
        return Ok(());
    };
    let transaction = fence["transaction"].as_str().unwrap_or("?");
    let since = fence["since"].as_str().unwrap_or("?");
    let passing = PASS.with(|cell| cell.borrow().as_deref() == Some(transaction));
    if passing {
        return Ok(());
    }
    bail!(
        "the vault is moving (transaction {transaction}, since {since}); retry after it. Writes \
         are held while the move stands, so nothing is written to a copy being moved; a step of \
         that move passes --fence {transaction}, and an abandoned move is ended with `skarbiec \
         fence lift --transaction {transaction}`"
    )
}

/// `skarbiec fence arm|lift|show`.
pub fn command(
    flags: &std::collections::HashMap<String, String>,
    positionals: &[String],
) -> Result<Value> {
    let vault = crate::core::vault_path();
    let verb = positionals.first().map(String::as_str);
    let allowed: &[&str] = match verb {
        Some("arm" | "lift") => &["transaction"],
        _ => &[],
    };
    if let Some(flag) = flags.keys().find(|flag| !allowed.contains(&flag.as_str())) {
        return Err(crate::cli::args::Usage(format!(
            "fence {} does not take --{flag}; usage: fence arm --transaction <T> | fence lift \
             --transaction <T> | fence show",
            verb.unwrap_or("")
        ))
        .into());
    }
    let transaction = || -> Result<&str> {
        flags
            .get("transaction")
            .map(String::as_str)
            .filter(|t| !t.trim().is_empty() && !t.chars().any(char::is_control))
            .ok_or_else(|| {
                crate::cli::args::Usage(
                    "fence arm and fence lift need --transaction <T>, the move's own id"
                        .to_string(),
                )
                .into()
            })
    };
    match (verb, positionals.len()) {
        (Some("show"), 1) => Ok(json!({
            "vault": vault.display().to_string(),
            "fence": current(&vault)?,
        })),
        (Some("arm"), 1) => {
            let transaction = transaction()?;
            if !crate::core::is_present(&vault, "the vault file")? {
                bail!(
                    "fence arm: no vault at {} to hold writes on; name the vault being moved with \
                     SKARBIEC_VAULT_FILE",
                    vault.display()
                );
            }
            if let Some(standing) = current(&vault)? {
                if standing["transaction"].as_str() == Some(transaction) {
                    return Ok(json!({"armed": true, "already": true, "fence": standing}));
                }
                bail!(
                    "fence arm: the vault is already fenced for transaction {} since {}; one move \
                     at a time — lift that one first (`skarbiec fence lift --transaction {}`)",
                    standing["transaction"].as_str().unwrap_or("?"),
                    standing["since"].as_str().unwrap_or("?"),
                    standing["transaction"].as_str().unwrap_or("?")
                );
            }
            let fence = json!({"transaction": transaction, "since": crate::core::clock::now_iso()});
            let path = path_for(&vault);
            crate::core::vault::atomic_write(
                &path,
                serde_json::to_string_pretty(&fence)?.as_bytes(),
            )
            .with_context(|| format!("write the vault's write fence {}", path.display()))?;
            crate::runtime::audit::append("fence-arm", &fence)?;
            Ok(json!({"armed": true, "already": false, "fence": fence}))
        }
        (Some("lift"), 1) => {
            let transaction = transaction()?;
            let Some(standing) = current(&vault)? else {
                return Ok(json!({"lifted": false, "reason": "no fence stands on this vault"}));
            };
            if standing["transaction"].as_str() != Some(transaction) {
                bail!(
                    "fence lift: the fence stands for transaction {}, not {transaction}; only the \
                     move that armed it lifts it",
                    standing["transaction"].as_str().unwrap_or("?")
                );
            }
            let path = path_for(&vault);
            std::fs::remove_file(&path)
                .with_context(|| format!("remove the vault's write fence {}", path.display()))?;
            crate::runtime::audit::append("fence-lift", &standing)?;
            Ok(json!({"lifted": true, "fence": standing}))
        }
        _ => Err(crate::cli::args::Usage(
            "usage: fence arm --transaction <T> | fence lift --transaction <T> | fence show"
                .to_string(),
        )
        .into()),
    }
}
