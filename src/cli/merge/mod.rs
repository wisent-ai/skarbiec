// `merge <keep> <drop>...`: settle one account kept in several items, as
// health's same_account names them. Every grant naming a dropped item is
// moved to the kept one, bearer kept, then the dropped items go to the
// trash, where restore brings any of them back. A person who could open a
// dropped item but not the kept one is named, not added: who reads the kept
// value stays the owner's decision, made with share.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::vault::Vault;
use crate::core::vault_path;

use super::args::Usage;
use super::items::ensure_owner_mutation_allowed;
use super::rename::grants_naming;

const USAGE: &str = "usage: merge <keep> <drop> [<drop>...]";

pub(crate) fn merge_value(positionals: &[String]) -> Result<Value> {
    let [keep, drops @ ..] = positionals else {
        return Err(Usage(USAGE.to_string()).into());
    };
    if drops.is_empty() {
        return Err(Usage(USAGE.to_string()).into());
    }
    if drops.contains(keep) {
        return Err(Usage(format!(
            "{keep} is both kept and dropped; name it once, as the item to keep"
        ))
        .into());
    }
    let vault = Vault::open(vault_path())?;
    // Every item is checked before anything moves, so a refused one leaves
    // the whole set as it was.
    ensure_owner_mutation_allowed(&vault, keep, "merge")?;
    vault.get_item(keep)?;
    for drop in drops {
        ensure_owner_mutation_allowed(&vault, drop, "remove")?;
    }
    let kept_readers = vault.item_recipient_uids(keep)?;
    let mut merged = Vec::new();
    for drop in drops {
        let readers_not_on_kept: Vec<String> = vault
            .item_recipient_uids(drop)?
            .into_iter()
            .filter(|uid| !kept_readers.contains(uid))
            .collect();
        let target = HashMap::from([
            ("from".to_string(), drop.clone()),
            ("to".to_string(), keep.clone()),
        ]);
        let mut moved = Vec::new();
        let mut not_moved = Vec::new();
        for consumer in grants_naming(&Vault::open(vault_path())?, drop) {
            match crate::access::dispatch(
                "grant",
                &target,
                &["retarget".to_string(), consumer.clone()],
            ) {
                Ok(_) => moved.push(consumer),
                Err(error) => {
                    not_moved.push(json!({"consumer": consumer, "error": format!("{error:#}")}))
                }
            }
        }
        // A grant that could not move would name a trashed item; the drop
        // waits for the owner instead.
        let trashed = not_moved.is_empty();
        if trashed {
            super::reads::cmd_delete(std::slice::from_ref(drop))?;
        }
        merged.push(json!({
            "item": drop,
            "trashed": trashed,
            "grants_moved": moved,
            "grants_not_moved": not_moved,
            "readers_not_on_kept": readers_not_on_kept,
        }));
    }
    crate::runtime::audit::append("items-merged", &json!({"kept": keep, "items": drops}))?;
    let ok = merged.iter().all(|row| row["trashed"] == json!(true));
    Ok(json!({"ok": ok, "kept": keep, "merged": merged}))
}
