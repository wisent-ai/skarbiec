// An acquisition coordinate that names a role instead of an item.
//
// A workload that acquires through the broker used to name the vault item it
// reads (`acquire:<item>#<field>`), so every such product kept an item name in
// its code, and renaming or replacing the item broke it. `role:<role>` names
// what the secret is for: the grant declares `acquire:role:<role>#<field>`, the
// workload signs its proof over `role:<role>` and the field, and redemption
// reads that field of the one live item tagged `stado:role:<role>` -- the same
// role a Stado consumer selects the item by. No item, or two items, in the
// role is refused rather than guessed.

use anyhow::{bail, Result};

use super::proof::exact_name;
use super::AcquisitionFieldMissing;
use crate::core::vault::Vault;

const ROLE_COORDINATE: &str = "role:";
const ROLE_TAG: &str = "stado:role:";

/// Whether a coordinate is an exact item name or `role:<exact role>`.
pub(super) fn exact_coordinate(coordinate: &str) -> bool {
    match coordinate.strip_prefix(ROLE_COORDINATE) {
        Some(role) => exact_name(role),
        None => exact_name(coordinate),
    }
}

/// The item a coordinate reads: the item it names, or the one live item that
/// plays the role it names.
pub(super) fn item_for(vault: &Vault, coordinate: &str) -> Result<String> {
    let Some(role) = coordinate.strip_prefix(ROLE_COORDINATE) else {
        return Ok(coordinate.to_string());
    };
    let tag = format!("{ROLE_TAG}{role}");
    match crate::access::route::declaration::tagged_items(vault, &tag).as_slice() {
        [item] => Ok((*item).to_string()),
        [] => Err(AcquisitionFieldMissing.into()),
        several => bail!(
            "{} live items carry {tag}; exactly one item may play role {role}",
            several.len()
        ),
    }
}
