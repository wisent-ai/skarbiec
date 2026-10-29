// The route command's published grammar and exact resource-name validation.
use anyhow::{bail, Result};
use serde_json::{json, Value};

use super::table as route_table;
use crate::core::schema::exact_token;

pub(super) fn help() -> Value {
    json!({
        "commands": [
            "route resolve [<name>...] [--consumer <c> --token-file <path>] [--emit --out <dir>] [--template <file> --out <file>]",
            "route declare --resource <resource> --item <item> --field <field> --reason <text>",
            "route withdraw --resource <resource> --reason <text>",
            "route verify [<consumer>]",
        ],
        "names": [
            "provider:<provider> -- the one credential declaring brama:provider:<provider>",
            "provider:<provider>:<id> -- the credential also declaring brama:id:<id>",
            "agent:<agent> -- the internal-authority item whose id field names that agent",
            "login:<item> -- the fields that login item's kind declares, under their exported names",
            "<item>#<field> -- one exact coordinate, named rather than declared",
            "<resource> -- anything a vault item cannot declare, from the hand-declared table",
        ],
        "table": route_table::table_path().display().to_string(),
        "usage": "route resolve reads what the vault declares -- the brama:provider: and brama:id: tags an operator wrote on a credential, the id and agent_auth_secret fields an internal-authority item carries, and the fields a login's kind declares -- and never how an item happens to be named, so renaming an item does not change which credential a name reaches. A resource no item can declare, such as origin:<page origin>/<field class>, is stated once with route declare and answered by exact id, where a rename fails loudly in route verify and names where the item went. With no name, route resolve prints every route this vault answers plus every item whose declaration is too ambiguous to act on; --emit writes one owner-only <item>.env per item reached, and --template fills a caller's own file of skarbiec:// references. route verify exits non-zero when a route cannot serve a usable credential -- an item that is missing, renamed away, in the trash or will not open on this host, a field the item does not carry, and a field that is empty or contains an uppercase placeholder. The optional <consumer> argument matches resource text and is presentation only: it narrows what is printed and grants nothing, because redemption is authorised by the live grant that registers a workload's Ed25519 key, never by this surface.",
    })
}

/// Every name a caller may ask for is checked exactly as `grant capability`
/// checks a resource it will issue against: a name carrying a newline would
/// land in a report and in a journal line as something no later reader can
/// split back out.
pub(super) fn exact_names(asked: &[String]) -> Result<Vec<String>> {
    for name in asked {
        if !exact_token(name) {
            bail!("route resolve requires exact names: {name} is not one");
        }
    }
    Ok(asked.to_vec())
}
