// The operator routes that change one item's own content: recovery codes,
// sites, a generated login, an authenticator seed, a key loaded into an
// agent, a kept file. `routes` asks this table before its own.

use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::HashMap;

use super::calls::{flags, optional, positionals, runtime, text, verbed};

pub(super) fn answer(path: &str, parsed: &Value) -> Result<Option<Value>> {
    let answer = match path {
        // Answers the code once, as the command line prints it once; the
        // desktop asks before it sends this and shows the code once.
        "/v1/operator/items/recovery-codes/take" => runtime(
            "totp",
            &HashMap::from([("take".to_string(), "true".to_string())]),
            &verbed("recovery", parsed, &["id"])?,
        ),
        // `codes` is the provider's new set, one per line, as stdin takes it.
        "/v1/operator/items/recovery-codes/replace" => {
            crate::runtime::totp::replace_recovery_codes(&text(parsed, "id")?, &text(parsed, "codes")?)
        }
        "/v1/operator/items/sites/set" => crate::runtime::logins::set_sites_from_body(parsed),
        // `sites <id> --add|--remove`: one site at a time, keeping the others;
        // `add-related` adds the sites sharing a sign-in with them.
        "/v1/operator/items/sites/change" => {
            runtime("sites", &flags(parsed, &["add", "remove", "add-related"]), &positionals(parsed, &["id"])?)
        }
        // The whole new text; an empty one removes the notes, so it is read
        // as given rather than through a helper that drops empty text.
        "/v1/operator/items/notes/set" => {
            let Some(notes) = parsed.get("notes").and_then(Value::as_str) else {
                bail!("notes required: the whole new text, empty to remove them");
            };
            crate::runtime::notes::set(&text(parsed, "id")?, notes)
        }
        // `set` with the rules, `lookup` or `clear`, as `password rules` takes them.
        "/v1/operator/items/password-rules/change" => {
            runtime("password", &flags(parsed, &["set", "lookup", "clear"]), &verbed("rules", parsed, &["id"])?)
        }
        // The password is made and stored in the backend; the answer names
        // the item and never carries it.
        "/v1/operator/items/new-login" => runtime(
            "login",
            &flags(
                parsed,
                &[
                    "username", "sites", "name", "tags", "length", "lower", "upper", "digits", "symbols",
                    "symbols-from", "unambiguous", "passphrase", "words", "separator", "capitalize",
                    "with-digit", "rules",
                ],
            ),
            &verbed("new", parsed, &["id"])?,
        ),
        // The private key is made and stored in the backend; the answer
        // carries the public key only.
        "/v1/operator/items/new-ssh-key" => runtime(
            "ssh",
            &flags(parsed, &["comment", "name", "tags"]),
            &verbed("new", parsed, &["id"])?,
        ),
        // One rotation through the provider `with` names, with the flags that
        // provider declares: its client — ssh, psql or mysql, aws, gcloud, az,
        // gh, glab or curl — runs where the vault is, and the answer names key
        // ids, accounts, revisions and public keys, never a secret.
        "/v1/operator/items/rotate" => {
            let provider = crate::runtime::rotate::provider(&text(parsed, crate::runtime::rotate::WITH)?)?;
            let taken = provider.flags();
            let mut keys: Vec<&str> = taken.iter().map(String::as_str).collect();
            keys.push(crate::runtime::rotate::WITH);
            runtime("rotate", &flags(parsed, &keys), &positionals(parsed, &["id"])?)
        }
        // The seed travels in the loopback body, never in an argument.
        "/v1/operator/items/totp-set" => {
            crate::runtime::totp::store_seed(&text(parsed, "id")?, &text(parsed, "seed")?)
        }
        // The seed leaves inside the address, as `totp uri` prints it, and
        // the read is journalled, so it is serialized with the writes.
        "/v1/operator/items/totp-uri" => runtime("totp", &HashMap::new(), &verbed("uri", parsed, &["id"])?),
        // The desktop names its own session's agent socket in `agent`: the
        // serving process may hold none, and the key goes where the operator is.
        // `id` adds one key; `tag` every key the tagged items hold.
        "/v1/operator/items/ssh-add" => runtime(
            "ssh",
            &flags(parsed, &["agent", "lifetime", "tag"]),
            &std::iter::once("add".to_string()).chain(optional(parsed, "id")).collect::<Vec<_>>(),
        ),
        // The file is on the machine the app runs on, at the absolute path its
        // panel chose; a relative one would mean the server's directory.
        "/v1/operator/items/attach" | "/v1/operator/items/detach" => {
            let given = positionals(parsed, &["id", "path"])?;
            if !given.last().is_some_and(|path| std::path::Path::new(path).is_absolute()) {
                bail!("path must be absolute: the file is the one the app chose, not one in the server's directory");
            }
            runtime(path.trim_start_matches("/v1/operator/items/"), &flags(parsed, &["tags"]), &given)
        }
        // The key file is on the machine the app runs on, at the absolute
        // path its panel chose; it is read there and never reaches the app.
        "/v1/operator/items/ssh-import" => {
            let file = text(parsed, "path")?;
            if !std::path::Path::new(&file).is_absolute() {
                bail!("path must be absolute: the key file is the one the app chose, not one in the server's directory");
            }
            runtime("ssh", &flags(parsed, &["name", "tags", "remove"]), &["import".to_string(), file, text(parsed, "id")?])
        }
        // `keep` and the list `drop`, as `merge <keep> <drop>...` takes them.
        "/v1/operator/items/merge" => {
            let mut given = vec![text(parsed, "keep")?];
            for drop in parsed.get("drop").and_then(Value::as_array).into_iter().flatten() {
                let Some(drop) = drop.as_str() else {
                    bail!("drop must list item ids as text");
                };
                given.push(drop.to_string());
            }
            crate::cli::merge::merge_value(&given)
        }
        // One item by `id`, or every live item one `tag` carries.
        "/v1/operator/items/expiry/set" => match optional(parsed, "tag") {
            Some(tag) => crate::runtime::expiry::set_tagged(&tag, &text(parsed, "on")?),
            None => crate::runtime::expiry::set(&text(parsed, "id")?, &text(parsed, "on")?),
        },
        "/v1/operator/items/expiry/clear" => match optional(parsed, "tag") {
            Some(tag) => crate::runtime::expiry::clear_tagged(&tag),
            None => crate::runtime::expiry::clear(&text(parsed, "id")?),
        },
        "/v1/operator/items/pin/add" => crate::runtime::pins::add(&text(parsed, "id")?),
        "/v1/operator/items/pin/remove" => crate::runtime::pins::remove(&text(parsed, "id")?),
        // `purge <id> --versions-before`, or with `all` every live item:
        // without `yes` it lists the stamps that would go; the desktop sends
        // `yes` only from its confirmation.
        "/v1/operator/items/purge-versions" => {
            let mut given = flags(parsed, &["yes"]);
            given.extend(flags(parsed, &["all"]));
            crate::cli::prune::purge_versions(
                &given,
                &optional(parsed, "id").into_iter().collect::<Vec<_>>(),
                &text(parsed, "versions-before")?,
            )
        }
        // The sealed message and its passphrase, once; nothing is kept.
        "/v1/operator/items/send" => crate::runtime::send::seal(&text(parsed, "id")?, &text(parsed, "field")?),
        "/v1/operator/items/copy" => {
            crate::cli::copy::copy_value(&flags(parsed, &["without"]), &positionals(parsed, &["id", "to"])?)
        }
        _ => return Ok(None),
    };
    answer.map(Some)
}
