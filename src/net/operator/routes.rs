// One operator route to one backend command. Every arm names a command that
// exists, so a route that answers nothing is a bug in this table. The reads
// live in `reads`; this table answers the ones that change something.

use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::HashMap;

use super::calls::{access, flags, grant, inbox, net, optional, positionals, rotation, text};
use crate::core;

pub(super) fn answer(path: &str, parsed: &Value) -> Result<Value> {
    if let Some(read) = super::reads::answer(path, parsed)? {
        return Ok(read);
    }
    if let Some(changed) = super::items::answer(path, parsed)? {
        return Ok(changed);
    }
    if let Some(reached) = super::replicas::answer(path, parsed)? {
        return Ok(reached);
    }
    if let Some(copied) = super::copies::answer(path, parsed)? {
        return Ok(copied);
    }
    if let Some(owned) = super::owner::answer(path, parsed)? {
        return Ok(owned);
    }
    let none: Vec<String> = Vec::new();
    let no_flags = HashMap::new();
    match path {
        // Mutations, one route per verb, bodies naming exact targets.
        "/v1/operator/vaults/create" => {
            crate::cmd_init(&no_flags, &positionals(parsed, &["owner"])?)
        }
        "/v1/operator/items/import" => core::importer::run(
            &flags(parsed, &["format", "conflict"]),
            &positionals(parsed, &["path"])?,
        ),
        // One id, or `tag` / `untouched-since` (with `yes` to act) as delete takes them.
        "/v1/operator/items/trash" => {
            match crate::cli::bulk::delete_set(&flags(parsed, &["tag", "untouched-since", "yes"])) {
                Some(answer) => answer,
                None => crate::cmd_delete(&positionals(parsed, &["id"])?),
            }
        }
        "/v1/operator/items/reclaim" => crate::cmd_reclaim(&positionals(parsed, &["id"])?),
        "/v1/operator/items/rename" => crate::cli::rename::rename_value(
            &flags(parsed, &["move-grants"]),
            &positionals(parsed, &["id", "to"])?,
        ),
        // Connecting the autofill extension mints a grant and writes the two
        // manifests for the user the serving process runs as.
        "/v1/operator/browser-host/install" => {
            crate::browser::install_host(&flags(parsed, &["binary"]))
        }
        "/v1/operator/browser-host/uninstall" => crate::browser::uninstall_host(),
        "/v1/operator/browser-host/cover" => crate::browser::cover_all(),
        // A review is journalled, so it is serialized with the writes;
        // `breached` asks Have I Been Pwned too, as `--breached` does, and
        // `alert` posts the findings as `--alert` does.
        "/v1/operator/review" => {
            let mut chosen = flags(parsed, &["before"]);
            chosen.extend(flags(parsed, &["breached", "alert"]));
            super::calls::runtime("review", &chosen, &none)
        }
        // The desktop sends this only from its own confirmation, after showing
        // the preview `/v1/operator/upgrade` answers.
        "/v1/operator/upgrade/apply" => {
            let mut chosen = flags(parsed, &["snapshot"]);
            chosen.insert("apply".to_string(), "true".to_string());
            core::items::upgrade(&chosen)
        }
        // The signing secret is generated in the vault and never answered.
        "/v1/operator/agents/enrol" => {
            crate::access::agent::enrol(&positionals(parsed, &["agent"])?)
        }
        // With `at`, the saved version recorded at that stamp becomes the
        // current value, as `restore <id> --at <at>` does; with `tag` (and
        // `yes` to act), every trashed item carrying it comes back.
        "/v1/operator/items/restore" => match optional(parsed, "tag") {
            Some(tag) => crate::cli::bulk::restore_tagged(&flags(parsed, &["yes"]), &tag),
            None => crate::cmd_restore(
                &positionals(parsed, &["id"])?,
                optional(parsed, "at").as_deref(),
            ),
        },
        // Only the write: a generated value never travels in an API answer,
        // so `into` is required here and the answer names the revision.
        "/v1/operator/items/generate" => {
            text(parsed, "into")?;
            crate::cli::generate::generate_value(&flags(
                parsed,
                &[
                    "into",
                    "field",
                    "length",
                    "lower",
                    "upper",
                    "digits",
                    "symbols",
                    "symbols-from",
                    "unambiguous",
                    "passphrase",
                    "words",
                    "separator",
                    "capitalize",
                    "with-digit",
                    "rules",
                    "rules-of",
                ],
            ))
        }
        // The desktop asks "Purge Permanently" before it sends this request.
        "/v1/operator/items/purge" => crate::cmd_purge(&positionals(parsed, &["id"])?, true),
        // `purge --trashed-before`: without `yes` it lists what would go, and
        // the desktop sends `yes` only from its own confirmation.
        "/v1/operator/items/purge-trash" => crate::cli::tools::cmd_purge_trash(
            &flags(parsed, &["yes"]),
            &none,
            &text(parsed, "trashed-before")?,
        ),
        // Either one item (`id`) or every item carrying `tag`, each with an
        // optional `until` ending the share, as the command line's
        // `share`/`revoke [--tag <tag>]` take.
        "/v1/operator/items/share" | "/v1/operator/items/revoke" => {
            let command = leaf(path).trim_start_matches("items ").to_string();
            match parsed.get("tag") {
                Some(_) => access(
                    &command,
                    &flags(parsed, &["tag", "until"]),
                    &positionals(parsed, &["uid"])?,
                ),
                None => access(
                    &command,
                    &flags(parsed, &["until"]),
                    &positionals(parsed, &["id", "uid"])?,
                ),
            }
        }
        "/v1/operator/shares/expire" => crate::access::recipients::expire_timed_shares(),
        // `import` is the key file's path on the serving machine, as add takes it.
        "/v1/operator/recipients/rekey" => access(
            "recipient",
            &flags(parsed, &["import", "yes"]),
            &[vec!["rekey".to_string()], positionals(parsed, &["uid"])?].concat(),
        ),
        // Both files are paths on the machine serving this API; a relative one
        // would resolve against a working directory nobody sees.
        "/v1/operator/migrate" => {
            let from = text(parsed, "from")?;
            let to = text(parsed, "to")?;
            if !std::path::Path::new(&from).is_absolute()
                || !std::path::Path::new(&to).is_absolute()
            {
                bail!("from and to must be absolute paths of vault files on this machine; got {from} and {to}");
            }
            crate::core::items::migrate_vault(&flags(parsed, &["from", "to", "force", "reconcile"]))
        }
        "/v1/operator/recipients/add" => access(
            "recipient add",
            &flags(parsed, &["import", "role"]),
            &positionals(parsed, &["uid"])?,
        ),
        // The desktop's Remove from vault sheet is the confirmation it sends.
        "/v1/operator/recipients/remove" => {
            let confirmed = HashMap::from([("yes".to_string(), "true".to_string())]);
            access(
                "recipient remove",
                &confirmed,
                &positionals(parsed, &["uid"])?,
            )
        }
        "/v1/operator/rotation/set" => rotation(
            "set",
            &flags(
                parsed,
                &[
                    "every-days",
                    "provider",
                    "consumer",
                    "purpose",
                    "with",
                    "url",
                    "length",
                    "delete-old",
                    "comment",
                    "hosts",
                    "account",
                    "github",
                    "gitlab",
                    "github-account",
                    "gitlab-account",
                    "github-signing",
                    "tenant",
                    "end-date",
                    "years",
                    "days",
                ],
            ),
            &positionals(parsed, &["item"])?,
        ),
        "/v1/operator/rotation/remove" => {
            rotation("remove", &no_flags, &positionals(parsed, &["item"])?)
        }
        "/v1/operator/rotation/run" => rotation("run", &flags(parsed, &["item", "now"]), &none),
        "/v1/operator/grants/capability" => grant(
            "capability",
            &flags(
                parsed,
                &[
                    "agent",
                    "purpose",
                    "resource",
                    "target",
                    "ttl",
                    "max-uses",
                    "authorization-id",
                ],
            ),
            &none,
        ),
        "/v1/operator/grants/issue" => grant(
            "issue",
            &flags(
                parsed,
                &[
                    "capabilities",
                    "workload-public-key-file",
                    "ttl-seconds",
                    "until-revoked",
                    "audience",
                    "replace-capabilities",
                ],
            ),
            &positionals(parsed, &["consumer"])?,
        ),
        "/v1/operator/grants/ensure" => grant(
            "ensure",
            &flags(parsed, &["field", "token-file"]),
            &positionals(parsed, &["consumer", "item"])?,
        ),
        "/v1/operator/grants/narrow" => grant(
            "narrow",
            &flags(parsed, &["field"]),
            &positionals(parsed, &["consumer", "item"])?,
        ),
        "/v1/operator/grants/keep" => {
            grant("keep", &no_flags, &positionals(parsed, &["consumer"])?)
        }
        "/v1/operator/grants/retarget" => grant(
            "retarget",
            &flags(parsed, &["from", "to"]),
            &positionals(parsed, &["consumer"])?,
        ),
        // `--token-file` and never `--token`: the command line offers both, and
        // a loopback body is the one place a bearer must not travel, so a
        // console proves possession through the same owner-only file the
        // widening route already requires.
        "/v1/operator/grants/verify" => grant(
            "verify",
            &flags(parsed, &["action", "field", "token-file"]),
            &positionals(parsed, &["consumer", "item"])?,
        ),
        // One consumer, `expired: true`, or `idle-since` with `yes`, as the
        // command line takes them.
        "/v1/operator/grants/revoke" => match optional(parsed, "consumer") {
            Some(consumer) => grant("revoke", &no_flags, &[consumer]),
            None => grant(
                "revoke",
                &flags(parsed, &["expired", "idle-since", "yes"]),
                &none,
            ),
        },
        "/v1/operator/donations/accept" => {
            inbox("donation accept", &no_flags, &positionals(parsed, &["id"])?)
        }
        "/v1/operator/donations/reject" => {
            inbox("donation reject", &no_flags, &positionals(parsed, &["id"])?)
        }
        "/v1/operator/credential" => super::credential::answer(parsed),
        "/v1/operator/emergency/grant" => access(
            &leaf(path),
            &flags(parsed, &["activate-after"]),
            &positionals(parsed, &["grantee"])?,
        ),
        "/v1/operator/emergency/cancel" => {
            access(&leaf(path), &no_flags, &positionals(parsed, &["grantee"])?)
        }
        "/v1/operator/emergency/activate" | "/v1/operator/emergency/revoke" => {
            access(&leaf(path), &no_flags, &positionals(parsed, &["grantee"])?)
        }
        "/v1/operator/recovery/drill" => {
            access(&leaf(path), &no_flags, &positionals(parsed, &["subject"])?)
        }
        "/v1/operator/policy/set" => access(
            "policy set",
            &no_flags,
            &positionals(parsed, &["key", "value"])?,
        ),
        "/v1/operator/policy/unset" => {
            access("policy unset", &no_flags, &positionals(parsed, &["key"])?)
        }
        // The candidate travels in the request body, never in a command's
        // argv, and the answer never repeats it.
        "/v1/operator/policy/check" => crate::access::policy::check(&text(parsed, "candidate")?),
        "/v1/operator/sync/init" => net(
            "mirror init",
            &no_flags,
            &positionals(parsed, &["endpoint"])?,
        ),
        "/v1/operator/sync/push" => net("mirror push", &flags(parsed, &["message"]), &none),
        "/v1/operator/sync/pull" => net("mirror pull", &flags(parsed, &["force"]), &none),
        "/v1/operator/sync/publish" => net("mirror publish", &no_flags, &none),
        "/v1/operator/sync/unpublish" => net("mirror unpublish", &no_flags, &none),
        "/v1/operator/route/declare" => access(
            "route",
            &flags(parsed, &["resource", "item", "field", "reason"]),
            &["declare".to_string()],
        ),
        "/v1/operator/route/withdraw" => access(
            "route",
            &flags(parsed, &["resource", "reason"]),
            &["withdraw".to_string()],
        ),
        _ => bail!("unknown operator route: {path}"),
    }
}

/// The backend leaf a route under a grouped object names: the path below
/// `/v1/operator/` with its separators read as spaces, so
/// `/v1/operator/emergency/grant` calls `emergency grant`.
fn leaf(path: &str) -> String {
    path.trim_start_matches("/v1/operator/").replace('/', " ")
}
