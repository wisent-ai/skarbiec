// Operator routes of the loopback API: the surface a local operator console —
// the desktop app — reads and drives instead of launching the backend as a
// subprocess for every question it asks.
//
// Trust model: the listener is loopback-only, and every route here carries
// exactly the authority that invoking the backend binary on this machine
// already carries, because the local keyring decides what opens either way.
// What this surface carries is every operation and value that the command
// line offers: the operator console and the local vault CLI cannot drift.
//
// Every handler delegates to the same dispatcher the matching command uses,
// so a console and an operator reading the same vault cannot drift. A request
// names its vault in the body's optional `vault` member; the request-scoped
// override in core applies it for exactly the thread answering here.

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::net::TcpStream;
use std::path::PathBuf;

use crate::core;
use crate::net::http;

pub(crate) const OK_LINE: &str = "HTTP/1.1 200 OK";
const BAD_LINE: &str = "HTTP/1.1 400 Bad Request";
const ROUTE_PREFIX: &str = "/v1/operator/";

/// The mutating operator routes, for the listener's write lock: a read stays
/// parallel, while a read-modify-write on the vault file never interleaves
/// with another writer. Credential calls are all here because a status read
/// can commit or roll back a staged revision.
pub(crate) fn is_mutation(path: &str) -> bool {
    copies::is_package_mutation(path) || copies::is_helper_mutation(path) || matches!(
        path,
        "/v1/operator/vaults/create"
            | "/v1/operator/items/import"
            | "/v1/operator/items/trash"
            | "/v1/operator/items/set-json"
            | "/v1/operator/items/retag"
            | "/v1/operator/items/reclaim"
            | "/v1/operator/items/restore"
            | "/v1/operator/items/generate"
            | "/v1/operator/items/rename"
            | "/v1/operator/browser-host/install"
            | "/v1/operator/browser-host/uninstall"
            | "/v1/operator/browser-host/cover"
            | "/v1/operator/review"
            | "/v1/operator/upgrade/apply"
            | "/v1/operator/agents/enrol"
            | "/v1/operator/recover-daemons"
            | "/v1/operator/items/recovery-codes/take"
            | "/v1/operator/items/recovery-codes/replace"
            | "/v1/operator/items/sites/set"
            | "/v1/operator/items/sites/change"
            | "/v1/operator/items/new-login"
            | "/v1/operator/items/new-ssh-key"
            | "/v1/operator/items/rotate"
            | "/v1/operator/items/totp-set"
            | "/v1/operator/items/totp-uri"
            | "/v1/operator/items/notes/set"
            | "/v1/operator/items/password-rules/change"
            | "/v1/operator/items/attach"
            | "/v1/operator/items/detach"
            | "/v1/operator/items/ssh-import"
            | "/v1/operator/items/purge"
            | "/v1/operator/items/purge-trash"
            | "/v1/operator/items/purge-versions"
            | "/v1/operator/items/merge"
            | "/v1/operator/items/expiry/set"
            | "/v1/operator/items/expiry/clear"
            | "/v1/operator/items/pin/add"
            | "/v1/operator/items/pin/remove"
            | "/v1/operator/items/send"
            | "/v1/operator/items/copy"
            | "/v1/operator/items/share"
            | "/v1/operator/items/revoke"
            | "/v1/operator/shares/expire"
            | "/v1/operator/items/ssh-add"
            | "/v1/operator/recipients/add"
            | "/v1/operator/recipients/remove"
            | "/v1/operator/recipients/rekey"
            | "/v1/operator/owner/rotate"
            | "/v1/operator/owner/key/mint"
            | "/v1/operator/migrate"
            | "/v1/operator/backup"
            | "/v1/operator/backup/check"
            | "/v1/operator/backup/diff"
            | "/v1/operator/ssh-sign"
            | "/v1/operator/backup/restore"
            | "/v1/operator/backup/schedule"
            | "/v1/operator/backup/unschedule"
            | "/v1/operator/alert/set"
            | "/v1/operator/alert/test"
            | "/v1/operator/alert/unset"
            | "/v1/operator/doctor/alert"
            | "/v1/operator/inject"
            | "/v1/operator/env-import"
            | "/v1/operator/git-hook/install"
            | "/v1/operator/git-hook/uninstall"
            | "/v1/operator/ci-secrets"
            | "/v1/operator/ci-secrets/keep"
            | "/v1/operator/ci-secrets/forget"
            | "/v1/operator/git-sign/setup"
            | "/v1/operator/git-sign/unset"
            | "/v1/operator/items/donate"
            | "/v1/operator/bonds/enroll"
            | "/v1/operator/rotation/set"
            | "/v1/operator/rotation/remove"
            | "/v1/operator/rotation/run"
            | "/v1/operator/grants/issue"
            | "/v1/operator/grants/capability"
            | "/v1/operator/grants/ensure"
            | "/v1/operator/grants/narrow"
            | "/v1/operator/grants/keep"
            | "/v1/operator/grants/retarget"
            | "/v1/operator/grants/revoke"
            | "/v1/operator/lockdown"
            | "/v1/operator/donations/accept"
            | "/v1/operator/donations/reject"
            | "/v1/operator/credential"
            | "/v1/operator/emergency/grant"
            | "/v1/operator/emergency/cancel"
            | "/v1/operator/emergency/activate"
            | "/v1/operator/emergency/revoke"
            | "/v1/operator/recovery/drill"
            | "/v1/operator/policy/set"
            | "/v1/operator/policy/unset"
            | "/v1/operator/sync/init"
            | "/v1/operator/sync/push"
            | "/v1/operator/sync/pull"
            | "/v1/operator/sync/publish"
            | "/v1/operator/sync/unpublish"
            | "/v1/operator/route/declare"
            | "/v1/operator/route/withdraw"
    )
}

/// Routes that act on this machine rather than on the vault's content alone:
/// the browser's native-messaging files, the operator's own ssh-agent and an
/// export file live where the app runs, so these are never forwarded to a
/// remote vault owner.
fn is_host_local(path: &str) -> bool {
    copies::is_package_host_local(path) || copies::is_helper_host_local(path) || matches!(
        path,
        "/v1/operator/browser-host"
            | "/v1/operator/browser-host/install"
            | "/v1/operator/browser-host/uninstall"
            | "/v1/operator/browser-host/cover"
            | "/v1/operator/items/ssh-add"
            | "/v1/operator/items/export"
            | "/v1/operator/items/attach"
            | "/v1/operator/items/detach"
            | "/v1/operator/items/ssh-import"
            | "/v1/operator/migrate"
            | "/v1/operator/backup"
            | "/v1/operator/backup/check"
            | "/v1/operator/backup/diff"
            | "/v1/operator/ssh-sign"
            | "/v1/operator/backup/restore"
            | "/v1/operator/backup/schedule"
            | "/v1/operator/backup/unschedule"
            | "/v1/operator/alert/set"
            | "/v1/operator/alert/status"
            | "/v1/operator/alert/test"
            | "/v1/operator/alert/unset"
            | "/v1/operator/doctor/alert"
            | "/v1/operator/inject"
            | "/v1/operator/env-import"
            | "/v1/operator/scan"
            | "/v1/operator/scan-history"
            | "/v1/operator/ci-secrets"
            | "/v1/operator/ci-secrets/keep"
            | "/v1/operator/ci-secrets/kept"
            | "/v1/operator/ci-secrets/forget"
            | "/v1/operator/git-hook/install"
            | "/v1/operator/git-hook/status"
            | "/v1/operator/git-hook/uninstall"
            | "/v1/operator/git-sign/setup"
            | "/v1/operator/git-sign/unset"
            | "/v1/operator/git-sign/status"
            | "/v1/operator/items/donate"
            | "/v1/operator/bonds/enroll"
            // The owner key is made in, and read from, this machine's keyring.
            | "/v1/operator/owner/key/mint"
            | "/v1/operator/owner/key/show"
    )
}

/// Route one operator request; `false` when the path is not an operator
/// route, so the listener falls through to its own table.
pub(crate) fn handle(stream: &mut TcpStream, method: &str, path: &str, body: &str) -> Result<bool> {
    if !path.starts_with(ROUTE_PREFIX) {
        return Ok(false);
    }
    if method != "POST" {
        http::write_response(
            stream,
            BAD_LINE,
            &json!({"error": "operator routes are POST with a JSON body"}),
        )?;
        return Ok(true);
    }
    let Some(parsed) = http::request_json(stream, body)? else {
        return Ok(true);
    };
    let vault = parsed
        .get("vault")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let forwarded = parsed.get(crate::net::owner::FORWARDED).is_some();
    let local = |vault: Option<PathBuf>| {
        let serve = || core::with_vault_override(vault, || answer(path, &parsed));
        if is_mutation(path) {
            http::serialized(serve)
        } else {
            serve()
        }
    };
    let result = if vault.is_none() && !is_host_local(path) {
        crate::net::owner::selected().and_then(|route| match route {
            // A request another host forwarded here named this host as the
            // vault owner; forwarding it again would loop between hosts.
            Some(route) if forwarded => bail!(
                "{path} was forwarded to this host as the vault owner, but this host routes to the owner {route} itself; declare the owner's vault on it instead of secrets.skarbiec.url"
            ),
            Some(route) => crate::net::owner::request(&route, path, &parsed),
            None => local(None),
        })
    } else {
        local(vault)
    };
    match result {
        Ok(value) => http::write_response(stream, OK_LINE, &value)?,
        Err(error) => http::write_response(
            stream,
            BAD_LINE,
            &json!({"error": http::detail_text(&format!("{error:#}"))}),
        )?,
    }
    Ok(true)
}

mod calls;
mod copies;
mod credential;
mod items;
mod owner;
mod reads;
mod replicas;
mod routes;

use routes::answer;
