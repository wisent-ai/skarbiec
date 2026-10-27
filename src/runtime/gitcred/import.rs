// `helper import git <id> <host> [--username <name>] [--tags <tag,...>]`:
// move the password or token git's `store` helper left in plain text — one
// https://user:password@host line in ~/.git-credentials, or in
// $XDG_CONFIG_HOME/git/credentials — into a new login offered on the host,
// make git ask this vault for the host (`setup`), and only then take the line
// out of the file. When setup is refused, the file keeps the line and the
// item holds a copy, both named in the refusal.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;

const SCHEME: &str = "https://";

/// The files git's store helper reads, in the order git reads them.
fn store_files() -> Result<Vec<PathBuf>> {
    let home = crate::core::env::path("HOME").context("HOME names no directory where git keeps ~/.git-credentials")?;
    let config = match crate::core::env::path("XDG_CONFIG_HOME") {
        Some(dir) => dir,
        None => home.join(".config"),
    };
    Ok(vec![home.join(".git-credentials"), config.join("git").join("credentials")])
}

/// One stored sign-in: the line it is on, and its username and password.
struct Stored {
    file: PathBuf,
    line: String,
    username: String,
    password: String,
}

fn decode(text: &str, what: &str, line: &str) -> Result<String> {
    percent_encoding::percent_decode_str(text)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .with_context(|| format!("the {what} on `{}` is not text once decoded", redacted(line)))
}

/// A stored line with its password left out, for a refusal to name.
fn redacted(line: &str) -> String {
    let parts = line.strip_prefix(SCHEME).and_then(|rest| rest.rsplit_once('@'));
    match parts.and_then(|(user, host)| user.split_once(':').map(|(name, _)| (name, host))) {
        Some((name, host)) => format!("{SCHEME}{name}:…@{host}"),
        None => "a line that is not https://user:password@host".to_string(),
    }
}

/// Every sign-in git's store keeps for `host` over https.
fn stored_for(host: &str) -> Result<Vec<Stored>> {
    let mut found = Vec::new();
    for file in store_files()? {
        let Some(text) = crate::core::read_present(&file, "git's credential store")? else { continue };
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix(SCHEME) else { continue };
            let Some((user, place)) = rest.rsplit_once('@') else { continue };
            let named = place.split('/').next().context("a stored line names no host")?;
            if named != host {
                continue;
            }
            let (username, password) = user.split_once(':').with_context(|| format!("{} holds `{}` with no password", file.display(), redacted(line)))?;
            found.push(Stored {
                file: file.clone(),
                line: line.to_string(),
                username: decode(username, "username", line)?,
                password: decode(password, "password", line)?,
            });
        }
    }
    Ok(found)
}

/// The hosts git's store helper keeps a plain-text https sign-in for, each
/// with the file holding it, so doctor can name those still left beside a
/// host git asks this vault for.
pub(crate) fn stored_hosts() -> Result<Vec<(PathBuf, String)>> {
    let mut hosts = Vec::new();
    for file in store_files()? {
        let Some(text) = crate::core::read_present(&file, "git's credential store")? else { continue };
        for line in text.lines() {
            let Some(place) = line.trim().strip_prefix(SCHEME).and_then(|rest| rest.rsplit_once('@')).map(|(_, place)| place) else { continue };
            let Some(host) = place.split('/').next() else { continue };
            hosts.push((file.clone(), host.to_string()));
        }
    }
    Ok(hosts)
}

pub(super) fn import(id: &str, host: &str, username: Option<&String>, tags: Option<&String>) -> Result<Value> {
    let host = super::config::checked(host)?;
    let mut found: Vec<Stored> = stored_for(host)?
        .into_iter()
        .filter(|stored| username.is_none_or(|wanted| &stored.username == wanted))
        .collect();
    if found.len() > std::iter::once(()).count() {
        let names: Vec<&str> = found.iter().map(|stored| stored.username.as_str()).collect();
        bail!("git's credential store keeps {} sign-ins for {host}, as {}; name one with --username", names.len(), names.join(", "));
    }
    let Some(stored) = found.pop() else {
        bail!(
            "git's credential store keeps no https sign-in for {host}{}; nothing was changed",
            match username {
                Some(wanted) => format!(" as {wanted}"),
                None => String::new(),
            }
        );
    };

    let mut fields = Map::new();
    fields.insert("username".to_string(), json!(stored.username));
    fields.insert("password".to_string(), json!(stored.password));
    let mut context = Map::new();
    context.insert("domains".to_string(), json!([host]));
    context.insert(crate::core::items::DISPLAY_NAME.to_string(), json!(format!("git over https to {host}")));
    let payload = crate::core::schema::payload("login", fields, context)?;
    let mut write = HashMap::from([("type".to_string(), "login".to_string())]);
    if let Some(tags) = tags {
        write.insert("tags".to_string(), tags.clone());
    }
    crate::cli::items::create_value(&write, id, &payload.to_string(), "helper import git")?;
    let read_back = crate::core::vault::Vault::open(crate::core::vault_path())?.get_item(id)?;
    if read_back["fields"]["password"] != json!(stored.password) {
        bail!("{id} does not read back {host}'s password; {} was left as it was", stored.file.display());
    }

    let set = super::config::setup(host)
        .with_context(|| format!("{} still keeps {host}'s sign-in, and {id} holds a copy of it", stored.file.display()))?;
    let text = std::fs::read_to_string(&stored.file).with_context(|| format!("read {} again", stored.file.display()))?;
    let kept: Vec<&str> = text.lines().filter(|line| *line != stored.line).collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    crate::core::vault::atomic_write(&stored.file, out.as_bytes()).with_context(|| {
        format!("git asks this vault for {host} now, but its sign-in is still in {}; remove that line", stored.file.display())
    })?;
    crate::runtime::audit::append("git-credential-import", &json!({"item": id, "host": host, "file": stored.file}))?;
    Ok(json!({
        "ok": true,
        "item": id,
        "host": host,
        "username": stored.username,
        "file": stored.file,
        "setting": set["setting"],
    }))
}
