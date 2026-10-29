// Which sites a login is for. A login states them in its `context`: a
// `domains` list and a single `domain`, which `sites --set` and `login new`
// write. A login imported from a browser or another password manager states
// instead the addresses it was saved under, in `url` and `urls`; their hosts
// are its sites until `sites --set` writes a list, which then decides. The
// browser host, `login list`, `find` and `sites` read them through these
// functions, so a site fills exactly the logins the owner sees listed for it.

use serde_json::Value;

/// The context member that holds what a person calls an item. The import
/// writes it for every row it brings in, and `login new` for a login it
/// creates; every reader takes the name from here.
pub const DISPLAY_NAME: &str = "display_name";

/// What a person calls the item whose context this is, when it says.
pub fn display_name(context: &Value) -> Option<&str> {
    context.get(DISPLAY_NAME).and_then(Value::as_str)
}

/// The context member that holds an item's free-text notes: where the import
/// puts the notes a source export carried and where `notes --set` writes.
pub const NOTES: &str = "notes";

/// The notes the item whose context this is carries, when it carries any.
pub fn notes(context: &Value) -> Option<&str> {
    context.get(NOTES).and_then(Value::as_str)
}

/// The context member that holds the site's password rules, in the Password
/// Rules language: where `password rules --set` writes and `generate
/// --rules-of` reads.
pub const PASSWORD_RULES: &str = "password_rules";

/// True when `host` is `domain` itself or a subdomain of it; a suffix match
/// alone would let `notexample.com` fill an `example.com` login.
pub fn domain_matches(domain: &str, host: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// The domains a login's context allows it on: its `domains` list and its
/// single `domain` when it states a list; otherwise its `domain` and the
/// hosts of the addresses it was imported with. A context that states none
/// of them allows no domain. Each host is named once.
pub fn item_domains(context: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |host: String| {
        if !host.is_empty() && !out.contains(&host) {
            out.push(host);
        }
    };
    let stated = context.get("domains").and_then(Value::as_array);
    for row in stated.into_iter().flatten().filter_map(Value::as_str) {
        add(row.to_string());
    }
    if let Some(single) = context.get("domain").and_then(Value::as_str) {
        add(single.to_string());
    }
    if stated.is_none() {
        for address in context
            .get("url")
            .into_iter()
            .chain(context.get("urls"))
            .flat_map(addresses)
        {
            add(site_host(&address));
        }
    }
    out
}

/// The addresses an item states (`url`, `urls`) that send its credentials
/// without TLS: anything typed there travels in clear, so health names them.
pub fn plain_http_addresses(context: &Value) -> Vec<String> {
    context
        .get("url")
        .into_iter()
        .chain(context.get("urls"))
        .flat_map(addresses)
        .filter(|address| address.to_ascii_lowercase().starts_with("http://"))
        .collect()
}

/// The addresses an imported value holds: a text that names a scheme, a list
/// of them, or a list of records whose text members name one (the shapes
/// Bitwarden's `uris` and 1Password's `urls` take). A text without `://` is a
/// label or a note, not an address.
fn addresses(value: &Value) -> Vec<String> {
    let is_address = |text: &&str| text.contains("://");
    match value {
        Value::String(text) => [text.as_str()]
            .into_iter()
            .filter(is_address)
            .map(str::to_string)
            .collect(),
        Value::Array(rows) => rows.iter().flat_map(addresses).collect(),
        Value::Object(members) => members
            .values()
            .filter_map(Value::as_str)
            .filter(is_address)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// The host a site is named by, from either a bare host or a whole address:
/// the scheme, any user, port and path are dropped and the rest lowercased,
/// so `https://Login.Example.com/path` names `login.example.com`.
pub fn site_host(site: &str) -> String {
    let after_scheme = match site.split_once("://") {
        Some((_, rest)) => rest,
        None => site,
    };
    let authority = match after_scheme.split_once('/') {
        Some((authority, _)) => authority,
        None => after_scheme,
    };
    let without_user = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let host = match without_user.split_once(':') {
        Some((host, _)) => host,
        None => without_user,
    };
    host.to_lowercase()
}
