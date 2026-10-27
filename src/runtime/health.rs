// Secret health across the whole vault: which live items hold the same value
// in one field as another item, and which fall short of the administrative
// length rule. `duplicates` compares whole payloads; one password reused by a
// login and a host account differs everywhere else and passes it. This reads
// each live item holding the field, compares digests in memory, and reports
// item ids only: no value, digest or length leaves the process.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

use crate::core::{crypto, schema, vault::Vault, vault_path};

/// The field compared when `--field` names none, as the usage line declares.
const DECLARED_FIELD: &str = "password";

pub fn dispatch(
    command: &str,
    flags: &HashMap<String, String>,
    _positionals: &[String],
) -> Result<Option<Value>> {
    match command {
        "health" => report(flags).map(Some),
        _ => Ok(None),
    }
}

/// One pass over every live item.
///
/// An item that will not open is named with its error rather than skipped,
/// because a report that leaves it out reads as "no problem there". An item
/// without the field, or with it empty or not text, is not a holder and is
/// not counted.
fn report(flags: &HashMap<String, String>) -> Result<Value> {
    let field = match flags.get("field") {
        Some(field) => field.as_str(),
        None => DECLARED_FIELD,
    };
    // `--breached` also asks the Have I Been Pwned range API about every
    // distinct value, once per value however many items hold it; only the
    // SHA-1 prefix leaves the host, as `breach check` does for one item.
    let check_breaches = crate::cli::args::flag_set(flags, "breached");
    let vault = Vault::open(vault_path())?;
    let policy = vault.doc().get("policy");
    let minimum = policy
        .and_then(|policy| policy.get("min_generated_length"))
        .and_then(Value::as_u64);
    let mut holders: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    let mut checked = Vec::new();
    let mut short = Vec::new();
    // Every policy rule a held value fails, decided as `policy check`
    // decides a candidate: the length rule and every other one.
    let mut below_policy = Vec::new();
    let mut unreadable = Vec::new();
    // Items whose stated address sends what is typed there without TLS.
    let mut insecure_addresses = Vec::new();
    // Logins naming one site and one username: the same account kept twice,
    // where only one copy is current and autofill offers both.
    let mut accounts: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    // Logins whose value breaks the password rules they keep for their site,
    // with the rules broken: the site may refuse it at the next change.
    let mut breaks_site_rules = Vec::new();
    for entry in vault.list(false) {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        if entry.get("state").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let payload = match vault.get_item(id) {
            Ok(payload) => payload,
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        let fields = match schema::fields(&payload) {
            Ok(fields) => fields,
            Err(error) => {
                unreadable.push(json!({"item": id, "error": format!("{error:#}")}));
                continue;
            }
        };
        if let Some(context) = payload.get("context") {
            let plain = crate::core::items::plain_http_addresses(context);
            if !plain.is_empty() {
                insecure_addresses.push(json!({"item": id, "addresses": plain}));
            }
        }
        if let (Some(context), Some(username)) =
            (payload.get("context"), fields.get("username").and_then(Value::as_str))
        {
            if !username.is_empty() {
                for site in crate::core::items::item_domains(context) {
                    accounts.entry((site, username.to_lowercase())).or_default().push(id.to_string());
                }
            }
        }
        let Some(text) = fields.get(field).and_then(Value::as_str) else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        checked.push(id.to_string());
        let digest = crypto::sha256_hex(text)?;
        if check_breaches {
            values.entry(digest.clone()).or_insert_with(|| text.to_string());
        }
        holders.entry(digest).or_default().push(id.to_string());
        let kept_rules = payload
            .get("context")
            .and_then(|context| context.get(crate::core::items::PASSWORD_RULES))
            .and_then(Value::as_str)
            .filter(|rules| !rules.trim().is_empty());
        if let Some(rules) = kept_rules {
            match crate::cli::generate::rules_broken(rules, text) {
                Ok(broken) if broken.is_empty() => {}
                Ok(broken) => breaks_site_rules.push(json!({"item": id, "broken": broken})),
                Err(error) => unreadable.push(json!({"item": id, "error": format!("its password rules: {error:#}")})),
            }
        }
        let verdict = crate::access::policy::decide(policy, text);
        if verdict["ok"] != json!(true) {
            let failed: Vec<&Value> = verdict["rules"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|rule| rule["ok"] != json!(true))
                .filter_map(|rule| rule.get("key"))
                .collect();
            if failed.iter().any(|key| key.as_str() == Some("min_generated_length")) {
                short.push(id.to_string());
            }
            below_policy.push(json!({"item": id, "failed": failed}));
        }
    }
    // A value seen in a breach corpus is breached in every item that holds
    // it; one the API could not be asked about is named with curl's reason
    // rather than counted as clean.
    let mut breached = Vec::new();
    let mut not_checked = Vec::new();
    for (digest, value) in &values {
        let Some(ids) = holders.get(digest) else {
            continue;
        };
        match crate::runtime::breach::lookup(value)? {
            crate::runtime::breach::Lookup::Answered(Some(seen)) => {
                breached.push(json!({"items": ids, "seen_count": seen}));
            }
            crate::runtime::breach::Lookup::Answered(None) => {}
            crate::runtime::breach::Lookup::Unreachable(detail) => {
                not_checked.push(json!({"items": ids, "detail": detail}));
            }
        }
    }
    // `--saved-versions` opens every saved version too and names each
    // value in use now that some item once gave up.
    let saved_versions = crate::cli::args::flag_set(flags, "saved-versions");
    let (reused_retired, retired_unreadable) = match saved_versions {
        true => crate::runtime::retired::reused(&vault, field, &holders)?,
        false => (Vec::new(), Vec::new()),
    };
    // A digest held by more than one item is one secret in several places:
    // a leak through any of them is a leak of all.
    let reused: Vec<Vec<String>> = holders
        .into_values()
        .filter(|ids| !matches!(ids.as_slice(), [] | [_]))
        .collect();
    // One site and username held by more than one item. The username stays
    // out of the answer, as every value does; the items and the site say it.
    let same_account: Vec<Value> = accounts
        .into_iter()
        .filter(|(_, ids)| !matches!(ids.as_slice(), [] | [_]))
        .map(|((site, _), items)| json!({"site": site, "items": items}))
        .collect();
    crate::runtime::audit::append(
        "health",
        &json!({
            "field": field,
            "checked": checked.len(),
            "reused_groups": reused.len(),
            "short": short.len(),
            "unreadable": unreadable.len(),
            "breach_checked": check_breaches,
            "breached_groups": breached.len(),
        }),
    )?;
    Ok(json!({
        "ok": reused.is_empty()
            && short.is_empty()
            && below_policy.is_empty()
            && unreadable.is_empty()
            && breached.is_empty()
            && not_checked.is_empty()
            && insecure_addresses.is_empty()
            && same_account.is_empty()
            && breaks_site_rules.is_empty()
            && reused_retired.is_empty()
            && retired_unreadable.is_empty(),
        "field": field,
        "checked": checked.len(),
        "reused": reused,
        "min_generated_length": minimum,
        "short": short,
        "below_policy": below_policy,
        "unreadable": unreadable,
        "breach_checked": check_breaches,
        "breached": breached,
        "breach_not_checked": not_checked,
        "insecure_addresses": insecure_addresses,
        "same_account": same_account,
        "breaks_site_rules": breaks_site_rules,
        "saved_versions_checked": saved_versions,
        "reused_retired": reused_retired,
        "saved_versions_unreadable": retired_unreadable,
    }))
}
