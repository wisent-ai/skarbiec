// A site's password rules in the Password Rules language Apple's
// passwordrules attribute and its Password Manager Resources use
// (https://developer.apple.com/password-rules/): rules such as minlength,
// maxlength, required and allowed, separated by semicolons. `generate --rules
// '<rules>'`, or `--rules-of <id>` reading the rules a login keeps under its
// context's `password_rules`, turns them into the generator's own options, so
// a site that refuses some symbols or caps the length gets a value it
// accepts. Nothing is assumed: rules that state no length are refused naming
// the missing rule. The rule and class names below are the language's own.

use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::cli::args::Usage;

/// The generator options the rules ask for, merged over the caller's own.
pub(super) fn options(rules: &str, mut flags: HashMap<String, String>) -> Result<HashMap<String, String>> {
    let mut lengths: (Option<usize>, Option<usize>) = (None, None);
    let mut symbols = String::new();
    for rule in rules.split(';').map(str::trim).filter(|rule| !rule.is_empty()) {
        let Some((name, value)) = rule.split_once(':') else {
            return Err(Usage(format!("password rule `{rule}` names no value; rules read `name: value; ...`")).into());
        };
        let value = value.trim();
        match name.trim() {
            "minlength" => lengths.0 = Some(number(name, value)?),
            "maxlength" => lengths.1 = Some(number(name, value)?),
            // A class the site requires is one the value draws from.
            "required" => classes(value, &mut flags, &mut symbols)?,
            // A class the site allows is drawn from too: the generator puts
            // one of every class it draws from in the value.
            "allowed" => classes(value, &mut flags, &mut symbols)?,
            // A limit on repeated characters is the site's to enforce; a
            // random value rarely repeats, and the policy check still runs.
            "max-consecutive" => {}
            other => bail!("password rule {other} is not one the Password Rules language names"),
        }
    }
    let length = match lengths {
        (_, Some(max)) => max,
        (Some(min), None) => min,
        (None, None) => {
            return Err(Usage(
                "the password rules state neither minlength nor maxlength, so no length can be taken from them; add one, or pass --length"
                    .to_string(),
            )
            .into())
        }
    };
    if flags.get("length").is_none() {
        flags.insert("length".to_string(), length.to_string());
    }
    if !symbols.is_empty() {
        flags.insert("symbols-from".to_string(), symbols);
    }
    Ok(flags)
}

fn number(name: &str, value: &str) -> Result<usize> {
    match value.parse::<usize>() {
        Ok(number) => Ok(number),
        Err(cause) => Err(Usage(format!("password rule {name}: {value} is not a whole number ({cause})")).into()),
    }
}

fn on(flags: &mut HashMap<String, String>, name: &str) {
    flags.insert(name.to_string(), "true".to_string());
}

/// Every class one required or allowed rule names, as generator options.
fn classes(value: &str, flags: &mut HashMap<String, String>, symbols: &mut String) -> Result<()> {
    for class in value.split(',').map(str::trim) {
        match class {
            "lower" => on(flags, "lower"),
            "upper" => on(flags, "upper"),
            "digit" => on(flags, "digits"),
            "special" => on(flags, "symbols"),
            "ascii-printable" => every_class(flags),
            "unicode" => every_class(flags),
            set if set.starts_with('[') && set.ends_with(']') => characters(set, flags, symbols),
            other => bail!("password rule class {other} is not lower, upper, digit, special, ascii-printable, unicode or a [set]"),
        }
    }
    Ok(())
}

fn every_class(flags: &mut HashMap<String, String>) {
    on(flags, "lower");
    on(flags, "upper");
    on(flags, "digits");
    on(flags, "symbols");
}

/// A bracketed set: its letters and digits turn their classes on, and every
/// other character joins the symbols the value may use.
fn characters(set: &str, flags: &mut HashMap<String, String>, symbols: &mut String) {
    for character in set.trim_start_matches('[').trim_end_matches(']').chars() {
        if character.is_ascii_lowercase() {
            on(flags, "lower");
        } else if character.is_ascii_uppercase() {
            on(flags, "upper");
        } else if character.is_ascii_digit() {
            on(flags, "digits");
        } else if !symbols.contains(character) {
            symbols.push(character);
        }
    }
}
