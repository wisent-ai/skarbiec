// Whether a value a login already holds still clears the password rules the
// login keeps for its site. A site that tightened its rules, or a password
// typed in before the rules were recorded, holds a value the site may refuse
// at the next change or reject outright; `health` names those logins. Each
// rule is read in the Password Rules language as `generate --rules` reads it,
// and every rule the value breaks is named, never the value.

use anyhow::{bail, Result};

/// The rules of `rules` that `value` breaks, each as the rule's own text.
pub(crate) fn broken(rules: &str, value: &str) -> Result<Vec<String>> {
    let length = value.chars().count();
    let mut broken = Vec::new();
    // Every class a required or allowed rule names; when there is one, the
    // value may hold no character outside them.
    let mut permitted: Vec<String> = Vec::new();
    for rule in rules
        .split(';')
        .map(str::trim)
        .filter(|rule| !rule.is_empty())
    {
        let Some((name, stated)) = rule.split_once(':') else {
            bail!("password rule `{rule}` names no value; rules read `name: value; ...`");
        };
        let stated = stated.trim();
        let kept = match name.trim() {
            "minlength" => length >= number(name, stated)?,
            "maxlength" => length <= number(name, stated)?,
            "required" => {
                let classes = classes(stated)?;
                let met = value
                    .chars()
                    .any(|character| classes.iter().any(|class| holds(class, character)));
                permitted.extend(classes);
                met
            }
            "allowed" => {
                permitted.extend(classes(stated)?);
                true
            }
            "max-consecutive" => {
                let limit = number(name, stated)?;
                runs(value).into_iter().all(|run| run <= limit)
            }
            other => bail!("password rule {other} is not one the Password Rules language names"),
        };
        if !kept {
            broken.push(rule.to_string());
        }
    }
    let outside = !permitted.is_empty()
        && value
            .chars()
            .any(|character| !permitted.iter().any(|class| holds(class, character)));
    if outside {
        broken.push(format!("a character outside {}", permitted.join(", ")));
    }
    Ok(broken)
}

fn number(name: &str, value: &str) -> Result<usize> {
    match value.parse::<usize>() {
        Ok(number) => Ok(number),
        Err(cause) => bail!("password rule {name}: {value} is not a whole number ({cause})"),
    }
}

/// The classes one rule lists, each checked to be one the language names.
fn classes(value: &str) -> Result<Vec<String>> {
    let mut named = Vec::new();
    for class in value.split(',').map(str::trim) {
        let known = matches!(
            class,
            "lower" | "upper" | "digit" | "special" | "ascii-printable" | "unicode"
        ) || (class.starts_with('[') && class.ends_with(']'));
        if !known {
            bail!("password rule class {class} is not lower, upper, digit, special, ascii-printable, unicode or a [set]");
        }
        named.push(class.to_string());
    }
    Ok(named)
}

/// Whether one character belongs to one class of the language. Its special
/// class is the ASCII punctuation and the space.
fn holds(class: &str, character: char) -> bool {
    match class {
        "lower" => character.is_ascii_lowercase(),
        "upper" => character.is_ascii_uppercase(),
        "digit" => character.is_ascii_digit(),
        "special" => character.is_ascii_punctuation() || character == ' ',
        "ascii-printable" => character.is_ascii_graphic() || character == ' ',
        "unicode" => true,
        set => set
            .trim_start_matches('[')
            .trim_end_matches(']')
            .contains(character),
    }
}

/// The length of every run of one character repeated, in order.
fn runs(value: &str) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut run: Vec<char> = Vec::new();
    for character in value.chars() {
        if run.last().is_some_and(|last| *last != character) {
            lengths.push(run.len());
            run.clear();
        }
        run.push(character);
    }
    lengths.push(run.len());
    lengths
}
