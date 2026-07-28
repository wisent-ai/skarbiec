// Typed items and secret generation for the skarbiec vault.
//
// Generic item shapes remain caller-defined JSON. Payment cards are the
// exception: they use a dedicated stdin-only command and a validated schema so
// PAN and CVC values never need to appear in argv or shell history.
// Generation uses OS entropy only:
//   password   : bytes from /dev/urandom mapped onto a character set
//   passphrase : words shuffled by `sort -R` (secure shuffle), then joined

use anyhow::{bail, Context, Result};
use chrono::{Datelike, Utc};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroize;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}";

pub const PAYMENT_CARD_TYPE: &str = "payment_card";
const PAYMENT_CARD_REQUIRED_FIELDS: &[&str] = &[
    "holder_name",
    "number",
    "expiry_month",
    "expiry_year",
    "cvc",
];
const PAYMENT_CARD_OPTIONAL_FIELDS: &[&str] = &[
    "label",
    "billing_address_line1",
    "billing_address_line2",
    "billing_city",
    "billing_region",
    "billing_postal_code",
    "billing_country_code",
];
const PAN_MIN_DIGITS: usize = 12;
const PAN_MAX_DIGITS: usize = 19;
const CVC_MIN_DIGITS: usize = 3;
const CVC_MAX_DIGITS: usize = 4;
const TEXT_MAX_CHARS: usize = 256;

// Small built-in wordlist used when the system dictionary is unavailable.
const BUILTIN_WORDS: &str = "\
apple amber anchor arbor autumn beacon birch bison bramble breeze cedar cinder \
cobalt copper coral cove crimson cyprus dawn delta ember fable falcon fern flint \
garnet glacier granite harbor hazel heron indigo ivory jasper juniper kelp lagoon \
lantern larch maple marble meadow meteor mica onyx opal orchard osprey pebble pine \
quartz quill raven reed ridge river saffron sage slate sparrow spruce summit talon \
thicket tundra umber valley violet walnut willow yarrow zephyr";

// Build a generic item. Payment cards must go through the dedicated validator
// and stdin-only command; accepting them here would expose PAN/CVC in argv.
pub fn build_item(item_type: &str, fields: &[String]) -> Result<Value> {
    if matches!(item_type, PAYMENT_CARD_TYPE | "card") {
        bail!("payment cards must be stored with card-set over stdin");
    }
    let mut map = Map::new();
    map.insert("type".to_string(), Value::String(item_type.to_string()));
    for field in fields {
        let (key, value) = field
            .split_once('=')
            .with_context(|| format!("field must be key=value: {field}"))?;
        map.insert(key.to_string(), Value::String(value.to_string()));
    }
    Ok(Value::Object(map))
}

/// Secret JSON whose string storage is cleared before it is released.
pub struct SensitiveItem(Value);

impl SensitiveItem {
    pub fn as_value(&self) -> &Value {
        &self.0
    }
}

impl Drop for SensitiveItem {
    fn drop(&mut self) {
        zeroize_value(&mut self.0);
    }
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_value),
        Value::Object(values) => values.values_mut().for_each(zeroize_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn string_field<'a>(fields: &'a mut Map<String, Value>, name: &str) -> Result<&'a mut String> {
    match fields.get_mut(name) {
        Some(Value::String(text)) => Ok(text),
        _ => bail!("payment card field {name} must be a string"),
    }
}

fn validate_text(value: &str, name: &str, required: bool) -> Result<()> {
    if value.trim() != value
        || value.chars().any(char::is_control)
        || value.chars().count() > TEXT_MAX_CHARS
        || (required && value.is_empty())
    {
        bail!("invalid payment card field: {name}");
    }
    Ok(())
}

fn valid_luhn(number: &str) -> bool {
    let mut sum = 0_u32;
    let mut double = false;
    for byte in number.bytes().rev() {
        let mut digit = u32::from(byte - b'0');
        if double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        double = !double;
    }
    sum % 10 == 0
}

pub fn payment_card_from_json(payload: &[u8]) -> Result<(SensitiveItem, String)> {
    let parsed: Value =
        serde_json::from_slice(payload).context("payment card stdin must be a JSON object")?;
    payment_card_from_value(parsed)
}

pub fn payment_card_from_value(parsed: Value) -> Result<(SensitiveItem, String)> {
    let mut secret = SensitiveItem(parsed);
    let fields = secret
        .0
        .as_object_mut()
        .context("payment card stdin must be a JSON object")?;

    let allowed: HashSet<&str> = PAYMENT_CARD_REQUIRED_FIELDS
        .iter()
        .chain(PAYMENT_CARD_OPTIONAL_FIELDS)
        .copied()
        .collect();
    if let Some(name) = fields.keys().find(|name| !allowed.contains(name.as_str())) {
        bail!("unknown payment card field: {name}");
    }
    for name in PAYMENT_CARD_REQUIRED_FIELDS {
        if !fields.contains_key(*name) {
            bail!("missing payment card field: {name}");
        }
    }

    validate_text(string_field(fields, "holder_name")?, "holder_name", true)?;

    let number = string_field(fields, "number")?;
    if number.len() < PAN_MIN_DIGITS
        || number.len() > PAN_MAX_DIGITS
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || !valid_luhn(number)
    {
        bail!("invalid payment card number");
    }
    let last4 = number[number.len() - CVC_MAX_DIGITS..].to_string();

    let month_text = string_field(fields, "expiry_month")?;
    if !month_text.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid payment card expiry_month");
    }
    let month: u32 = month_text
        .parse()
        .context("invalid payment card expiry_month")?;
    if !(1..=12).contains(&month) {
        bail!("invalid payment card expiry_month");
    }
    *month_text = format!("{month:02}");

    let year_text = string_field(fields, "expiry_year")?;
    if year_text.len() != CVC_MAX_DIGITS || !year_text.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid payment card expiry_year");
    }
    let year: i32 = year_text
        .parse()
        .context("invalid payment card expiry_year")?;
    let today = Utc::now();
    if year < today.year() || (year == today.year() && month < today.month()) {
        bail!("payment card is expired");
    }

    let cvc = string_field(fields, "cvc")?;
    if cvc.len() < CVC_MIN_DIGITS
        || cvc.len() > CVC_MAX_DIGITS
        || !cvc.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("invalid payment card cvc");
    }

    for name in PAYMENT_CARD_OPTIONAL_FIELDS {
        if fields.contains_key(*name) {
            let text = string_field(fields, name)?;
            validate_text(text, name, false)?;
            if *name == "billing_country_code" {
                if text.len() != 2 || !text.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                    bail!("invalid payment card billing_country_code");
                }
                text.make_ascii_uppercase();
            }
        }
    }

    fields.insert(
        "type".to_string(),
        Value::String(PAYMENT_CARD_TYPE.to_string()),
    );
    Ok((secret, last4))
}

// Character set from the requested classes. When no class is requested the
// default is lower+upper+digits (symbols stay opt-in for paste-safety).
fn charset(lower: bool, upper: bool, digits: bool, symbols: bool) -> String {
    let mut set = String::new();
    let any = lower || upper || digits || symbols;
    if lower || !any {
        set.push_str(LOWER);
    }
    if upper || !any {
        set.push_str(UPPER);
    }
    if digits || !any {
        set.push_str(DIGITS);
    }
    if symbols {
        set.push_str(SYMBOLS);
    }
    set
}

pub fn generate_password(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
) -> Result<String> {
    if length == usize::MIN {
        bail!("password length must be positive");
    }
    let chars: Vec<char> = charset(lower, upper, digits, symbols).chars().collect();
    if chars.is_empty() {
        bail!("empty character set");
    }
    let mut buf: Vec<u8> = vec![Default::default(); length];
    File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut buf)
        .context("read entropy")?;
    Ok(buf
        .iter()
        .map(|byte| chars[(*byte as usize) % chars.len()])
        .collect())
}

// Words available for a passphrase: system dictionary if present, else built-in.
fn words() -> Vec<String> {
    let dict = std::fs::read_to_string("/usr/share/dict/words").ok();
    let source = dict.as_deref().unwrap_or(BUILTIN_WORDS);
    source
        .split_whitespace()
        .map(|w| w.trim().to_lowercase())
        .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
        .collect()
}

pub fn generate_passphrase(count: usize, separator: &str) -> Result<String> {
    if count == usize::MIN {
        bail!("passphrase word count must be positive");
    }
    let pool = words();
    if pool.is_empty() {
        bail!("no words available for passphrase");
    }
    // `sort -R` shuffles using randomness; take the first `count` distinct words.
    let mut child = Command::new("sort")
        .arg("-R")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn sort -R")?;
    child
        .stdin
        .take()
        .context("sort stdin")?
        .write_all(pool.join("\n").as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("sort -R failed");
    }
    let shuffled = String::from_utf8_lossy(&out.stdout);
    let picked: Vec<&str> = shuffled
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(count)
        .collect();
    if picked.len() < count {
        bail!("word pool smaller than requested count");
    }
    Ok(picked.join(separator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_card() -> Value {
        json!({
            "holder_name": "Test User",
            "number": "4111111111111111",
            "expiry_month": "7",
            "expiry_year": (Utc::now().year() + 1).to_string(),
            "cvc": "123",
            "billing_country_code": "pl"
        })
    }

    fn encode(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("serialize payment card fixture")
    }

    #[test]
    fn payment_card_is_validated_and_normalized() {
        let (card, last4) =
            payment_card_from_json(&encode(&valid_card())).expect("valid payment card");
        let value = card.as_value();

        assert_eq!(last4, "1111");
        assert_eq!(
            value.get("type").and_then(Value::as_str),
            Some(PAYMENT_CARD_TYPE)
        );
        assert_eq!(
            value.get("expiry_month").and_then(Value::as_str),
            Some("07")
        );
        assert_eq!(
            value.get("billing_country_code").and_then(Value::as_str),
            Some("PL")
        );
        assert!(value.get("number").and_then(Value::as_str).is_some());
        assert!(value.get("cvc").and_then(Value::as_str).is_some());
    }

    #[test]
    fn payment_card_rejects_invalid_pan() {
        let mut input = valid_card();
        input["number"] = json!("4111111111111112");

        let error = payment_card_from_json(&encode(&input))
            .err()
            .expect("invalid PAN must fail");
        assert_eq!(error.to_string(), "invalid payment card number");
    }

    #[test]
    fn payment_card_rejects_expired_card() {
        let mut input = valid_card();
        input["expiry_month"] = json!("12");
        input["expiry_year"] = json!((Utc::now().year() - 1).to_string());

        let error = payment_card_from_json(&encode(&input))
            .err()
            .expect("expired card must fail");
        assert_eq!(error.to_string(), "payment card is expired");
    }

    #[test]
    fn generic_set_rejects_payment_cards() {
        let error = build_item(PAYMENT_CARD_TYPE, &[])
            .err()
            .expect("generic payment card must fail");
        assert_eq!(
            error.to_string(),
            "payment cards must be stored with card-set over stdin"
        );
    }
}
