// Generating a value nobody has to invent: a password over a chosen
// character set, or a passphrase over the words this host has. Every pick is
// a uniform draw from the kernel's random source.

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Read;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}";
/// Characters one font or one reader takes for another: a value someone has
/// to read off a screen and type is generated without them on request.
const LOOKALIKES: &str = "0O1lI|";

// Small built-in wordlist used when the system dictionary is unavailable.
const BUILTIN_WORDS: &str = "\
apple amber anchor arbor autumn beacon birch bison bramble breeze cedar cinder \
cobalt copper coral cove crimson cyprus dawn delta ember fable falcon fern flint \
garnet glacier granite harbor hazel heron indigo ivory jasper juniper kelp lagoon \
lantern larch maple marble meadow meteor mica onyx opal orchard osprey pebble pine \
quartz quill raven reed ridge river saffron sage slate sparrow spruce summit talon \
thicket tundra umber valley violet walnut willow yarrow zephyr";

/// The decimal digits, read from the ASCII table rather than spelled out.
fn digits() -> impl Iterator<Item = char> {
    (char::MIN..)
        .take_while(char::is_ascii)
        .filter(char::is_ascii_digit)
}

/// Uniform draws from `/dev/urandom`.
struct Entropy(File);

impl Entropy {
    fn open() -> Result<Self> {
        Ok(Self(
            File::open("/dev/urandom").context("open /dev/urandom")?,
        ))
    }

    /// An index below `bound`, every one equally likely. A 64-bit draw below
    /// 2^64 mod `bound` is drawn again, so the draws that remain divide evenly
    /// among the indices and no index is favoured.
    fn below(&mut self, bound: usize) -> Result<usize> {
        let bound = u64::try_from(bound).context("draw range exceeds 64 bits")?;
        if bound == 0 {
            bail!("draw from an empty range");
        }
        let threshold = bound.wrapping_neg() % bound;
        let mut bytes: [u8; std::mem::size_of::<u64>()] = Default::default();
        loop {
            self.0.read_exact(&mut bytes).context("read entropy")?;
            let draw = u64::from_ne_bytes(bytes);
            if draw >= threshold {
                return usize::try_from(draw % bound).context("drawn index exceeds usize");
            }
        }
    }
}

/// The character classes a password draws from, each without the
/// look-alikes when asked. The default is lower+upper+digits (symbols stay
/// opt-in for paste-safety); `symbols_from` names the symbols a site
/// accepts, in place of the built-in set.
fn classes(
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    symbols_from: Option<&str>,
    unambiguous: bool,
) -> Vec<Vec<char>> {
    let symbols = symbols || symbols_from.is_some();
    let any = lower || upper || digits || symbols;
    let mut chosen: Vec<String> = Vec::new();
    if lower || !any {
        chosen.push(LOWER.to_string());
    }
    if upper || !any {
        chosen.push(UPPER.to_string());
    }
    if digits || !any {
        chosen.push(self::digits().collect());
    }
    if symbols {
        chosen.push(match symbols_from {
            Some(set) => set.to_string(),
            None => SYMBOLS.to_string(),
        });
    }
    chosen
        .into_iter()
        .map(|class| {
            class
                .chars()
                .filter(|candidate| !unambiguous || !LOOKALIKES.contains(*candidate))
                .collect()
        })
        .collect()
}

/// A password of `length` characters drawn uniformly from the chosen classes,
/// holding at least one character of every class chosen — what a site's
/// "must contain a digit" rule and the policy's min_character_classes ask.
/// A draw missing a class is drawn again whole, so every password that holds
/// them all stays equally likely. With `unambiguous` the characters in
/// `LOOKALIKES` are left out of the alphabet, so a value read aloud or typed
/// from a screen survives the trip.
pub fn generate_password(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    symbols_from: Option<&str>,
    unambiguous: bool,
) -> Result<String> {
    if length == 0 {
        bail!("password length must be positive");
    }
    if let Some(set) = symbols_from {
        // A symbol set holds symbols: a letter, digit or space there would
        // be a second class wearing the symbols' name.
        if set.is_empty() || set.chars().any(|held| !held.is_ascii_punctuation()) {
            bail!("--symbols-from {set:?} must list ASCII symbols only, such as !#%-_");
        }
    }
    let classes = classes(lower, upper, digits, symbols, symbols_from, unambiguous);
    if length < classes.len() {
        bail!(
            "a password of {length} characters cannot hold one of each of the {} classes chosen; ask for a longer one or fewer classes",
            classes.len()
        );
    }
    let chars: Vec<char> = classes.iter().flatten().copied().collect();
    if chars.is_empty() || classes.iter().any(Vec::is_empty) {
        bail!(
            "a chosen character class is empty once the look-alikes are left out; choose another"
        );
    }
    let mut entropy = Entropy::open()?;
    loop {
        let mut password = String::with_capacity(length);
        while password.chars().count() < length {
            password.push(chars[entropy.below(chars.len())?]);
        }
        if classes
            .iter()
            .all(|class| password.chars().any(|held| class.contains(&held)))
        {
            return Ok(password);
        }
    }
}

// Words available for a passphrase: the system dictionary, or the built-in list
// on a host that has none. A dictionary that exists but cannot be read is
// refused with its path and cause, because drawing from the small built-in
// list instead would give a weaker secret than the caller expects.
fn words() -> Result<Vec<String>> {
    let path = "/usr/share/dict/words";
    let dict = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => bail!("passphrase dictionary {path} cannot be read: {error}"),
    };
    let source = match dict.as_deref() {
        Some(text) => text,
        None => BUILTIN_WORDS,
    };
    Ok(source
        .split_whitespace()
        .map(|w| w.trim().to_lowercase())
        .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
        .collect())
}

/// `count` distinct words of this host's pool, each drawn uniformly from the
/// words not yet drawn, joined by `separator`. With `capitalize` each word
/// starts upper case; with `with_digit` one digit, drawn uniformly, follows
/// the last word, so a site whose rules ask for either accepts the phrase.
pub fn generate_passphrase(
    count: usize,
    separator: &str,
    capitalize: bool,
    with_digit: bool,
) -> Result<String> {
    if count == 0 {
        bail!("passphrase word count must be positive");
    }
    let mut pool = words()?;
    pool.sort_unstable();
    pool.dedup();
    if pool.len() < count {
        bail!(
            "the word pool holds {} distinct words, fewer than the {count} requested",
            pool.len()
        );
    }
    let mut entropy = Entropy::open()?;
    let mut picked = Vec::with_capacity(count);
    while picked.len() < count {
        let index = entropy.below(pool.len())?;
        picked.push(pool.swap_remove(index));
    }
    if capitalize {
        picked = picked.iter().map(|word| capitalized(word)).collect();
    }
    let mut phrase = picked.join(separator);
    if with_digit {
        let pool: Vec<char> = digits().collect();
        phrase.push(pool[entropy.below(pool.len())?]);
    }
    Ok(phrase)
}

/// The word with its first letter upper case.
fn capitalized(word: &str) -> String {
    let mut letters = word.chars();
    match letters.next() {
        Some(first) => first.to_uppercase().chain(letters).collect(),
        None => String::new(),
    }
}
