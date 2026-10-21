// Generating a value nobody has to invent: a password over a chosen
// character set, or a passphrase over the words this host has. Every pick is
// a uniform draw from the kernel's random source.

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Read;
use std::num::{NonZeroU64, NonZeroUsize};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}";

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
        let bound = NonZeroU64::new(u64::try_from(bound).context("draw range exceeds 64 bits")?)
            .context("draw from an empty range")?;
        let threshold = bound.get().wrapping_neg() % bound;
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
        set.extend(self::digits());
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
    if NonZeroUsize::new(length).is_none() {
        bail!("password length must be positive");
    }
    let chars: Vec<char> = charset(lower, upper, digits, symbols).chars().collect();
    if chars.is_empty() {
        bail!("empty character set");
    }
    let mut entropy = Entropy::open()?;
    let mut password = String::with_capacity(length);
    while password.chars().count() < length {
        password.push(chars[entropy.below(chars.len())?]);
    }
    Ok(password)
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
/// words not yet drawn, joined by `separator`.
pub fn generate_passphrase(count: usize, separator: &str) -> Result<String> {
    if NonZeroUsize::new(count).is_none() {
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
    Ok(picked.join(separator))
}
