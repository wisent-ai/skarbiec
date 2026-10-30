//! The keys a vault is sealed to and opened with, in one owner-only file
//! beside the vault: every recipient's public key, and the secret halves
//! this host holds. Skarbiec reads and writes it itself; no keyring daemon
//! stands between a request and its key.
//!
//! The file is JSON (`format` [`FORMAT`]): each key is its OpenPGP public
//! key packets (base64), so the fingerprint every vault records stays the
//! key's name, and, when this host holds it, its secret half: the Ed25519
//! seed that signs and the X25519 scalar that opens. With an unlock phrase
//! configured (`SKARBIEC_UNLOCK`, `SKARBIEC_UNLOCK_FILE`, or the default
//! unlock file) each secret half is written sealed under it; without one it
//! is written as it is, and the file's owner-only mode is its protection.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::{json, Map, Value};
use std::fs::OpenOptions;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use skarbiec_crypto::chacha;
use skarbiec_crypto::openpgp::armor::{base64_decode, base64_encode};
use skarbiec_crypto::openpgp::keys::{parse_public_keys, PublicKey};
use skarbiec_crypto::openpgp::{hex_upper, packets};
use skarbiec_crypto::sha::Sha256;
use skarbiec_crypto::wipe::Secret;

/// What the key file states it is; a file stating anything else is refused.
pub(crate) const FORMAT: &str = "skarbiec-keys-1";

/// The iteration count a secret half is sealed under: the highest RFC 4880
/// section 3.7.1.3 can state (coded count 255), the count `send` seals with.
const UNLOCK_COUNT: u64 = 65_011_712;
/// Bytes of salt for the unlock key derivation (RFC 4880's S2K salt).
const UNLOCK_SALT_BYTES: usize = 8;
/// What the sealed secret half is bound to, beside its key's fingerprint.
const SECRET_CONTEXT: &[u8] = b"skarbiec-keys-1 secret";

/// The key file Skarbiec reads for the vault `vault`: `SKARBIEC_KEYS_FILE`
/// when it names one, otherwise `<vault without .json>.keys.json` in the
/// vault's own directory, so each vault on a host has its own keys and a
/// copy of the vault file alone carries none.
pub(crate) fn path_for(vault: &Path) -> PathBuf {
    if let Some(configured) = crate::core::env::path("SKARBIEC_KEYS_FILE") {
        return configured;
    }
    vault.with_extension("keys.json")
}

/// The key file of the vault this process works on.
pub(crate) fn path() -> PathBuf {
    path_for(&crate::core::vault_path())
}

/// A secret half as this process holds it once unlocked.
pub(crate) struct SecretHalf {
    pub seed: Secret,
    pub scalar: Secret,
}

/// A secret half as the file holds it.
enum Stored {
    Clear(SecretHalf),
    Sealed {
        salt: Vec<u8>,
        count: u64,
        nonce: [u8; 12],
        data: Vec<u8>,
    },
}

pub(crate) struct Key {
    /// The public key packets, as stored and exported.
    pub packets: Vec<u8>,
    pub public: PublicKey,
    stored: Option<Stored>,
    /// The secret half, unlocked, or why it could not be.
    unlocked: Option<std::result::Result<Arc<SecretHalf>, String>>,
}

impl Key {
    pub fn fingerprint(&self) -> String {
        self.public.fingerprint_hex()
    }

    pub fn holds_secret(&self) -> bool {
        self.stored.is_some()
    }

    /// The secret half, or why this host cannot use it.
    pub fn secret(&self, file: &Path) -> Result<Arc<SecretHalf>> {
        match &self.unlocked {
            Some(Ok(secret)) => Ok(Arc::clone(secret)),
            Some(Err(why)) => bail!("{why}"),
            None => bail!(
                "{} holds only the public key of {}, not its secret half; import the secret \
                 half here with `skarbiec keys import`, or open the vault on the host that holds it",
                file.display(),
                self.fingerprint()
            ),
        }
    }

    /// The X25519 key items are sealed to: the key's first encryption subkey.
    pub fn x25519(&self) -> Result<[u8; 32]> {
        match self.public.subkeys.first() {
            Some(subkey) => Ok(subkey.x25519),
            None => bail!(
                "key {} has no Curve25519 encryption subkey, so nothing can be sealed to it; \
                 give its holder a new key (`skarbiec recipient rekey`)",
                self.fingerprint()
            ),
        }
    }
}

pub(crate) struct Keyring {
    pub path: PathBuf,
    pub keys: Vec<Key>,
}

impl Keyring {
    /// The key a selector names: a fingerprint (40 hex digits) or key id
    /// (its last 16) of the key or one of its subkeys, or a whole user id.
    /// Never a part of a user id or its address: an owner `a@example` must
    /// not find the recovery key `skarbiec-recovery <a@example>`.
    pub fn find(&self, selector: &str) -> Option<&Key> {
        let upper = selector.trim().to_ascii_uppercase();
        let hex = !upper.is_empty() && upper.chars().all(|c| c.is_ascii_hexdigit());
        if hex && (upper.len() == 40 || upper.len() == 16) {
            if let Some(key) = self.keys.iter().find(|key| {
                key.fingerprint().ends_with(&upper)
                    || key
                        .public
                        .subkeys
                        .iter()
                        .any(|sub| hex_upper(&sub.fingerprint).ends_with(&upper))
            }) {
                return Some(key);
            }
        }
        self.keys
            .iter()
            .find(|key| key.public.user_ids.iter().any(|uid| uid == selector))
    }

    /// The key a fingerprint names, refused naming the file when absent.
    pub fn require(&self, fingerprint: &str) -> Result<&Key> {
        self.find(fingerprint).with_context(|| {
            format!(
                "the key file {} holds no key {fingerprint}; import its public key \
                 (`skarbiec recipient add <uid> --import <file>`) or, for a key gpg kept, \
                 run `skarbiec keys import`",
                self.path.display()
            )
        })
    }

    /// Every unlocked secret half, with its key; keys whose secret could not
    /// be unlocked are left out and named in the second list with why.
    pub fn secrets(&self) -> (Vec<(&Key, Arc<SecretHalf>)>, Vec<String>) {
        let mut held = Vec::new();
        let mut locked = Vec::new();
        for key in &self.keys {
            match &key.unlocked {
                Some(Ok(secret)) => held.push((key, Arc::clone(secret))),
                Some(Err(why)) => locked.push(why.clone()),
                None => {}
            }
        }
        (held, locked)
    }
}

/// The unlock phrase: `SKARBIEC_UNLOCK` for one invocation, the owner-only
/// file `SKARBIEC_UNLOCK_FILE` names, or the persistent default
/// `$HOME/.stado/skarbiec-unlock`. None when none is configured.
pub(crate) fn unlock_phrase() -> Result<Option<Secret>> {
    if let Some(phrase) = crate::core::env::text("SKARBIEC_UNLOCK")? {
        return Ok(Some(Secret::new(phrase.into_bytes())));
    }
    let path = match crate::core::env::path("SKARBIEC_UNLOCK_FILE") {
        Some(path) => path,
        None => {
            let Some(home) = std::env::var_os("HOME") else {
                return Ok(None);
            };
            let candidate = PathBuf::from(home).join(".stado").join("skarbiec-unlock");
            // Only a default file that does not exist means "no phrase"; one
            // that cannot be inspected is reported below with its cause.
            match std::fs::symlink_metadata(&candidate) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                _ => candidate,
            }
        }
    };
    owner_only_file(&path, "Skarbiec unlock file")?;
    let phrase = std::fs::read_to_string(&path)
        .with_context(|| format!("read Skarbiec unlock file {}", path.display()))?;
    let phrase = phrase.trim_end();
    Ok((!phrase.is_empty()).then(|| Secret::new(phrase.as_bytes().to_vec())))
}

/// Refuse a file that is not a regular file of this account with owner-only
/// permissions, naming `what`, why, and the command that fixes it.
fn owner_only_file(path: &Path, what: &str) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {what} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "{what} {} must be a regular file, not a link or a directory; put the file itself there",
            path.display()
        );
    }
    if metadata.uid() != crate::core::effective_uid() {
        bail!(
            "{what} {} belongs to uid {}, not to this account (uid {}); a file another account \
             can replace decides which keys open the vault: chown it to this account",
            path.display(),
            metadata.uid(),
            crate::core::effective_uid()
        );
    }
    if metadata.mode() & crate::core::mode::GROUP_AND_OTHER != 0 {
        bail!(
            "{what} {} must be mode 0600 (it is {:o}), so no other account reads it: chmod 600 {}",
            path.display(),
            metadata.mode() & crate::core::mode::ALL,
            path.display()
        );
    }
    Ok(metadata)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str, what: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        bail!("{what} is not whole bytes of hexadecimal");
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&text[at..at + 2], 16)
                .with_context(|| format!("{what} holds a character that is not hexadecimal"))
        })
        .collect()
}

fn thirty_two(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .with_context(|| format!("{what} is {} bytes, not 32", bytes.len()))
}

/// Unlock keys this process derived, by phrase digest, salt and count: the
/// derivation is deliberately slow, and every secret half in one key file is
/// sealed under the same salt, so a process derives each key once.
type Derived = Vec<([u8; 32], Vec<u8>, u64, Secret)>;
static DERIVED: Mutex<Derived> = Mutex::new(Vec::new());

fn unlock_key(phrase: &[u8], salt: &[u8], count: u64) -> Secret {
    let digest = skarbiec_crypto::sha::sha256(phrase);
    // A cache a panicking thread left behind is only a cache: derive again.
    let mut derived = match DERIVED.lock() {
        Ok(derived) => derived,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some((_, _, _, key)) = derived.iter().find(|(held, held_salt, held_count, _)| {
        *held == digest && held_salt == salt && *held_count == count
    }) {
        return key.clone();
    }
    let key = Secret::new(skarbiec_crypto::openpgp::agent::s2k_iterated::<Sha256, 32>(
        phrase, salt, count, 32,
    ));
    derived.push((digest, salt.to_vec(), count, key.clone()));
    key
}

fn sealing_context(fingerprint: &str) -> Vec<u8> {
    let mut context = SECRET_CONTEXT.to_vec();
    context.extend_from_slice(fingerprint.as_bytes());
    context
}

fn unseal(
    fingerprint: &str,
    phrase: Option<&Secret>,
    salt: &[u8],
    count: u64,
    nonce: &[u8; 12],
    data: &[u8],
    file: &Path,
) -> std::result::Result<SecretHalf, String> {
    let Some(phrase) = phrase else {
        return Err(format!(
            "{} holds the secret half of {fingerprint} sealed under the unlock phrase, and no \
             unlock phrase is configured: write it to the owner-only file SKARBIEC_UNLOCK_FILE \
             names (default ~/.stado/skarbiec-unlock), or set SKARBIEC_UNLOCK for one command",
            file.display()
        ));
    };
    let key = unlock_key(phrase.expose(), salt, count);
    let key: [u8; 32] = key
        .expose()
        .try_into()
        .map_err(|_| "unlock key".to_string())?;
    let opened = chacha::open(&key, nonce, &sealing_context(fingerprint), data).map_err(|_| {
        format!(
            "the unlock phrase does not open the secret half of {fingerprint} in {}: it was sealed \
             under another phrase, or the file was changed; configure the phrase it was written \
             under (SKARBIEC_UNLOCK_FILE or SKARBIEC_UNLOCK)",
            file.display()
        )
    })?;
    let opened = Secret::new(opened);
    if opened.expose().len() != 64 {
        return Err(format!(
            "the secret half of {fingerprint} in {} is {} bytes, not the 64 a seed and a scalar make",
            file.display(),
            opened.expose().len()
        ));
    }
    Ok(SecretHalf {
        seed: Secret::new(opened.expose()[..32].to_vec()),
        scalar: Secret::new(opened.expose()[32..].to_vec()),
    })
}

fn parse_key(entry: &Value, index: usize, phrase: Option<&Secret>, file: &Path) -> Result<Key> {
    let what = format!("key {index} of {}", file.display());
    let encoded = entry
        .get("public")
        .and_then(Value::as_str)
        .with_context(|| format!("{what} has no public key text"))?;
    let packets = base64_decode(encoded).map_err(|error| anyhow::anyhow!("{what}: {error}"))?;
    let public = parse_public_keys(&packets)
        .map_err(|error| anyhow::anyhow!("{what}: {error}"))?
        .into_iter()
        .next()
        .with_context(|| format!("{what} holds no public key"))?;
    let fingerprint = public.fingerprint_hex();
    let stored = match entry.get("secret") {
        None | Some(Value::Null) => None,
        Some(secret) => {
            let field = |name: &str| -> Result<Vec<u8>> {
                let text = secret
                    .get(name)
                    .and_then(Value::as_str)
                    .with_context(|| format!("{what} ({fingerprint}): its secret has no {name}"))?;
                unhex(text, &format!("{what} ({fingerprint}) {name}"))
            };
            match secret.get("sealed").and_then(Value::as_bool) {
                Some(true) => Some(Stored::Sealed {
                    salt: field("salt")?,
                    count: secret
                        .get("count")
                        .and_then(Value::as_u64)
                        .with_context(|| {
                            format!("{what} ({fingerprint}): its sealed secret states no count")
                        })?,
                    nonce: field("nonce")?.as_slice().try_into().with_context(|| {
                        format!("{what} ({fingerprint}): its nonce is not 12 bytes")
                    })?,
                    data: field("data")?,
                }),
                _ => Some(Stored::Clear(SecretHalf {
                    seed: Secret::new(thirty_two(&field("ed25519")?, "an Ed25519 seed")?.to_vec()),
                    scalar: Secret::new(
                        thirty_two(&field("x25519")?, "an X25519 scalar")?.to_vec(),
                    ),
                })),
            }
        }
    };
    let unlocked = match &stored {
        None => None,
        Some(Stored::Clear(half)) => Some(Ok(Arc::new(SecretHalf {
            seed: half.seed.clone(),
            scalar: half.scalar.clone(),
        }))),
        Some(Stored::Sealed {
            salt,
            count,
            nonce,
            data,
        }) => Some(unseal(&fingerprint, phrase, salt, *count, nonce, data, file).map(Arc::new)),
    };
    // A secret half that is not this key's would sign and open as someone
    // else: the seed and the scalar must give the public keys stored.
    if let Some(Ok(half)) = &unlocked {
        let seed = thirty_two(half.seed.expose(), "an Ed25519 seed")?;
        if skarbiec_crypto::ed25519::public_key(&seed) != public.ed25519 {
            bail!(
                "{what}: the secret half stored for {fingerprint} is not that key's (its Ed25519 \
                 public key differs); the file was changed or written wrongly: import the key again"
            );
        }
        let scalar = thirty_two(half.scalar.expose(), "an X25519 scalar")?;
        let opens = public
            .subkeys
            .iter()
            .any(|sub| skarbiec_crypto::x25519::public_key(&scalar) == sub.x25519);
        if !opens {
            bail!(
                "{what}: the X25519 secret stored for {fingerprint} matches none of its encryption \
                 subkeys; the file was changed or written wrongly: import the key again"
            );
        }
    }
    Ok(Key {
        packets,
        public,
        stored,
        unlocked,
    })
}

/// What the cached keyring was read from, so a changed file, or another
/// unlock phrase, reads it again.
#[derive(PartialEq, Eq)]
struct Stamp {
    path: PathBuf,
    present: Option<(u64, u64, i64, i64, u64)>,
    phrase: Option<[u8; 32]>,
}

type Cached = Option<(Stamp, Arc<Keyring>)>;
static CACHE: Mutex<Cached> = Mutex::new(None);

fn stamp(path: &Path, phrase: Option<&Secret>) -> Result<Stamp> {
    let present = match std::fs::metadata(path) {
        Ok(metadata) => Some((
            metadata.dev(),
            metadata.ino(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.size(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("inspect the key file {}", path.display()))
        }
    };
    Ok(Stamp {
        path: path.to_path_buf(),
        present,
        phrase: phrase.map(|phrase| skarbiec_crypto::sha::sha256(phrase.expose())),
    })
}

/// The keyring of the vault this process works on.
pub(crate) fn load() -> Result<Arc<Keyring>> {
    load_from(&path())
}

/// The keyring `path` holds; an absent file is an empty keyring.
pub(crate) fn load_from(path: &Path) -> Result<Arc<Keyring>> {
    let phrase = unlock_phrase()?;
    let stamp = stamp(path, phrase.as_ref())?;
    let mut cache = CACHE
        .lock()
        .map_err(|_| anyhow::anyhow!("the key cache was poisoned by a thread that panicked"))?;
    if let Some((cached, keyring)) = cache.as_ref() {
        if *cached == stamp {
            return Ok(Arc::clone(keyring));
        }
    }
    let keyring = Arc::new(read(path, phrase.as_ref())?);
    *cache = Some((stamp, Arc::clone(&keyring)));
    Ok(keyring)
}

fn read(path: &Path, phrase: Option<&Secret>) -> Result<Keyring> {
    let Some(text) = crate::core::read_present(path, "the key file")? else {
        return Ok(Keyring {
            path: path.to_path_buf(),
            keys: Vec::new(),
        });
    };
    owner_only_file(path, "the key file")?;
    let document: Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "the key file {} is not the JSON Skarbiec writes; restore it from where it was kept",
            path.display()
        )
    })?;
    match document.get("format").and_then(Value::as_str) {
        Some(FORMAT) => {}
        other => bail!(
            "the key file {} states format {other:?}, not {FORMAT}; this build reads only {FORMAT}",
            path.display()
        ),
    }
    let entries = document
        .get("keys")
        .and_then(Value::as_array)
        .with_context(|| format!("the key file {} has no keys list", path.display()))?;
    let keys = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_key(entry, index, phrase, path))
        .collect::<Result<Vec<Key>>>()?;
    Ok(Keyring {
        path: path.to_path_buf(),
        keys,
    })
}

/// A key to add: its public packets and, when held here, its secret half.
pub(crate) struct NewKey {
    pub packets: Vec<u8>,
    pub secret: Option<SecretHalf>,
}

/// The salt a key file's sealed halves are written under: the one its first
/// sealed half already uses, so a process unlocking the file derives one key,
/// or a fresh one for a file that has none. Each half keeps its own nonce.
fn file_salt(document: &Value) -> Result<Vec<u8>> {
    let held = document
        .get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("secret"))
        .find(|secret| {
            secret.get("sealed").and_then(Value::as_bool) == Some(true)
                && secret.get("count").and_then(Value::as_u64) == Some(UNLOCK_COUNT)
        })
        .and_then(|secret| secret.get("salt"))
        .and_then(Value::as_str);
    match held {
        Some(salt) => unhex(salt, "the key file's unlock salt"),
        None => skarbiec_crypto::random::bytes(UNLOCK_SALT_BYTES)
            .context("draw the salt that seals the key file's secret halves"),
    }
}

fn entry(key: &NewKey, fingerprint: &str, phrase: Option<&Secret>, salt: &[u8]) -> Result<Value> {
    let mut entry = Map::new();
    entry.insert("public".into(), json!(base64_encode(&key.packets)));
    let secret = match (&key.secret, phrase) {
        (None, _) => Value::Null,
        (Some(half), None) => json!({
            "ed25519": hex(half.seed.expose()),
            "x25519": hex(half.scalar.expose()),
        }),
        (Some(half), Some(phrase)) => {
            let nonce: [u8; 12] = skarbiec_crypto::random::bytes(12)
                .context("draw the nonce that seals a secret key")?
                .as_slice()
                .try_into()
                .context("a 12-byte nonce")?;
            let key = unlock_key(phrase.expose(), salt, UNLOCK_COUNT);
            let key: [u8; 32] = key.expose().try_into().context("a 32-byte unlock key")?;
            let mut plain = half.seed.expose().to_vec();
            plain.extend_from_slice(half.scalar.expose());
            let plain = Secret::new(plain);
            let data = chacha::seal(&key, &nonce, &sealing_context(fingerprint), plain.expose());
            json!({
                "sealed": true,
                "salt": hex(salt),
                "count": UNLOCK_COUNT,
                "nonce": hex(&nonce),
                "data": hex(&data),
            })
        }
    };
    entry.insert("secret".into(), secret);
    Ok(Value::Object(entry))
}

/// Add `keys` to the key file at `path`, under its lock: a key already
/// there keeps its entry, except that a secret half it lacked is added.
/// Returns, per key, its fingerprint and whether the file changed for it.
pub(crate) fn add(path: &Path, keys: Vec<NewKey>) -> Result<Vec<(String, bool)>> {
    let parent = path
        .parent()
        .with_context(|| format!("the key file {} has no directory", path.display()))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(crate::core::mode::OWNER_ALL)
        .create(parent)
        .with_context(|| format!("create the key file's directory {}", parent.display()))?;
    let lock_path = path.with_extension("lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(crate::core::vault::private_file_mode()?)
        .open(&lock_path)
        .with_context(|| format!("open the key file lock {}", lock_path.display()))?;
    stado_wait::blocking(
        stado_wait::Kind::Lock,
        "the key file lock",
        lock_path.display(),
        || lock.lock_exclusive(),
    )
    .with_context(|| format!("lock the key file {}", lock_path.display()))?;
    let phrase = unlock_phrase()?;
    let mut document = match crate::core::read_present(path, "the key file")? {
        Some(text) => {
            owner_only_file(path, "the key file")?;
            serde_json::from_str::<Value>(&text).with_context(|| {
                format!(
                    "the key file {} is not the JSON Skarbiec writes",
                    path.display()
                )
            })?
        }
        None => json!({"format": FORMAT, "keys": []}),
    };
    // Each entry's fingerprint and whether it holds a secret half, kept in
    // step with `entries` as keys are added below.
    let mut held: Vec<(String, bool)> = read(path, phrase.as_ref())?
        .keys
        .iter()
        .map(|key| (key.fingerprint(), key.holds_secret()))
        .collect();
    let salt = file_salt(&document)?;
    let entries = document
        .get_mut("keys")
        .and_then(Value::as_array_mut)
        .with_context(|| format!("the key file {} has no keys list", path.display()))?;
    let mut answers = Vec::new();
    for key in keys {
        let public = parse_public_keys(&key.packets)
            .map_err(|error| anyhow::anyhow!("the key to add: {error}"))?
            .into_iter()
            .next()
            .context("the key to add holds no public key")?;
        skarbiec_crypto::openpgp::keys::verify_self_signatures(&key.packets).map_err(|error| {
            anyhow::anyhow!(
                "key {}'s own signatures do not verify ({error}), so its user ids and subkey are \
                 not shown to be its holder's; it was changed or is not a key: get it again from its holder",
                public.fingerprint_hex()
            )
        })?;
        let fingerprint = public.fingerprint_hex();
        let at = held.iter().position(|(held, _)| *held == fingerprint);
        match at {
            // A secret half arrives for a key held only publicly: the whole
            // entry is written again with it.
            Some(index) if key.secret.is_some() && !held[index].1 => {
                entries[index] = entry(&key, &fingerprint, phrase.as_ref(), &salt)?;
                held[index].1 = true;
                answers.push((fingerprint, true));
            }
            // The same key again: its public half is replaced when it
            // differs (a later expiry, a new user id), its secret kept.
            Some(index) => {
                let encoded = base64_encode(&key.packets);
                let changed =
                    entries[index].get("public").and_then(Value::as_str) != Some(encoded.as_str());
                if changed {
                    entries[index]["public"] = json!(encoded);
                }
                answers.push((fingerprint, changed));
            }
            None => {
                entries.push(entry(&key, &fingerprint, phrase.as_ref(), &salt)?);
                held.push((fingerprint.clone(), key.secret.is_some()));
                answers.push((fingerprint, true));
            }
        }
    }
    if answers.iter().any(|(_, changed)| *changed) {
        crate::core::vault::atomic_write(path, serde_json::to_string_pretty(&document)?.as_bytes())
            .with_context(|| format!("write the key file {}", path.display()))?;
    }
    if let Err(error) = FileExt::unlock(&lock) {
        eprintln!(
            "skarbiec: the key file lock {} was not released: {error}",
            lock_path.display()
        );
    }
    Ok(answers)
}

/// The public key packets in an armored or binary OpenPGP public key.
pub(crate) fn public_packets(text: &str) -> Result<Vec<u8>> {
    let data = skarbiec_crypto::openpgp::armor::dearmor(text, "PGP PUBLIC KEY BLOCK")
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    packets(&data).map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(data)
}
