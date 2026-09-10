// Encrypted per-recipient vault document for skarbiec. Every item is gpg-armored
// ciphertext encrypted to the public keys of its recipients (always the owner
// and the recovery key, plus anyone it is shared with). The on-disk file is an
// index of that ciphertext plus non-secret metadata — safe at rest.
//
// All numbers enter at runtime (argv / stored JSON written by the compiled
// binary), never as literals in this source.

use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Vault {
    pub path: PathBuf,
    doc: Value,
    base_generation: u64,
}
pub(crate) struct ItemWrite<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub payload: &'a Value,
    pub recipients: &'a [String],
    pub tags: &'a [String],
    pub import_source: Option<&'a str>,
}

#[derive(Clone, Copy)]
pub struct ManagedWrite<'a> {
    pub controller: &'a str,
    pub writer: &'a str,
    pub operation_id: Option<&'a str>,
}

#[derive(Default)]
struct WritePolicy<'a> {
    writer: Option<&'a str>,
    managed: Option<ManagedWrite<'a>>,
    /// An `item_uid` this item already had somewhere else -- the source vault
    /// of a cross-vault migrate. Only ever consulted when the target has no
    /// item under this id yet; an existing item's own identifier always wins.
    item_uid: Option<&'a str>,
}

struct VaultWriteLock(PathBuf);

impl Drop for VaultWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn acquire_write_lock(vault_path: &Path) -> Result<VaultWriteLock> {
    let lock_path = vault_path.with_extension("write.lock");
    let parent = lock_path.parent().context("vault path has no parent")?;
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(u32::from_str_radix("700", "8".parse()?)?)
            .create(parent)
            .with_context(|| format!("create vault directory {}", parent.display()))?;
    }
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(
                "another process owns the vault write lock {}; verify it is no longer running before removing a stale lock",
                lock_path.display()
            )
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("create vault write lock {}", lock_path.display()))
        }
    };
    let guard = VaultWriteLock(lock_path);
    writeln!(file, "{}", std::process::id())?;
    file.sync_all()?;
    Ok(guard)
}

fn private_file_mode() -> Result<u32> {
    u32::from_str_radix("600", "8".parse()?).context("private vault file mode")
}

/// The only item envelope revision this build reads. It was written inline at
/// each comparison, so a reader could not tell which number was load-bearing.
pub fn current_envelope() -> u64 {
    "2".parse().expect("envelope revision is a number")
}

/// Bytes of OS entropy behind one `item_uid`.
const ITEM_UID_ENTROPY_BYTES: usize = 16;

/// Mint an item's permanent identifier.
///
/// An item id is a mutable human-chosen name, and this session removed its
/// power to decide behaviour one guard at a time. What was left is that the
/// name is still the only identity the vault has, so renaming one item is a
/// fleet-wide migration and nobody renames anything -- which is how the names
/// came to carry meaning in the first place. This is the identity a rename
/// cannot touch.
///
/// 128 bits straight from `/dev/urandom`, hex. Random and nothing else: no
/// counter, no hostname, no MAC address and no timestamp, because this string
/// travels in cleartext beside the ciphertext and into `list`, a route table
/// row and a journal line, and an identifier that encodes when or where an item
/// was made would disclose exactly what an opaque one must not. 128 bits of
/// CSPRNG output collide by birthday at around 2^64 items against a vault
/// holding hundreds, so no coordination, registry or uniqueness check is
/// needed -- which is the whole point, since two vaults mint independently.
///
/// Hex rather than base64url or a UUID's hyphenated grouping: the alphabet is
/// `exact_component`-clean, so the value can appear in a resource string, an
/// error or a log line with no escaping and no case ambiguity, and it needs no
/// dependency and no version-nibble fiddling to produce. `/dev/urandom`
/// directly rather than `crypto::random_token`, which spawns `openssl`: the
/// backfill mints for every item that lacks one, and 599 subprocesses to
/// produce 599 random numbers is not a thing to ship.
pub fn mint_item_uid() -> Result<String> {
    let mut bytes = vec![Default::default(); ITEM_UID_ENTROPY_BYTES];
    File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read entropy for item uid")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The `item_uid` an entry already carries, if it carries a usable one.
///
/// Absent is a legitimate, permanent state: every item written before this
/// field existed has none, and no read, list, route or diagnosis may fail or
/// narrow because of it. Only a non-empty string counts, so a `null` left by
/// an older projection reads as absent rather than as an identity.
pub fn entry_item_uid(entry: &Value) -> Option<&str> {
    entry
        .get("item_uid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn document_generation(doc: &Value) -> u64 {
    doc.get("generation")
        .and_then(Value::as_u64)
        .unwrap_or_default()
}

fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path.parent().context("vault path has no parent")?;
    let temp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(private_file_mode()?)
        .open(&temp)
        .with_context(|| format!("create vault temporary file {}", temp.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(body)?;
        file.sync_all()?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(private_file_mode()?))?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn obj_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Map<String, Value> {
    v.get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("vault section is an object")
}

fn now() -> String {
    // ISO-8601 via `date` — avoids a numeric time literal and needs no crate.
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

mod document;
mod items;
mod managed;
mod recipients;
