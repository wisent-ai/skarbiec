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

pub struct Vault {
    pub path: PathBuf,
    doc: Value,
    /// The saves the document recorded when it was opened; `None` for one
    /// never saved, which only a vault being created is.
    base_generation: Option<std::num::NonZeroU64>,
    /// The owner's user id, checked non-empty when the document was opened.
    owner: String,
    /// The recovery key's fingerprint, checked to be text when opened.
    recovery: String,
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

/// Who writes an item, as its `management.mode` records it: the vault owner,
/// a managed controller (the credential lifecycle, Weles) through
/// [`ManagedWrite`], or another writer outside both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagementMode {
    Owner,
    Managed,
    External,
}

impl ManagementMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ManagementMode::Owner => "owner",
            ManagementMode::Managed => "managed",
            ManagementMode::External => "external",
        }
    }

    /// The mode a stored `management.mode` names, read back through
    /// [`ManagementMode::as_str`]; nothing for a value no writer records.
    pub(crate) fn parse(name: &str) -> Option<ManagementMode> {
        [
            ManagementMode::Owner,
            ManagementMode::Managed,
            ManagementMode::External,
        ]
        .into_iter()
        .find(|mode| mode.as_str() == name)
    }

    /// The mode an item's `management` object records, when it records one
    /// this vault writes.
    pub(crate) fn of(item: &Value) -> Option<ManagementMode> {
        item.get("management")
            .and_then(|management| management.get("mode"))
            .and_then(Value::as_str)
            .and_then(ManagementMode::parse)
    }
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
    // A lock that stays refuses every later writer as owned by another
    // process while none is; that is said with its path and cause.
    fn drop(&mut self) {
        crate::core::staging::remove_said(&self.0, "the vault write lock is not released");
    }
}

fn acquire_write_lock(vault_path: &Path) -> Result<VaultWriteLock> {
    let lock_path = vault_path.with_extension("write.lock");
    let parent = lock_path.parent().context("vault path has no parent")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(crate::core::mode::OWNER_ALL)
        .create(parent)
        .with_context(|| format!("create vault directory {}", parent.display()))?;
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

/// The owner-only mode every private file the vault and its companions
/// write is given.
pub(crate) fn private_file_mode() -> Result<u32> {
    Ok(crate::core::mode::OWNER_READ_WRITE)
}

/// The item envelope revisions this product has written, oldest first; an
/// envelope's `format` is its place in this list, counted from one.
const ENVELOPE_REVISIONS: &[&str] = &[
    "one ciphertext per item, without item_uid, kind or state",
    "item_uid, kind, state and saved revisions beside the current one",
];

/// The only item envelope revision this build reads: the newest one written.
pub fn current_envelope() -> u64 {
    ENVELOPE_REVISIONS.len() as u64
}

/// Bytes of OS entropy behind one `item_uid`: one 128-bit number.
const ITEM_UID_ENTROPY_BYTES: usize = std::mem::size_of::<u128>();

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

/// A list of text an entry stores (its `tags`, its `recipients`), read whole
/// for a writer that seals it back. An entry without the field, or with the
/// null the item listing projects for an absent one, carries none; a field
/// that is not a list of text is refused, because a writer given only what it
/// could read would store the item again without the rest.
pub fn entry_texts(id: &str, entry: &Value, field: &str) -> Result<Vec<String>> {
    match entry.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(listed)) => listed
            .iter()
            .map(|each| each.as_str().map(str::to_string))
            .collect::<Option<Vec<String>>>()
            .with_context(|| {
                format!(
                    "vault item {id} carries {field} with an entry that is not text: {listed:?}"
                )
            }),
        Some(other) => bail!("vault item {id} carries {field} {other}, not a list"),
    }
}

/// The saves `doc` records: none for a document never saved, and a refusal
/// for a generation that is not a count above zero, which no writer of this
/// file produces.
fn document_generation(doc: &Value) -> Result<Option<std::num::NonZeroU64>> {
    match doc.get("generation") {
        None => Ok(None),
        Some(recorded) => match recorded.as_u64().and_then(std::num::NonZeroU64::new) {
            Some(generation) => Ok(Some(generation)),
            None => bail!("records generation {recorded}, not a count of saves above zero"),
        },
    }
}

/// Write a vault document privately and atomically: a fresh owner-only
/// temporary beside the target, synced, then renamed over it. Every writer of
/// a vault file, including replica pulls, uses this path so privacy does not
/// depend on the process umask.
pub fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
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
        crate::core::staging::remove_said(&temp, "a failed vault write left its temporary file");
    }
    result
}

/// The vault document's `key` section, refused naming it when it is absent
/// or not an object, so a damaged vault refuses the one write that needs
/// the section instead of aborting the process serving every consumer.
fn obj_mut<'a>(v: &'a mut Value, key: &str) -> Result<&'a mut Map<String, Value>> {
    v.get_mut(key)
        .and_then(Value::as_object_mut)
        .with_context(|| format!("the vault's {key} section is missing or not a JSON object"))
}

fn now() -> String {
    crate::core::clock::now_iso()
}

mod document;
pub(crate) use document::VaultChangedConcurrently;
mod items;
mod managed;
mod recipients;
mod removal;
