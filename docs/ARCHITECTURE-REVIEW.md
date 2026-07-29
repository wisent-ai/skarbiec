# Architecture review

Written after the July key-loss incident, from reading the shipped source rather
than the documentation. Ordered by what can destroy or leak the vault, not by
what is most interesting to fix.

## What the product is

Skarbiec is the fleet's credential boundary. Not an encryption library — `gpg`
does the encryption — but the single authority that holds secrets at rest and the
only thing permitted to hand one out. Every other component is a consumer:
deploy units, agents, workers, CI jobs, the desktop apps. A consumer presents a
scoped grant and receives one field, once, and the request is recorded in a
tamper-evident journal.

Two consequences follow, and both are load-bearing:

- **Its availability is the fleet's availability.** Nothing starts without it.
  There is no fallback by design — the cross-cloud fallback was deliberately
  removed after an earlier outage, so a broker that cannot answer is a fleet
  that cannot boot.
- **Its honesty is the fleet's diagnosability.** When the broker fails, every
  consumer fails at once and every symptom points somewhere else. The July
  outage cost hours because the health probe reported the process, not the key
  material, and reads of an unreadable item dropped the connection instead of
  returning a status.

That is the frame for everything below: correctness of the stored bytes first,
truthful failure second, features last.

## How the repository works today

One crate, one binary, deliberately dependency-light: `anyhow` and `serde_json`
only. All cryptography is delegated to vetted local tools — `gpg` for
public-key operations and key material, `openssl` for random, `shasum` for
digests — invoked as subprocesses. That choice is worth keeping: it makes the
trust base auditable and the crate portable, at the cost of a process spawn per
operation.

- `core/` — `crypto` (the subprocess seam), `vault` (the document), `items`
  (typed item model).
- `access/` — `recipients` (owner, sharing, rotation), `tokens` (consumer
  grants and one-time field acquisitions), `acquisition` (the short-lived
  bearer state machine), `recovery` (recovery status, key doctor, time-delayed
  emergency access), `policy`.
- `net/` — `http` (loopback API), `mcp` (stdio agent surface), `sync` (git-backed
  replication of the ciphertext).
- `runtime/` — `audit` (hash-chained append-only journal), `resolve` (login
  materialisation), `breach`, `totp`.

The vault is a single JSON document: `owner`, `recovery`, a `recipients` map of
uid to fingerprint and role, an `items` map where each entry carries its
ciphertext in `current` and every prior ciphertext in a `history` array, plus
`tokens` and `policy` sections. Item metadata — ids, types, tags, recipient
uids, token hashes and scopes — is cleartext by design and documented as such.

Trust boundaries: the loopback HTTP API authenticates with an `X-Consumer`
header and a bearer whose SHA-256 is stored in the document; scopes are
action-prefixed globs (`read:`, `write:`, `delete:`) with bare globs treated as
read-only for compatibility. Acquisition grants are exact `item#field` pairs
that cannot read anything directly and only mint a single-use bearer.

## Defects that can destroy the vault

### The write is not atomic and not durable

`Vault::save` calls `fs::write`, which truncates the file and then writes. A
crash, a kill, a full disk or a laptop losing power between those two steps
leaves the fleet's only ciphertext truncated or empty. There is no temporary
file, no atomic rename, no `fsync`, and no backup of the previous generation.

The acquisition state file — which holds only hashes and expiry metadata — is
written through a same-owner temporary file and an atomic rename under an
exclusive lock. The document holding every secret the company owns is not. That
inversion is the single most serious thing in this repository.

**Fix:** write to a temporary file in the same directory, `fsync` it, `rename`
over the target, then `fsync` the directory. Keep the previous generation as a
sibling until the rename succeeds.

### Concurrent writers lose each other's writes

The HTTP layer opens the vault per request and the CLI opens it per invocation.
Every mutation is a read-modify-write of the whole document with no lock. A
`token-mint` racing an `http-item-write` silently discards one of them. The
audit journal takes an exclusive `flock` before appending; the vault takes
nothing.

This is not theoretical: a grant minted during this incident carried eleven
scopes where the deploy unit expected fourteen, which is exactly the shape of a
lost update.

**Fix:** one exclusive lock around read-modify-write, reusing the audit
journal's existing lock discipline rather than inventing a second one.

### `token-mint` overwrites the whole grant entry

Minting replaces the consumer's entry outright, so re-minting a token drops any
`acquisition_scopes` and any scope not restated on that command line. Rotation
therefore silently narrows authority, and the failure appears later, in a
different process, as an authorization error.

**Fix:** mint must either preserve the existing scope sets or refuse when they
would change without an explicit flag.

### Permissions are applied after the fact and unchecked

`save` writes the file and only then shells out to `chmod`, discarding the
result with `.ok()`. There is a window where the document exists at the
process umask, and a `chmod` failure is invisible.

**Fix:** create with the mode set, and treat a permission failure as a write
failure.

## Defects that caused this outage

### Owner and recovery share one failure domain

`cmd_init` generates both keys with `crypto::generate_key`, which passes an
empty passphrase, into the same local keyring. The design promises offline
recovery material; the implementation puts the recovery secret next to the owner
secret, unprotected, on one machine. Deleting one directory took both.

`recovery-status` now reports when the recovery secret half is present locally
and says plainly that this is a fault, and `key-doctor` names the exact key
files a restore needs. Neither prevents the arrangement.

**Fix:** `init` must emit the recovery secret as armored offline material and
remove it from the local keyring in the same operation, so the promise is
structural instead of advisory. A vault whose recovery half never left the
machine should fail its own health probe.

### Nothing verifies that recovery works

The recovery recipient was on every item and unusable, and no command would have
noticed until it was needed. `key-doctor` closes the diagnosis gap; it does not
close the drill gap.

**Fix:** record the timestamp of the last successful recovery decryption in the
document and report its age. An untested recovery key is a hypothesis.

### One command could half-perform an ownership change

`add-user --role owner` registered a key without re-encrypting anything and
without touching the `owner` field, leaving an owner that could read nothing.
It now refuses, and `rotate-owner` performs the real operation atomically —
rewrapping every current and historical ciphertext, preserving the recovery
recipient, writing nothing until all of it succeeds.

## Structural limits worth deciding on

**The document is one blob and grows without bound.** Every item keeps every
prior ciphertext in the same file, so every write rewrites the entire history of
every secret. This is what makes the atomicity defect catastrophic rather than
annoying, and it puts a ceiling on how large the vault can get before writes
become slow enough to widen the corruption window.

**Metadata is a complete map of the company.** Names of every secret, every
consumer, every scope and every token hash sit in cleartext. That is a
documented trade, but it means the file's confidentiality requirement is much
higher than "the values are encrypted" suggests, and the git-backed sync copies
that map to a remote.

**There are no tests in the shipped lineage.** Not one `cfg(test)` module. The
`vendored-superset` branch carries an integration suite. Every guarantee in this
document is currently enforced by review alone.

**The subprocess seam hides failure modes.** `gpg` returning "No such file or
directory" for a missing pinentry, or hanging instead of failing when no
passphrase source exists, both surfaced during this incident. The seam is worth
keeping; it needs a single place that maps subprocess failures to intelligible
errors.

## Order of work

1. Atomic, durable, locked writes. Everything else is worthless if the file can
   be lost.
2. Recovery material off the machine at `init`, and a recorded drill.
3. `token-mint` preserving scopes.
4. Tests for the invariants named above, starting with write atomicity under a
   kill and scope preservation across a re-mint.
5. Split version history out of the hot document, or cap it.

Feature parity with `vendored-superset` is last. Its sixteen extra commands link
a database engine, a block cipher, signatures, key derivation and an HTTP client
into the process that holds every secret; each one should have to argue for
itself against the dependency posture that makes this crate auditable.
