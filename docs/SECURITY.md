# Security model

skarbiec keeps sensitive values in a single file that is armored ciphertext,
safe at rest. This document states what the vault protects, the trust
boundaries, and the invariants it upholds.

## What is encrypted, and what is not

- **Encrypted.** Each item's field values are sealed with public-key encryption
  to the item's recipient group (owner, recovery, and any shared users). The
  on-disk `skarbiec.vault.json` reveals no values.
- **Cleartext metadata.** `list` returns item ids, types, tags, and revision
  counts. These identifiers are not encrypted; treat item ids and tags as
  non-sensitive.

## Reading requires possession

Decrypting any item requires a recipient (or recovery) private half held in the
local `gpg` keyring. When that key is passphrase-protected, `skarbiec` supplies
the unlock phrase for a single decrypt from `SKARBIEC_UNLOCK` (handed to `gpg`
over stdin, never on argv or disk). With no key present — or no unlock phrase for
a protected key — decryption fails closed.

An attacker who copies the vault file alone gains nothing: they also need the
private half and, if it is protected, the unlock phrase.

## Values never leak to the edges

Three invariants keep values off surfaces that get logged or captured:

- `resolve --emit` lands the canonical login mapping in an owner-only
  (mode-0600) file and returns only that path plus the exported variable NAMES
  (for example `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_TOTP`). The values
  themselves are never printed to stdout.
- The append-only audit journal keeps operation names and non-sensitive
  identifiers only — never values.
- `list`, HTTP list endpoints, and `skarbiec_list` return metadata only.

## Service-account grants

A machine consumer never holds a recipient key. Existing direct consumers
present a grant minted by `token-mint --scopes`; generic HTTP scopes remain
action-qualified as `read:<item-glob>`, `write:<item-glob>`, and
`delete:<item-glob>`. A legacy bare glob authorizes reads only, so enabling
mutation endpoints cannot silently upgrade an existing grant.

Startup consumers instead use `token-mint --acquisition-scopes item#field`.
That grammar accepts only an exact existing item and exact field, rejects
wildcards/globs, and cannot be combined with direct scopes. The long-lived
bootstrap can request but cannot read. Skarbiec issues an opaque short-TTL
bearer bound to consumer, item, and field; the first successful read removes its
stored hash atomically before returning only that field. Binding mismatch does
not consume or broaden it. Replay and expiry return unauthorized.

Acquisition state is a separate owner-only regular file, updated through a
same-owner temporary file and atomic rename while an exclusive state lock is
held. Values never enter that file or the audit journal. Issuance and consumption
audit entries contain only consumer, item, field, expiry, and operation metadata.
`token-verify` continues to check direct read access without resolving.

## The MCP boundary is tighter than the CLI

An agent is not an operator at a terminal, so `resolve` over MCP stays disabled
until the server process is configured through its own environment:

- `SKARBIEC_MCP_CONSUMER` — the consumer identity to gate by.
- `SKARBIEC_MCP_TOKEN` (or `SKARBIEC_MCP_TOKEN_FILE`) — the consumer's grant, read
  from the server's own environment, never a tool argument, so it never lands in
  a transcript, log, or child argv.
- `SKARBIEC_MCP_OUT_DIR` — a required, absolute directory for emitted env files;
  a relative path is refused so a launch directory cannot place files in a repo.

With any of these absent, `skarbiec_resolve` returns a graceful "disabled"
message while health, list, and audit stay available. The value-revealing and
mutating verbs (item read, mint, rotation, export) are not exposed over MCP at
all.

## Recovery and rotation

Every item carries a recovery recipient, so losing the daily identity never
loses data. `rotate-owner <uid>` installs a new owner: it re-encrypts every
item and its full version history onto the new recipient group, drops the
previous owner from each item, and keeps the recovery recipient. Time-delayed
emergency grants share the vault with a trusted user only after an
operator-chosen moment.

Registering a key is not rotating one. `add-user` only adds a recipient and
deliberately leaves stored ciphertext alone, which is right for `share` but
would hand out an ownership title over data the holder cannot read; it
therefore refuses `--role owner` and names `rotate-owner` instead. Rotation
requires the new key to already be in the keyring and every existing
ciphertext to decrypt before anything is written, so a half-finished rotation
cannot leave the vault readable by neither owner.

Because the recovery recipient is the last line, its private half belongs
off-machine — a vault whose recovery key sits in the same keyring as the owner
key has one failure domain, not two. `recovery-status` lists the recovery
fingerprint and the item count it covers; an untested recovery key is a
hypothesis, so open one item with it on a schedule.

## Tamper evidence

The audit journal is append-only; each line carries the prior line's hash.
`verify-chain` recomputes the chain and reports any retroactive edit.

## Cryptography is delegated

skarbiec performs no cryptography of its own. It shells out to vetted local
tools: `gpg` for per-recipient public-key encryption and key material, `openssl`
for entropy, `shasum` for hashing (the audit chain and the k-anonymity breach
check), and optional `oathtool` for one-time codes. The vault's security rests on
those tools and on the operating system that guards the keyring and the unlock
phrase.

## What skarbiec does not defend against

- A host already compromised while the key is unlocked can read what the operator
  can read. skarbiec is not a substitute for operating-system protection of the
  keyring and the unlock phrase.
- Cleartext metadata (ids, types, tags) is visible to anyone who can run `list`
  against an unlocked vault.
