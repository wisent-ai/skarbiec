# What is Skarbiec

What is Skarbiec, and what is the mental model for reading everything else in
these docs? Skarbiec is a local secrets broker: one encrypted vault file, a
grant system that lends exactly one field to exactly one identity, and a
hash-chained journal that records every accepted action. The whole product is
three moving parts — a vault that stores, grants that lend, and a journal that
remembers.

## The vault stores

The vault is a single JSON file (default
`~/.local/share/skarbiec/skarbiec.vault.json`, overridable with
`SKARBIEC_VAULT_FILE`). Every item's field values are armored ciphertext,
sealed with public-key encryption to the item's recipient group: the owner, a
recovery recipient, and any shared users. The file is safe at rest; copying it
alone yields nothing without a recipient's private key in the local `gpg`
keyring.

Items are typed. Each one is a `skarbiec.item.v2` payload with a `kind`
(`login`, `token`, `api-key`, `certificate`, and the rest of the schema in
[the item model](item-model.md)), encrypted `fields` and `context`, and
plaintext envelope metadata — id, kind, tags, recipients — that `list`
returns and that synchronization carries. No cryptography is hand-rolled:
Skarbiec shells out to `gpg` for encryption, `openssl` for entropy, `shasum`
for hashing, and optional `oathtool` for one-time codes.

## Grants lend

A machine consumer never holds a recipient key. It holds a grant: exact
structured capabilities of the form `action:item[#field]`, with no wildcards
([grants and consumers](grants-and-consumers.md)). The default machine path
is acquisition — the workload registers an Ed25519 public key and an
`acquire:item#field` capability, signs a timestamped, nonced request, and
receives an opaque one-time bearer with a short TTL (30 seconds by default).
The first successful read atomically deletes the bearer's stored hash before
returning that one field; replay, expiry, and any binding mismatch are
unauthorized.

Grants answer "who may read this field". They do not decide which caller may
use which model, route provider traffic, or run workloads: those are other
products' contracts, and Skarbiec's only role in them is holding the
credentials they resolve at execution time.

## The journal remembers

Every accepted action appends one line to an append-only journal, and each
line carries the previous line's hash. `verify-chain` recomputes linkage and
digests and names any retroactive edit; `audit-query` answers which consumer
touched which item and when. Values, signatures, one-use tokens, and public
keys never enter the journal — only operation names and non-sensitive
identifiers.

## What Skarbiec is not

Skarbiec does not protect secrets from a host that is already compromised
while the owner key is usable, does not encrypt item ids or tags (the
envelope is deliberately plaintext metadata), and does not replace OS keyring
custody, TLS, firewalling, or backups. The loopback HTTP broker
([HTTP API](http-api.md)) serves machine consumers and the local operator
console; it is not a hosted service and requires no account. Credential
rotation against external providers is a separate reviewed workflow through
Weles, described in [the CLI reference](CLI.md#externally-managed-credentials-through-weles).

## The first three commands

```sh
skarbiec status
```

The vault path and counts of items, recipients, tokens, and bonds, plus the
recovery fingerprint and whether its secret key is present locally.

```sh
skarbiec list
```

Item metadata — id, type, revision count, recipient uids, tags — and never a
value.

```sh
skarbiec doctor
```

The vault, the audit chain, the canonical endpoint, and WORM receipts, each
as `pass`, `fail`, or `not_configured`. It reads the files directly, never
the HTTP API it is diagnosing, so it still answers when that API does not.

The end-to-end path is [quick-start](quick-start.md); the full command
surface is [the CLI reference](CLI.md); the trust boundaries are in
[SECURITY.md](SECURITY.md). Each core noun has an exact page under
[concepts/](concepts/item.md); executed transcripts are
[the item lifecycle](walkthrough-item-lifecycle.md) and
[the acquisition broker](walkthrough-acquisition-broker.md); giving a
machine access is [delegate to a consumer](delegate-to-a-consumer.md);
triage is [the runbook](runbook.md).
