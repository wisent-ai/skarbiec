# bond — the vault synchronization primitive

Status: implemented (2026-07-29) — full-vault pull over serve (`GET /v1/vault` gated by a `sync:pull` grant, `skarbiec pull` with an item-count regression guard and atomic rename), the `bond` config section in the vault doc (`bond-add`/`bond-list`/`bond-remove`), and the p2p donation path (`GET /v1/owner-pubkey`, `POST /v1/donations` gated by a `donate` grant, append-only with `exists` rejection, `skarbiec donate`) all exist; hub mode needs nothing beyond scoped grants and git mode is `sync-init`/`sync-push`/`sync-pull`.

## Definition

A **bond** is the named configuration object between two vaults that defines
how they synchronize and exchange information. Each vault stays an
autonomous ciphertext file; the bond holds the rule that binds them.
Bonds are two-sided but asymmetric, many-to-one per vault, and replaceable
without touching the vault — the vault format and cryptography never change.

## Why it exists

Two vaults never talk to each other directly, and there is no
vault-to-vault protocol baked into the file format. Every form of
synchronization reduces to one atom (the ciphertext file) moving or being
served, plus per-item sealing deciding who may open what. The bond names
that surface so the operator can choose the topology per relationship
instead of hardcoding one model.

## Schema

```
bond.mode:       replica | hub | p2p | git
bond.role:       source | replica | consumer | peer
bond.channel:    { type: serve | git | file, address: ..., token_scope: ... }
bond.peers:      [<public keys of the other side>]
bond.donations:  { policy: accept | owner-review }
bond.recovery:   <where this relation's rescue material lives>
```

## Modes

- **replica** — a `source` writes and exposes the ciphertext; every
  `replica` pulls and atomically replaces its file. Single writer by role
  definition; no conflicts exist. Transport: `serve` (token scope
  `sync:pull`) or any file channel.
- **hub** — the 1Password model. The `source` is one live serve; everyone
  else is a `consumer` with a scoped grant. No replicas at all; offline
  does not work; requires a DR leg (recovery key off-machine plus a host
  that can take the role).
- **p2p** — every `peer` writes locally and emits donations to
  `bond.peers`. No canonical source: each peer is the source of its own
  items. Conflict rule: new items are append-only; an existing item id may
  be overwritten only by its owner (the first writer of that id).
- **git** — like `replica`, but the channel is a git remote (self-hosted,
  e.g. over Tailscale — never a third-party host by default). Version
  history comes free; conflicts surface as git rejects and are resolved at
  file level.

## Invariants (all modes)

- The vault file is always the atom of synchronization.
- Access to values is decided exclusively by per-item sealing to recipient
  keys — the mode never changes that.
- The canonical source is **declared** in `bond.role`, not hardcoded.
- The only inbound write that is not "replace the file" is the **donation**
  (required in p2p, optional elsewhere): an item encrypted to the source's
  public key, transported over any channel, written by the source.
- Every pull, push and donation lands in the audit chain identically.

## Canonical source rule

Exactly one `source` exists per bond relationship in replica, hub and git
modes. p2p has none by design — ownership is per item id.

## What changes in code (conceptual)

A `bond` section in the vault document and one dispatch over the channel
types (`serve-pull`, `git`, `donation-inbox`). Everything else — init,
set/get, share, rotate-owner, recovery, serve, tokens — is untouched,
because the modes differ in transport and writer policy, not in vault
format.

## Naming

`bond` reads in both registers: the masonry joint that holds separate
stones as one structure, and the obligation of trust between parties.

## v2 additions (implemented 2026-07-30)

- **Donation inbox** — `POST /v1/donations` no longer merges on arrival; it
  enqueues the armored donation into a per-vault, owner-only inbox file
  (`<vault>.donations.json`) and answers `{"ok":true,"status":"pending"}`.
  The owner lists (`skarbiec donations`), merges (`donation-accept`, applying
  the append-only / owner-of-id rules), or drops (`donation-reject`); every
  transition is audited.
- **Provenance + owner-of-id overwrite** — every item carries `written_by`
  (uid or consumer of its writer; recorded by set/set-json, the HTTP write
  path, and donation merges). An overwriting donation is admitted only when
  its `from` claim matches the item's `written_by`, otherwise it is rejected
  `not-owner`; items predating provenance keep the v1 `exists` rejection.
  v1 trust model: the donate token's consumer IS the writer identity —
  `from` is an unsigned claim, signing arrives with real peer keys later.
- **Enroll** — `skarbiec enroll --as <uid> --to <base-url> --token <t>
  --items a,b,c` sends the local owner's armored public key to
  `POST /v1/enroll` (scope `enroll`); the source registers it as a member
  and re-seals the listed items to it (preserving `written_by`). After the
  next pull the replica opens exactly the enrolled items with its own key.
- **sync-daemon** — `skarbiec sync-daemon --bond <name> --token <t>` pulls
  on `bond.channel.interval_seconds` (read from the vault doc, never a
  literal) and shuts down cleanly on SIGTERM. launchd wraps it for
  persistence; no plist is created by the tool. A pull preserves the local
  `bond` section across the replace and stamps `last_pull_at` /
  `last_items_after` into it.
- **sync-status** — `skarbiec sync-status [--bond <name>] [--token <t>]`
  reports per bond: config, last pull stamp, local vs remote item counts
  (via `GET /v1/vault` when the channel is serve), and channel health.
- **invite** — `skarbiec invite <item> --field <field> --for <consumer>
  --workload-public-key-file <path>` registers one exact workload-bound
  `acquire:<item>#<field>` capability and prints a non-secret redemption
  contract; the secret itself is never printed.
- **bonds** — `skarbiec bonds` lists the whole bond registry (config plus
  last-pull stamps), read-only.
