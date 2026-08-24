# Item

What exactly does the vault store when you run `set`? One item: a plaintext
envelope wrapped around an encrypted payload, plus every previous revision of
that payload. This page is the stored shape and its lifecycle; the narrative
model is [the item model](../item-model.md), flags are in
[the CLI reference](../CLI.md#vault-items).

## Stored shape

Every write builds the same envelope (`src/core/vault.rs::set_item_with_writer`):

| Member | Plaintext? | Meaning |
| --- | --- | --- |
| `format` | yes | Envelope version. Anything but the current version is refused everywhere with `item uses the legacy envelope: <id> (run migrate-v2)`. |
| `kind` | yes | The item's validated type ([kind](kind.md)). |
| `state` | yes | `active` or `trashed` ([trash and purge](trash-and-purge.md)). |
| `revision` | yes | Monotonic write counter, starting at 1. |
| `management` | yes | `{"mode":"owner"\|"external"\|"managed","controller":<uid or consumer>}` — who may write this item. |
| `created_at` / `updated_at` | yes | ISO timestamps; `created_at` survives rewrites. |
| `recipients` | yes | Shared-user uids. The owner and recovery recipients are vault-wide and implicit. |
| `tags` | yes | Role labels ([tag](tag.md)). |
| `current` | mixed | `{revision, kind, created_at, written_by, operation_id, ciphertext}` — the live revision. Only `ciphertext` is sealed; `written_by` records the writing identity. |
| `history` | mixed | Every superseded `current`, oldest first. Nothing is deleted by an update. |
| `pending` | mixed | Present only while the credential lifecycle has staged a revision that is not yet provider-verified. |

`list` returns the envelope plus `versions` (history length + 1) and
`deleted`; it never returns a value. The ciphertext opens only for a holder of
a recipient private key; decryption re-validates the payload against the
item's `kind` before returning it.

## Lifecycle

```text
set/set-json ──> active (revision 1)
set/set-json ──> active (revision +1, previous current pushed to history)
restore-version <at> ──> active (a fresh revision copying the chosen version)
delete ──> trashed          restore ──> active          purge ──> gone
```

- **Every update is an append.** The previous `current` moves into `history`;
  `restore-version <id> <at>` re-encrypts the chosen historical payload as a
  new revision rather than activating old ciphertext in place
  (`src/core/vault.rs::restore_version`).
- **Writes stamp their writer.** `current.written_by` is the owner uid for
  owner writes and the consumer name for API writes; the `item-write` journal
  entry additionally records pid, process, and parent process, because a tag
  that disappears again must name its own cause
  (`src/core/vault.rs`, comment above `append_sync("item-write", ...)`).
- **Absent metadata flags preserve.** `set`/`set-json` without `--tags` or
  `--recipients` keep what the item carries; `--tags=` (empty value) still
  clears. An absent flag once meant "empty list", and every OAuth rotation
  through `set-json` stripped a live subscription's tags
  (`src/main.rs::requested_or_existing`).

## Who may write it

`management` is stamped from the identity of the first writer and only that
authority may change the item afterwards. The gate in front of every direct
owner mutation (`set`, `set-json`, `retag`, `delete`, `purge`, `restore`,
`import`) is `ensure_owner_mutation_allowed` (`src/main.rs`), whose refusal
reads:

```text
use the item's controlling lifecycle instead of direct owner <operation>
```

with `<operation>` being the gate's verb (`rotate`, `retag`, `remove`,
`acquire`). A missing item surfaces through the same gate, so
`restore` of a purged item answers this sentence with
`Caused by: item not found: <id>` — observed in
[the item walkthrough](../walkthrough-item-lifecycle.md). When the recorded
controller can no longer write, `reclaim <id>` returns the item to owner
control, touching no field, tag, recipient, or revision
([grants and consumers](../grants-and-consumers.md#reclaim-repairing-an-item-with-no-writer)).

## Invariants

- The envelope is deliberately plaintext: ids, kinds, tags, and recipient uids
  index the vault without a key. Treat them as non-sensitive
  ([SECURITY.md](../SECURITY.md#what-is-encrypted-and-what-is-not)).
- A value never leaves through `list`, `status`, `tokens`, or the audit
  journal; only `get`, `acquisition-read`, `totp`, and authorized API
  responses carry one ([CLI reference](../CLI.md)).
- Reading a trashed item is refused, not emptied:
  `item is in trash: <id> (restore it first)` from the CLI,
  `410 Gone` with `"detail":"restore it first: skarbiec restore <id>"` over
  HTTP ([trash and purge](trash-and-purge.md)).
- `retag` rewrites tags without re-encrypting: setting tags through a payload
  write would re-seal the value to the current recipient list and requires the
  secret in hand (`src/core/vault.rs::set_item_tags`).

## Commands

```sh
skarbiec set <id> [--type <kind>] name=value ... [--recipients a,b] [--tags x,y]
skarbiec set-json <id>          # payload on stdin, never argv
skarbiec get <id> [--field <field>]
skarbiec list [--all]
skarbiec retag <id> --tags tag[,tag...]
skarbiec restore-version <id> <at>
skarbiec reclaim <id>
```

## Not to be confused with

- **A grant.** The item is the credential; a [grant](grant.md) is a scoped
  permission to act on it. Rotating one never rotates the other.
- **A kind.** The [kind](kind.md) is the validated shape of the payload, not
  the item itself; two items of one kind are still two credentials.
- **A route.** A capability route maps a workload-facing resource name onto
  one item and field; the item's id is not a discovery mechanism
  ([grants and consumers](../grants-and-consumers.md#capability-routes-names-for-workloads)).
