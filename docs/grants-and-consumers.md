# Grants and consumers

How does a machine read a secret it cannot decrypt? A human recipient holds
a `gpg` key; a machine consumer never does. It holds a grant: exact
structured capabilities checked at every call, with only a hash of any
bearer retained in the vault. This page is the model; exact flags are in
[the CLI reference](CLI.md#service-account-grants).

## Capabilities: one action, one resource, one optional field

A capability is `action:item[#field]`. The v2 validator rejects wildcards
and legacy scopes; resource and field names must be exact. The allowed
actions (`src/access/tokens.rs`):

| Action | Grants |
| --- | --- |
| `read` | Read one exact field of one item. |
| `acquire` | Request a one-time bearer for one exact field. Requires a field. |
| `stage` | Write one exact field. Requires a field; provider-verified activation stays inside the credential lifecycle. |
| `rotate`, `verify` | Field-scoped credential-change actions. Require a field. |
| `share`, `revoke`, `trash`, `purge` | Item-scoped mutations: recipient changes, soft-delete, permanent removal. `trash` gates `DELETE /v1/items`. |
| `admin` | Administrative settlement on one exact item (for example quarantine resolution). |
| `lifecycle` | Drive credential operations on one exact item; never authorizes reading its value, and cannot share a grant with a `read` capability. Item-scoped — must not name a field. |
| `reseal` | Replace that item's sealed directory contract. Item-scoped. |
| `sync` | Serve-channel replication (`sync:pull`). |
| `enroll` | Register a replica recipient (`enroll:<uid>`). |
| `donate` | Enqueue one exact item into another vault's donation inbox (`donate:<item-id>`). |
| `introspect` | Ask what an inbound bearer is; returns an identity and its capabilities, never a value. |
| `call` | Reach a service, and with `#field` the exact route within it. |

Two consumer shapes exist, and they cannot be mixed in one grant:

- **Direct grant** — `token-mint <consumer> --capabilities ...` returns a
  bearer exactly once; the vault keeps only its SHA-256 hash. TTL defaults
  to 30 days. `token-ensure-read` idempotently adds one exact field read to
  an existing direct grant without rotating its bearer.
- **Acquisition identity** — `token-mint` with
  `--workload-public-key-file` registers an Ed25519 public key and only
  `acquire` capabilities. No standing bearer exists at all.

`tokens` lists every consumer with its structured capabilities, expiry,
audience, and whether it is workload-bound; `token-revoke <consumer>` drops
either shape; `token-verify` checks one exact action/resource/field binding.

## Acquisition grants: no standing secret

The default machine path replaces a standing read token with a signed,
one-use exchange:

1. The operator registers the workload's Ed25519 public key and one exact
   `acquire:<item>#<field>` capability (`token-mint`, or `invite`, which
   also returns a non-secret redemption contract).
2. The workload signs the domain-separated consumer, item, field, workload
   id, epoch timestamp, and random nonce with its private key.
3. `acquisition-request` (CLI) or `POST /v1/acquisitions` (HTTP) verifies
   the signature against the registered key, rejects proofs outside the
   short clock window, records accepted nonce hashes until replay is
   impossible, and issues an opaque bearer bound to that workload, consumer,
   item, and field.

Each request and response names exactly one field. The bearer's TTL is
`SKARBIEC_ACQUISITION_TTL_SECONDS` (1–300, default 30). Issued bearer hashes
live in an owner-only acquisition state file beside the vault, updated by
atomic rename under an exclusive lock.

## One-time bearers: consumed on first read

`acquisition-read` (CLI) or `POST /v1/acquisitions/read` (HTTP) returns only
the bound field and atomically removes the bearer's stored hash under the
state lock *before* the value is returned. Replay, expiry, or any binding
mismatch is `unauthorized`; a mismatch neither consumes nor broadens the
bearer. Issuance records only consumer, workload id, item, field, and
expiry in the audit journal; consumption records consumer, item, and field.
Values, signatures, and public keys never enter the journal.

The complete executable proof is
[`examples/acquire-one-field.sh`](examples/acquire-one-field.sh): it
consumes a field once, repeats the same read to demonstrate `unauthorized`,
and prints the matching audit records.

## Capability routes: names for workloads

A workload never names a vault item. It asks for a resource —
`origin:https://.../password`, `provider:openai`, `agent:<name>` — and the
`routes` table maps that name onto one item and one field. The table is the
only place the two vocabularies meet; a resource it does not carry is
refused rather than guessed. `routes add` is idempotent and audited,
`routes reconcile` derives identity routes from the live vault without
moving existing ones, and `routes verify` resolves every route the way
redemption does and exits non-zero when any cannot deliver. Details and the
`item_present`/`field_present` semantics are in
[the CLI reference](CLI.md#capability-routes). The table authorizes
nothing: whether a workload may redeem a resource is decided at redemption
by the live vault grant that registered its workload key.

## Reclaim: repairing an item with no writer

Item control belongs to whoever created the item
([item model](item-model.md#control-who-may-write-an-item)). A consumer
that wrote through an API the broker no longer serves leaves its item with
no writer at all: the owner is refused as not owner-controlled, and the
consumer's path is gone — `set`, `set-json`, `delete`, and `import` all
decline.

`reclaim <id>` is the repair. It moves control back to the owner and
touches nothing else: no field, tag, recipient, or revision changes, so the
material stays exactly as the previous controller left it and the next
ordinary owner write is what changes anything. It refuses items under the
Weles credential lifecycle — mode `managed` or the `managed:weles` tag —
because their local state must not diverge from the provider's, and it
records the previous controller in the audit journal as `item-reclaimed`.

## Grants are not model policy

A Skarbiec grant answers exactly one question: may this identity perform
this action on this item (and field). Which caller may use which model,
provider, or subscription is not decided here; Skarbiec holds those
credentials as items and lends fields under the rules above, and the
consuming products own their access policy.
