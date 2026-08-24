# Item model

An item is one credential with an identity, a shape, and a place to be found.
This page states the model; the exact command flags live in
[the CLI reference](CLI.md#vault-items).

## Envelope and ciphertext

Every item has two surfaces, and they are deliberately not equally visible:

- The **envelope** — id, `kind`, `tags`, recipient uids, revision count — is
  plaintext. `list` returns it, a sync pull document carries it, and any
  holder of either can index it. Treat ids and tags as non-sensitive.
- The **payload** — `fields` (the values) and `context` (which account,
  service, or session the credential belongs to) — is ciphertext, sealed to
  the item's recipient group. No grant holder can search it; only a key
  holder can answer "which items belong to this service".

Deleting is recoverable by default: `delete` moves an item to the trash,
`restore` brings it back, `purge` removes it permanently, and
`restore-version <id> <at>` rolls back to an earlier version by timestamp.
Every write appends a version rather than replacing history.

## Kinds

Every payload is one JSON object validated against `skarbiec.item.v2`
(`src/core/schema.rs`). Allowed top-level properties are `schema`, `kind`,
`fields` (non-empty object), `context` (required object), and optional
`extensions`.

| Kind | Fields (`*` = required) |
| --- | --- |
| `login` | `username*`, plus at least one of `password`, `totp_secret`, `recovery_codes` |
| `host-account` | `username*`, `password*`, and `context.account_ref` naming `<user>@<host>` |
| `note` | `value*` |
| `api-key` | `api_key*`, `api_user`, `username`, `client_ip` |
| `access-key` | `access_key_id*`, `secret_access_key*`, `session_token` |
| `token` | `token*` |
| `oauth-client` | `client_id*`, `client_secret*` |
| `proxy` | `username*`, `password*`, `host`, `ports`, `zone` |
| `key-pair` | `private_key*`, `public_key`, `passphrase`, `key_id`, `issuer_id`, `team_id` |
| `certificate` | `certificate*`, `private_key*`, `chain`, `passphrase` |
| `service-account` | `credential_json*` |
| `credential-operation` | `value*` |
| `bundle` | free-form fields |
| `stado-secret` | free-form fields |
| `internal-authority` | free-form fields |

Typed kinds reject fields outside their list. The free-form kinds accept any
field whose name is 1–128 ASCII alphanumerics plus `.`, `_`, `-`;
`credential-operation` additionally requires `value`. `host-account` is the
one kind that also constrains its context, because an account credential
that does not name its host cannot be matched to the host it opens.

A kind states what shape a secret has, and shape is a contract: a `login` is
what browser-fill trajectories enumerate, so a machine account is a
`host-account` rather than a `login` with a tag on it — the two sets stay
disjoint so a host password is never typed into a web form.

## Context

`context` carries provenance rather than secrets, inside the ciphertext:
`source_kind`, `provider`, `account_ref`, `tenant_ref`, `request_id`,
`operation`, `session_label`, `login_method`, `name`, `login_url`, and
`domains` are the recognized keys. Two context members are owned end to end
by the credential lifecycle and never written through item APIs:
`context.directory` (a sealed directory-identity contract) and
`context.receipt` (proof of the last provider-verified change); see
[the CLI reference](CLI.md#externally-managed-credentials-through-weles).

## Tags: role, not shape

What an item is *for* belongs in `tags`, and a consumer that needs to find
its own items filters on them. Parsing an item id is not a discovery
mechanism: a rename silently removes the item from a listing, while a wrong
tag is visible in `list`. Tags are a set, so one item can carry several
independent roles; `retag` rewrites an item's tag set.

Tag namespaces are shaped `<product>:<role>[:<value>]`, lowercase, and every
namespace is registered in the table in
[the CLI reference](CLI.md#tag-namespaces-role-not-shape) in the same commit
that starts writing it. Never put a secret, a token, or a personal
identifier in a tag — anything holding a list or pull grant reads them.
`managed:weles` is reserved: `set`, `set-json`, and `import` refuse it,
because once an item has authenticated Weles provenance, direct owner
mutation yields to the `credential` lifecycle.

## Control: who may write an item

`management` records who may write an item, stamped from the identity of
whoever created it: the owner gets `{"mode":"owner"}`, any other writer gets
`{"mode":"external","controller":"<consumer>"}`. Afterwards only that same
authority may change it, which is what stops two systems from fighting over
one credential. When the recorded controller can no longer write —
its API path is gone — `reclaim <id>` returns the item to owner control,
touching no field, tag, recipient, or revision; the repair is described with
its refusal rules in [grants and consumers](grants-and-consumers.md#reclaim-repairing-an-item-with-no-writer).

## Finding an item

An owner holding the key is the only party that can search inside the
ciphertext, and `scripts/search-items.py` is that query: it opens each item
locally and matches a pattern against id, tags, field names, and context,
printing coordinates and never a value. Two consequences worth restating
from [the CLI reference](CLI.md#finding-an-item): an id is not an index, and
a context match is not a credential for that service — read `source_kind`
to separate the credential of a service from an account merely named after
one.
