# Trash and purge

Deleting a credential is two distinct decisions, and Skarbiec refuses to
merge them: `delete` is a recoverable state change, `purge` is the
irreversible removal. The comment above the implementation is the contract:
"Trash is recoverable. Purge remains a separate owner-only operation"
(`src/core/vault.rs::delete_item`).

## The states

An item's envelope carries `state`: `active` or `trashed`
([item](item.md#stored-shape)).

```text
delete <id>   active ──> trashed     (state flip; ciphertext, history, tags untouched)
restore <id>  trashed ──> active     (state flip back; nothing else changes)
purge <id>    any ──> gone           (the entry is removed from the vault document)
```

- `delete` and `restore` rewrite only `state` and `updated_at`
  (`delete_item`, `restore_item`).
- `purge` removes the whole entry — envelope, ciphertext, and every
  historical revision (`purge_item`). There is no undo; the git-synced or
  bonded copies of the vault document are the only place the item still
  exists. The documented flow trashes first, but the code removes the entry
  whatever its state.

## A trashed item is refused, not emptied

Every read boundary answers with a sentence that names the way out:

- CLI `get`: `item is in trash: <id> (restore it first)`
  (`src/core/vault.rs::get_item`).
- HTTP `POST /v1/items/read`: `410 Gone` —
  `{"error":"item is in trash","error_code":"not_found","detail":"restore it
  first: skarbiec restore <id>"}` (`src/net/mod.rs`). The status is `410`,
  not `404`, deliberately: callers read `404` as an absent optional value
  and retried a trashed item forever blaming infrastructure; `410`
  classifies as `not_found` in `wisent-errors`, which is never retryable.
- `routes verify`: a route pointing at a trashed item reports
  `vault item <item> is in trash` (`src/access/routes.rs`).
- `list` hides trashed items; `list --all` shows them with
  `"deleted": true`. A stale grant row naming a trashed item is inert, and
  mint-time validation deliberately skips rows a re-mint merely preserves
  ([grant](grant.md#capability-grammar)).

Observed, both surfaces ([item walkthrough](../walkthrough-item-lifecycle.md),
[acquisition walkthrough](../walkthrough-acquisition-broker.md)):

```text
$ skarbiec get demo-api
Error: item is in trash: demo-api (restore it first)

$ curl POST /v1/items/read demo-note#value (trashed)
{"detail":"restore it first: skarbiec restore demo-note","error":"item is in trash","error_code":"not_found"} [410]
```

## Who may trash, who may purge

- **Owner CLI.** `delete`, `restore`, and `purge` pass the owner-mutation
  gate: an item another authority controls is refused with `use the item's
  controlling lifecycle instead of direct owner <verb>` — verb `remove` for
  `delete`/`purge`, `acquire` for `restore` (`src/main.rs`). A purged item
  surfaces through the same gate, so acting on it twice reads:

  ```text
  Error: use the item's controlling lifecycle instead of direct owner remove

  Caused by:
      item not found: demo-api
  ```

- **Consumers.** `DELETE /v1/items` requires a `trash:<item>` capability and
  soft-deletes only; there is no purge over the consumer API
  ([HTTP API](../http-api.md#items)). `purge` exists as a mintable action so
  a grant may name it, and as the operator-console route
  `/v1/operator/items/purge`, which carries local-operator authority, not a
  consumer bearer (`src/net/operator.rs`).
- **Weles-managed items.** Once an item carries lifecycle provenance,
  owner-side `delete`, `restore`, `purge`, and `restore-version` are all
  refused through the same gate; the credential lifecycle is the only
  authority that may end that item
  ([CLI reference](../CLI.md#externally-managed-credentials-through-weles)).

## What the record shows

Trash, restore, and purge are envelope operations: in the executed
walkthrough they appended no journal entries of their own — the journal
carried exactly one `item-write` per revision, and the purged item's history
left with it. The durable trace of a purge is therefore the *absence* the
next `verify-chain`-intact journal cannot explain, plus any synced copy of
the vault document. Purge a leaked credential only after rotating it;
purging is how the old ciphertext stops being carried, not how it stops
having been disclosed ([SECURITY.md](../SECURITY.md)).

## Not to be confused with

- **`revoke <item-id> <uid>`.** Revoking a recipient re-encrypts the item to
  the remaining group; the item stays. Trash changes visibility, not the
  recipient set.
- **`token-revoke <consumer>`.** That ends a grant, not an item
  ([grant](grant.md)).
- **Purging history.** There is no partial purge: `restore-version` adds
  revisions and `purge` removes the whole item; no command deletes a single
  historical revision ([item](item.md#lifecycle)).
