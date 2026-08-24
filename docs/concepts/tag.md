# Tag

How does a consumer find its own items without parsing ids? It filters on
tags. A tag is a plaintext role label in the item envelope: visible to every
holder of a list or pull grant, authorizing nothing, and load-bearing for
every product that enumerates the vault.

## What it is

`tags` is a set of strings beside the ciphertext
([item](item.md#stored-shape)). Namespaces are shaped
`<product>:<role>[:<value>]`, lowercase; every namespace is registered in
[the CLI reference table](../CLI.md#tag-namespaces-role-not-shape) in the same
commit that starts writing it. Never put a secret, a token, or a personal
identifier in a tag — anything holding a list or pull grant reads them.

Role, not shape: what an item *is* belongs to its [kind](kind.md); what it is
*for* belongs here. Parsing an item id is not a discovery mechanism — a rename
silently removes the item from a listing, while a wrong tag is visible in
`list`.

## Lifecycle

- `set`/`set-json --tags x,y` writes the set at item creation or rewrite.
- **An absent flag preserves; an empty flag clears.** `set`/`set-json` without
  `--tags` keep the item's current tags; `--tags=` clears them. The old
  absent-means-empty behavior let every `set-json` credential rotation strip a
  live subscription's `brama:subscription` and `brama:agent:` tags — the item
  kept serving traffic while vanishing from every consumer that enumerates by
  tag (`src/main.rs::requested_or_existing`).
- `retag <id> --tags tag[,tag...]` replaces the set without touching the
  payload: a payload write would re-encrypt to the current recipient list —
  a write that can narrow access to a live credential and needs the secret in
  hand to perform at all (`src/main.rs::cmd_retag`,
  `src/core/vault.rs::set_item_tags`).
- The `item-write` journal entry records both `tags` (stored count) and
  `tags_requested` (what the writer passed), so a stored count that falls to
  zero names the writer that emptied it ([WORM audit](worm-audit.md)).

## The reserved tag

`managed:weles` marks authenticated Weles provenance and only the credential
lifecycle may write it. `set`, `set-json`, `retag`, and `import` refuse it:

```text
managed:weles is reserved for authenticated Weles writes
```

(`src/main.rs::ensure_no_reserved_tags`). An item carrying it also refuses
`reclaim`: `<id> is managed by Weles; use a credential operation`
(`src/core/vault.rs::reclaim_item`).

## Invariants

- Tags are plaintext. They ride in `list`, in a `sync`/`pull` document, and
  in every donation envelope; treat them as public within the trust boundary
  ([SECURITY.md](../SECURITY.md#what-is-encrypted-and-what-is-not)).
- Tags authorize nothing. A grant names an item and field exactly; there is
  no tag-scoped capability ([grant](grant.md)).
- Tags are a set: one item can carry several independent roles, and `retag`
  replaces the whole set, not one member.

## Commands

```sh
skarbiec set <id> ... --tags demo:walkthrough
skarbiec retag <id> --tags demo:walkthrough,demo:retagged
skarbiec list            # tags ride in every row
```

## Not to be confused with

- **A kind.** Shape is validated; role is declared. The vault refuses a
  `login` without a `username`, but no tag is ever required.
- **`management`.** Who may write the item is `management`'s answer, stamped
  from writer identity, not a label anyone can set ([item](item.md)).
- **A capability route.** A route maps a resource name to a field for
  redemption; a tag only makes an item findable
  ([capability token](capability-token.md)).
