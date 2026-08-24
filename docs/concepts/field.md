# Field

Every access decision in Skarbiec ends at a field: grants name one, one-time
bearers are bound to one, and the HTTP read route returns exactly one. An
item is the unit of storage; a field is the unit of disclosure.

## What it is

A field is one named member of an item payload's `fields` object. Its name is
1–128 ASCII characters from `[A-Za-z0-9._-]` (`exact_component`,
`src/core/schema.rs`); which names may exist is the [kind](kind.md)'s
contract. Values are strings except `ports`, `recovery_codes`, and `chain`
(arrays allowed) and `credential_json` (object allowed).

`context` is addressable as a pseudo-field: `schema::field` returns the whole
context object for the name `context`, and grant validation admits it for
`read` capabilities only — `context is metadata and may only be named by read
capabilities` (`src/access/tokens.rs::parse_capabilities`).

## Field-scoped access

- `read:<item>#<field>`, `acquire:<item>#<field>`, `stage:<item>#<field>`,
  `rotate:...`, `verify:...` all name one exact field; `acquire`, `stage`,
  `rotate`, and `verify` refuse to exist without one:
  `{action} capability requires one exact field`
  ([grant](grant.md)).
- `POST /v1/items/read` and both acquisition routes take `{"id","field"}` and
  answer with exactly that field; there is no "all fields" machine read. The
  owner-only equivalents are `get <id>` (whole decrypted payload) and
  `get <id> --field <field>` (one exact text field printed raw).
- A capability route maps a workload resource onto one item *and one field*;
  `routes verify` reports `field_present` separately from `item_present`
  ([CLI reference](../CLI.md#capability-routes)).

## Existence is checked at every boundary

- **Mint time.** A grant naming a field the item does not carry is refused:
  `capability names a missing field: <item>#<field>` — except `stage`/
  `acquire` capabilities for a field the kind *allows*, because staging is how
  the field comes to exist (`parse_capabilities`).
- **Issue time.** An acquisition for a field that does not exist on the item
  fails with `acquisition field does not exist on item`
  (`src/access/acquisition.rs::validate_target`).
- **Consume time.** The field is read again under the state lock; a field
  removed between issue and read answers
  `acquisition field no longer exists on item` and the bearer is not spent.
- **Read time.** `canonical item has no field: <name>` (`schema::field`) is
  the CLI sentence; over HTTP an unauthorized field is indistinguishable from
  an unauthorized item: `403 {"error":"consumer not authorized to read item
  field"}` — captured in
  [the acquisition walkthrough](../walkthrough-acquisition-broker.md).

## Invariants

- One request, one field. Acquisition issuance and consumption each name
  exactly one field, and the audit journal records item and field names,
  never the value ([WORM audit](worm-audit.md)).
- Field names are envelope-adjacent, not secret: they appear in grants,
  routes, audit entries, and refusal sentences. The values are what the
  ciphertext protects.
- A provider contract writes one exact field — `password` for Microsoft
  directory providers, `api_key` for the rest — and the credential lifecycle
  refuses items whose kind cannot carry that field
  ([CLI reference](../CLI.md#the-items-field-is-a-contract-not-a-mapping)).

## Not to be confused with

- **A column or glob.** There are no field patterns; `read:item#*` is refused
  as `capabilities require exact resource and field names without globs`.
- **A tag.** Tags label the item, live in the plaintext envelope, and grant
  nothing ([tag](tag.md)).
- **A route.** The `#field` in a `call` capability names a route inside a
  service (`wisent-backend/chat/primary`), validated by `exact_route`, not a
  vault field ([capability token](capability-token.md)).
