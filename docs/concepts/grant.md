# Grant

A grant is the vault's answer to "may this identity perform this action on
this item (and field)" — nothing more. It is a consumer entry holding exact
structured capabilities; the vault keeps at most a hash of any bearer. The
narrative model is [grants and consumers](../grants-and-consumers.md); this
page is the exact grammar, the stored shape, and every mint-time refusal.

## Capability grammar

One capability is `action:item[#field]`, comma-separated in
`--capabilities`. The validator (`src/access/tokens.rs::parse_capabilities`)
enforces:

- `action` is one of `acquire`, `read`, `stage`, `rotate`, `verify`,
  `revoke`, `share`, `trash`, `purge`, `admin`, `sync`, `enroll`, `donate`,
  `lifecycle`, `reseal`, `introspect`, `call` (`allowed_action`). The action
  table with meanings is in
  [grants and consumers](../grants-and-consumers.md#capabilities-one-action-one-resource-one-optional-field).
- `item` matches `[A-Za-z0-9._\-:/]+` (`exact_resource`); a field is one
  exact component, except a `call` field, which is a `/`-joined route with no
  empty component and no `..` (`exact_route`).
- No wildcards, no legacy scopes, no duplicates.

Refusals, verbatim:

```text
token-mint requires --capabilities action:item[#field]
capabilities use action:item[#field]
unsupported capability action: <action>
capabilities require exact resource and field names without globs
<action> capability requires one exact field          (acquire, stage, rotate, verify)
<action> capability is item-scoped and must not name a field   (lifecycle, reseal)
duplicate capability: <encoded>
context is metadata and may only be named by read capabilities
capability names a missing field: <item>#<field>
capability names a missing item: <item>
```

Existence checks have two deliberate exceptions: `stage`/`acquire` may name a
field the kind merely *allows* (staging is how it comes to exist), and `call`
names a service, not a vault item, so nothing is required to exist. When a
mint re-states a consumer's existing capabilities, rows it merely preserves
are not re-validated: a stale row whose item was later trashed is already
inert, and re-validating it would make one stale row block every unrelated
addition (`parse_capabilities`, comment).

## Stored shape

`token-mint <consumer> --capabilities ...` writes one entry under the vault's
`tokens` section:

```json
{
  "hash": "<sha256 of the bearer, or null>",
  "capabilities": [{"action": "...", "item": "...", "field": "..."}],
  "workload_public_key": "<armored Ed25519 key, or null>",
  "audience": "<consumer unless --audience>",
  "expires_at": 1790201006
}
```

The bearer itself is returned exactly once (`"token"` in the mint response)
and never stored; TTL defaults to 30 days (`--ttl-seconds`, default
`2592000`). `tokens` lists every entry without hashes or bearers;
`token-verify` checks one exact action/resource/field binding;
`token-revoke <consumer>` drops the entry — after which even a fresh,
correctly signed acquisition proof answers `401 unauthorized`, captured in
[the acquisition walkthrough](../walkthrough-acquisition-broker.md).

## Composition rules

Mint-time refusals that keep grants narrow (`mint_once`):

```text
token-mint refuses to change existing capabilities without --replace-capabilities
acquire capabilities cannot share a grant with direct capabilities
lifecycle capabilities cannot share a grant with read capabilities
acquire capabilities require --workload-public-key-file
workload public keys are valid only for acquire capabilities
acquire capabilities cannot use --token-file
--ttl-seconds must be positive
existing grant is not v2; run migrate-v2 first
```

The first is the widening gate: re-minting a consumer with a different
capability set is refused unless `--replace-capabilities true` says so.
`token-ensure-read <consumer> <item> --field <field> --token-file <path>` is
the idempotent alternative — it adds one exact `read` capability to an existing
grant without rotating its bearer, answering `"status":"unchanged"` when the
capability is already present, and refuses when the presented file does not
match: `token file does not match the consumer's recorded bearer`.

## Invariants

- A grant is per-consumer and singular: one entry per consumer name; minting
  again replaces it (subject to the widening gate).
- The vault stores hashes, never bearers; hashing shells out to `shasum`
  ([SECURITY.md](../SECURITY.md#cryptography-is-delegated)).
- An expired grant and an unknown one are indistinguishable to a caller
  (`active()` filters both), so probing the vault leaks nothing about what
  exists ([consumer](consumer.md)).
- Grants are not model policy: which caller may use which model, provider, or
  subscription is the consuming product's contract
  ([grants and consumers](../grants-and-consumers.md#grants-are-not-model-policy)).

## Commands

```sh
skarbiec token-mint <consumer> --capabilities read:item#field[,...] [--ttl-seconds n] [--audience a]
skarbiec token-mint <consumer> --capabilities acquire:item#field --workload-public-key-file key.pem
skarbiec token-ensure-read <consumer> <item> --field <field> --token-file <path>
skarbiec token-register-acquisitions <absolute-catalog> --workload-public-key-file key.pem [--ttl-seconds n] [--replace-capabilities]
skarbiec tokens
skarbiec token-verify <consumer> <item-id> --action read [--field <f>] --token <bearer>
skarbiec token-revoke <consumer>
```

## Not to be confused with

- **The bearer.** The grant is the vault-side record; the bearer is the
  secret a direct consumer presents ([capability token](capability-token.md)).
  Acquisition grants have no bearer at all.
- **A recipient.** A recipient holds a `gpg` key and decrypts; a grant holder
  never decrypts — the broker does, per authorized field
  ([consumer](consumer.md)).
- **An emergency grant.** `emergency-grant` is time-delayed *recipient*
  sharing for a human, not a consumer capability
  ([CLI reference](../CLI.md#recovery-and-emergency-access)).
