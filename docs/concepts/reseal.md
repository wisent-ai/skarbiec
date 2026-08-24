# Reseal

A managed credential item carries a sealed statement of *which principal it
speaks for*. Sealing writes that statement once; resealing is the only way to
change it, and it requires its own capability. Nothing in a lifecycle call
can smuggle a different identity past it.

## The sealed directory contract

The contract is four keys, exactly (`src/credential/directory.rs`,
`DIRECTORY_KEYS`):

```json
{
  "provider": "<exact name, ≤128 chars>",
  "tenant_id": "<lowercase uuid>",
  "principal_object_id": "<lowercase uuid>",
  "account_upn": "<email>"
}
```

plus item-local `sealed_at` bookkeeping that never crosses the bridge wire
(`wire_directory`). Malformed blocks are refused key by key:
`sealed directory contract is missing <key>`, `sealed directory tenant_id and
principal_object_id must be lowercase UUIDs`.

One authority, two copies: the contract lives in a dedicated seal record
(surviving item absence) and in the item's `context.directory` once the item
exists. The two must agree:

```text
DIRECTORY_CONTRACT_DIVERGED: <id> and its sealed directory record name
different identities; reseal it before any lifecycle operation
```

(`resolved_directory`). Divergence is a contract failure, never a preference.

## Seal once, reseal deliberately

```sh
skarbiec credential seal-directory <item-id> --local \
  --provider <provider> --tenant <uuid> --object-id <uuid> --account-upn <email>

skarbiec credential reseal <item-id> --local \
  --provider <provider> --tenant <uuid> --object-id <uuid> --account-upn <email> \
  --as <consumer> --token-file <path>
```

- `seal-directory` refuses to overwrite:
  `<id> already carries a sealed directory contract; changing it requires
  credential reseal and a reseal capability`.
- `reseal` demands a live `reseal:<item>` capability presented as
  `--as <consumer> --token-file <path>`; without one:
  `<consumer> holds no reseal capability for <item-id>`.
- Both are local-only trust decisions:
  `credential <subcommand> runs against the vault file it owns; rerun it with
  --local on the canonical Skarbiec host` (`src/credential/mod.rs`). There is
  no HTTP route that reseals.
- A quarantined item refuses both until the quarantine is resolved
  (`refuse_quarantined`).
- Success is journaled as `credential-directory-sealed` or
  `credential-directory-resealed` with the four identity keys — identities,
  never secrets ([WORM audit](worm-audit.md)).

## The reseal capability

`reseal` is one of the two item-scoped lifecycle actions
(`src/access/tokens.rs`): it must not name a field
(`reseal capability is item-scoped and must not name a field`), it is checked
against a live grant at call time, and holding it never authorizes reading
the credential's value. Mint it narrowly:

```sh
skarbiec token-mint directory-sealer --capabilities reseal:<item-id>
```

## Why callers cannot set identity

Every lifecycle operation reads the sealed contract from the item and puts it
on the wire itself; no call argument carries a directory identity. The
`--expect-tenant` / `--expect-object-id` / `--expect-upn` flags can only
*refuse* — `DIRECTORY_EXPECTATION_MISMATCH: <flag> does not match the sealed
directory contract of <id>` — never set (`cross_check_expectations`). So no
caller can
rotate one principal's password while naming another; the full lifecycle
contract is in
[the CLI reference](../CLI.md#externally-managed-credentials-through-weles).

## Not to be confused with

- **Re-encrypting recipients.** `share`/`revoke`/`rotate-owner` re-seal
  *ciphertext* to a recipient group; `reseal` rewrites the *identity
  contract* and touches no key material ([SECURITY.md](../SECURITY.md)).
- **Enrollment.** `POST /v1/enroll` re-encrypts named items to a replica's
  key — recipient plumbing, not identity
  ([HTTP API](../http-api.md#sync-donations-enrollment)).
- **`stage`.** Staging writes a field value under lifecycle control; the
  sealed contract is metadata about whose value it is ([grant](grant.md)).
