# Capability token

Three different tokens travel around a Skarbiec deployment, and confusing
them is how privilege quietly broadens. This page keeps them apart: the
standing bearer of a direct grant, the one-time acquisition bearer, and the
brokered capability a browser trajectory redeems.

## Standing bearer (direct grant)

`token-mint <consumer> --capabilities read:item#field` returns an opaque
bearer exactly once; the vault keeps only its SHA-256 hash
([grant](grant.md)). The consumer presents it on every call
(`Authorization: Bearer ...`). It expires with the grant (default 30 days),
dies with `token-revoke`, and is deliberately boring: no format, no embedded
claims, no offline verification — every check is a live vault lookup.
`--token-file` lets an operator supply a fixed bearer from an owner-only file
instead of generating one; the file must be owner-owned, mode-safe, and
non-empty (`src/access/tokens.rs::read_fixed_token`).

## One-time acquisition bearer

The default machine path holds no standing secret at all. The workload's
grant stores an Ed25519 public key; each borrow is a fresh exchange
(`src/access/acquisition.rs`):

1. The workload signs
   `SKARBIEC-WORKLOAD-ACQUISITION\0v1\0<consumer>\0<item>\0<field>\0<workload_id>\0<timestamp>\0<nonce>`
   with its private key.
2. `acquisition-request` / `POST /v1/acquisitions` verifies the signature
   against the registered key and refuses — uniformly as `unauthorized`,
   never naming the failed check — when: any name is inexact; the workload id
   is not 1–128 characters free of control characters and surrounding
   whitespace; the nonce is not exactly 43 base64url characters; the
   signature is not exactly 128 hex characters; the timestamp is more than
   30 seconds from now
   (`proof_window_seconds`); or the `sha256(workload_id\0nonce)` proof hash
   was already accepted (recorded for 2× the window = 60 s, which outlives
   the clock window it guards).
3. The issued bearer is random, stored only as a hash in the owner-only
   acquisition state file beside the vault, and bound to consumer, item,
   field, and workload id. TTL is `SKARBIEC_ACQUISITION_TTL_SECONDS`
   (1–300, default 30).
4. `acquisition-read` / `POST /v1/acquisitions/read` returns only the bound
   field and removes the stored hash under the state lock before the value is
   returned. Replay, expiry, or any binding mismatch answers `unauthorized`;
   a mismatch neither consumes nor broadens the bearer.

Both legs, including the replayed read and the post-revocation refusal, are
captured verbatim in
[the acquisition walkthrough](../walkthrough-acquisition-broker.md).

Issue-time refusals that are *errors* rather than `unauthorized`:
`acquisition field does not exist on item` (the grant names a field the item
lacks) and `item and field must be exact names without wildcards or
separators` (`validate_target`).

## Brokered capability (capability broker)

A browser trajectory mid-flight must hold a secret in memory for one form
fill and never receive anything it could persist. The capability broker
(`src/access/capability.rs`) serves that case over a Unix socket:

- **Issue.** `capability-issue --agent <a> --purpose <p> --resource <r>
  --target <t> [--ttl s] [--max-uses n]` records a promise: this agent may
  read this resource, `max-uses` times (1–16), until `issued_at + ttl`
  (1–3600 s, default 600). The resource must already resolve through the
  [capability routes](../grants-and-consumers.md#capability-routes-names-for-workloads)
  table — `no capability route maps <resource> to a vault field` — except
  `challenge:` resources, whose value arrives later by design.
- **Redeem.** `capability-serve --socket <path>` (or `SKARBIEC_CAP_SOCKET`)
  answers `skarbiec.redeem.v1` requests of at most 8 KiB: the caller proves
  it is the agent with an Ed25519 signature over
  `SKARBIEC-WORKLOAD-PROOF\0v1\0...`, the nonce is refused twice, and the
  stream yields exactly `secret_len` bytes and closes. Every denial is the
  same opaque refusal on the wire — a caller must not learn which check it
  failed — while the operator's journal records the reason
  (`capability-request-failed`, `denied_because`).
- **Pending.** A `challenge:` resource redeems as `pending` until
  `apple-challenge-put <resource>` stores the six digits a trusted device just
  showed (code on stdin, never argv). Denying would force the caller to tell
  "not yet" from "never" by guessing.

`capability-issue`, `capability-serve`, and `apple-challenge-put` are serving
surfaces outside the 70-command public contract in `skarbiec help`; their
lineage is recorded in [LINEAGE.md](../LINEAGE.md). State lives in
`SKARBIEC_CAPABILITY_FILE` (default `<vault>.capabilities.json`), audited as
`capability-redeemed` / `capability-cancelled`.

## Choosing between them

| Need | Token |
| --- | --- |
| A service reads the same field for months | Standing bearer, narrowest possible capability set |
| A workload borrows one field at execution time | Acquisition — no standing secret to steal |
| A browser flow must type a secret it may never hold | Brokered capability — the secret crosses one socket, once |

The decision guide with provisioning steps is
[delegate to a consumer](../delegate-to-a-consumer.md).

## Not to be confused with

- **The grant.** All three tokens are spent against a live grant entry;
  revoking the [grant](grant.md) kills every token form at once.
- **A recipient key.** No token decrypts anything; the broker process holding
  a `gpg` recipient key does, per authorized field.
- **A capability route.** The routes table maps resource names to vault
  coordinates and authorizes nothing; whether a workload may redeem is
  decided at redemption by the live grant that registered its key.
