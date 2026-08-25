# Runbook

Symptom-first triage for an operator at a broken vault. Every quoted
sentence is the verbatim string the binary emits (all from `src/`, several
observed live in the executed walkthroughs). Start with `skarbiec doctor`:
it reads state directly, never through the API it is diagnosing, and only
`fail` is an incident — `not_configured` means nobody switched that surface
on ([WORM audit](concepts/worm-audit.md#write-once-receipts)).

## First response

```sh
skarbiec doctor        # vault, audit, endpoint, worm — file and socket probes
skarbiec status        # item/recipient/grant counts and the vault path in use
skarbiec vaults        # every vault this machine knows about
```

`doctor`'s four checks and their failure sentences:

| Check | `fail` looks like | Meaning |
| --- | --- | --- |
| `vault` | `<path>: <error>` or `<path> reported no item count` | The vault file itself will not open or parse. |
| `audit` | `N of M entries linked, newest K digests intact; F fault(s), first at line L (<at>), in <journal>` | The hash chain is broken — see [chain faults](#verify-chain-reports-faults). |
| `endpoint` | `nothing answers <endpoint>, declared by <forward>` | The declared canonical broker is not listening. `not_configured` reads `SKARBIEC_ENDPOINT_UNRESOLVED: no canonical forward at <path>; declare it with `skarbiec credential declare-endpoint <url>``. |
| `worm` | `configured but absent: <paths>` | Receipts were configured and the store is gone — that is an incident, unlike the default `not_configured`. |

## Vault will not open

- `vault not initialized at <path> (run: init)` — the path is wrong before
  anything else is: check `SKARBIEC_VAULT_FILE`
  ([configuration](configuration.md#vault-and-state)). `init` on an
  existing vault refuses with `vault already exists at <path>`.
- `parse vault file` — the JSON document is damaged; recover from the
  git-sync or bond replica ([CLI reference](CLI.md#git-synchronization))
  rather than editing it.
- `gpg failed: <stderr>` — Skarbiec performs no cryptography of its own;
  the underlying `gpg` sentence is passed through. Missing secret key,
  locked keyring, or a wrong `GNUPGHOME` all surface here. `skarbiec
  key-doctor` and `recovery-status` say which recipient halves this machine
  actually holds. For a passphrase-protected key, the unlock file must
  exist and be readable: `read Skarbiec unlock file <path>`
  ([configuration](configuration.md#unlocking-a-protected-key)).
- `GET /health` answering `503` with `vault is unreadable: <error>` is the
  same class over HTTP: the broker holds ciphertext it can no longer
  decrypt, and a healthy socket does not make it healthy.

## Two writers, one vault

All mutations serialize behind `<vault>.write.lock`:

- `another process owns the vault write lock <path>; verify it is no longer
  running before removing a stale lock` — the sentence is the procedure:
  find the process first (`skarbiec serve`, an operator console, a stuck
  command); only after confirming it is dead, remove the lock file.
- `vault changed concurrently: loaded generation <n>, persisted generation
  <m>; reopen and retry` — a lost read-modify-write race, detected by the
  document generation number. Retrying the command is the fix; the vault is
  undamaged.
- `vault disappeared before save; refusing to recreate it from stale state`
  — something removed the file mid-operation; restore it before retrying,
  or the stale in-memory copy would become the vault.

## Audit journal lock is still held

Observed live during the executed walkthrough — the command failed, five
seconds after starting, with:

```text
Error: audit journal lock /tmp/.../demo.audit.append.lock is still held; no entry was written
```

Appends serialize across processes behind `<journal>.append.lock`, held for
milliseconds; a waiting writer gives up after 5 seconds, and a lock file
older than 30 seconds is treated as abandoned and cleared automatically
(`src/runtime/audit.rs`). So:

1. **Wait 30 seconds and retry.** The next writer removes an abandoned
   lock itself. This was the fix for the live occurrence, and for the lock
   a killed `serve` process left behind.
2. Persistent recurrence means a live holder is actually slow or stuck —
   find the process before touching the file. Never delete a lock younger
   than the window; deleting a *held* lock is exactly how the journal got
   two lines claiming one predecessor (the 2026-08-10 incidents recorded in
   the source comments).

The mutation itself did not happen — `no entry was written` also means the
vault change was not made, so the retry is safe, not a duplicate.

## verify-chain reports faults

`verify-chain` never stops at the first fault; read the `faults` array
whole ([WORM audit](concepts/worm-audit.md#verifying-the-chain)).

- `"fault": "linkage"` — a line's recorded predecessor is not the line
  before it: the signature of two writers racing one append (or a truncated
  copy), not of an edit. Every entry after it is still individually
  digest-valid; the journal remains evidence, with one documented seam.
- `"fault": "digest"` — the line's own fields no longer hash to the hash it
  carries: a retroactive edit of exactly that line. Executed demonstration
  (one byte changed on line 2): `"intact": false`, `"faults": [{"line": 2,
  "fault": "digest", ...}]`, linkage still 3 of 3.
- Digest verification runs in-process. `--tail N` bounds CPU and disk work;
  `doctor` verifies the newest 200 while linkage still covers the entire file.
- `"fault": "epoch"` means a checkpoint signature, its cleartext, or its
  `previous_tail` does not validate. For known historical damage, preserve the
  file and run `audit-epoch-start --reason <incident>`.
- Check you are reading the journal in service: the report's `journal`
  field names the file, and the default path and the path a supervisor
  passes (`SKARBIEC_AUDIT_FILE`) can be different files with wildly
  different entry counts.

## A read is refused

| Sentence | Cause and fix |
| --- | --- |
| `item is in trash: <id> (restore it first)` / HTTP `410 Gone` with `"detail":"restore it first: skarbiec restore <id>"` | Trashed, not gone. `skarbiec restore <id>`. The `410` is deliberate: it classifies as non-retryable `not_found`, so stop retrying ([trash and purge](concepts/trash-and-purge.md)). |
| `item uses the legacy envelope: <id> (run migrate-v2)` / HTTP `409` (`config`) | Pre-v2 envelope; run `skarbiec migrate-v2` (it snapshots first). |
| `use the item's controlling lifecycle instead of direct owner <verb>` | The item has a non-owner writer. If the controller is Weles, use the matching `credential` operation; if the controller is gone, `skarbiec reclaim <id>` ([item](concepts/item.md#who-may-write-it)). With `Caused by: item not found: <id>` underneath, the item was purged — there is nothing to act on. |
| `canonical item has no field: <name>` | The field never existed on this item; `list` shows the kind, the kind's table shows its fields ([kind](concepts/kind.md)). |
| HTTP `403 {"error":"consumer not authorized to read item field"}` | The grant does not cover this exact item#field — deliberately indistinguishable from the item not existing. `skarbiec token-verify <consumer> <item> --action read --field <f> --token <t>` answers precisely. |

## `unauthorized` from the acquisition path

Uniform by design — the caller is never told which check failed
([capability token](concepts/capability-token.md#one-time-acquisition-bearer)).
The operator-side checklist, in the order the checks run:

1. Names exact? Consumer, item, field must match the grant precisely.
2. Grant alive? `skarbiec tokens` — expired and revoked are
   indistinguishable from never-existed. After `token-revoke`, even a
   fresh, correctly signed proof answers `401` (executed in
   [the walkthrough](walkthrough-acquisition-broker.md#revocation-kills-a-valid-proof)).
3. Proof well-formed? Nonce exactly 43 base64url characters, signature
   exactly 128 hex characters, workload id 1–128 clean characters.
4. Clock inside the window? The timestamp must be within 30 seconds of the
   vault host's clock — skew between workload and vault hosts lands here.
5. Nonce fresh? A replayed `sha256(workload_id\0nonce)` proof hash is
   refused for 60 seconds.
6. Bearer fresh? One read consumes it; TTL is 30 s by default
   (`SKARBIEC_ACQUISITION_TTL_SECONDS`, 1–300).

Issue-time refusals that are errors, not `unauthorized`: `acquisition field
does not exist on item`, `item and field must be exact names without
wildcards or separators`. `acquisition state is locked` means 5 seconds of
contention on `<vault>.acquisitions.json` — retry.

## Minting is refused

All verbatim, from `src/access/tokens.rs`
([grant](concepts/grant.md) has the complete table):

- `token-mint refuses to change existing capabilities without
  --replace-capabilities` — the widening gate. Prefer
  `token-ensure-read` for one read; its own refusal is `token file does not
  match the consumer's recorded bearer`.
- `workload public key must be an owner-controlled regular file` — observed
  live: `openssl` writes mode 0644; `chmod 600` the PEM (walkthrough,
  [setup](walkthrough-acquisition-broker.md#setup)). The token-file twins:
  `token file must be an owner-controlled regular file`, `token file must
  contain one bounded non-whitespace token`.
- `acquire capabilities cannot share a grant with direct capabilities` /
  `lifecycle capabilities cannot share a grant with read capabilities` —
  split the consumer in two; that separation is the design.
- `capability names a missing item: <item>` / `capability names a missing
  field: <item>#<field>` — grants bind to what exists (`stage`/`acquire`
  excepted for fields the kind allows).

## HTTP status map

Statuses are Skarbiec's own; every `error_code` comes from `wisent-errors`
and Skarbiec emits exactly three ([HTTP API](http-api.md#items)):

| Status | `error_code` | Meaning |
| --- | --- | --- |
| `401` | — | Bad or consumed bearer, failed workload proof, revoked grant. |
| `403` | — | Live bearer, wrong capability. |
| `409` | `config` | Legacy envelope, or an in-flight adopt candidate. |
| `410` | `not_found` | Trashed item; never retryable. |
| `503` | `infra_down` | Ciphertext will not decrypt, or acquisition state unavailable. Retryable once the infrastructure is back. |

## Where the state actually is

Everything is a file beside the vault; `doctor` and this table are the
whole inventory
([configuration](configuration.md) has every variable):

| File | Contents |
| --- | --- |
| `<vault>` (`SKARBIEC_VAULT_FILE`) | The vault document: envelopes, ciphertext, recipients, grants, bonds. |
| `<vault>.write.lock` | Cross-process mutation lock. |
| `<journal>` (`SKARBIEC_AUDIT_FILE`) | Hash-chained audit journal. |
| `<journal>.append.lock` | Append critical section (30 s abandonment). |
| `<vault>.acquisitions.json` (`SKARBIEC_ACQUISITION_FILE`) | Issued one-time bearer hashes and accepted proof hashes; owner-only, or every acquisition fails with `acquisition state must be an owner-controlled regular file` / `acquisition state permissions must not grant group or other access`. |
| `<vault>.capabilities.json` (`SKARBIEC_CAPABILITY_FILE`) | Capability broker promises. |
| `capability-routes.json` (`SKARBIEC_CAPABILITY_ROUTES_FILE`) | Resource-to-field routes; `routes help` prints the resolving path. |
| `<vault>.donations.json` | Donation inbox awaiting `donation-accept`. |

A diagnosis session against a real vault, with expected output, is
[`examples/operations/diagnose-a-vault.sh`](examples/operations/diagnose-a-vault.sh);
the credential-lifecycle states (`quarantined`, `DIRECTORY_CONTRACT_DIVERGED`,
`DIRECTORY_EXPECTATION_MISMATCH`) have their own decision table in
[the CLI reference](CLI.md#externally-managed-credentials-through-weles) and
[reseal](concepts/reseal.md).
