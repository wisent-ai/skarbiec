# Architecture

skarbiec is a standalone secrets manager: encryption at
rest, multi-recipient sharing, service-account access, recovery, tamper-evident
audit, and runtime injection — with no dependency on any external manager or
hosted service. All cryptography is delegated to vetted local tools (gpg for
authenticated per-recipient encryption and key material, openssl for entropy,
shasum for hashing, optional oathtool for one-time codes). No cryptography is
hand-rolled here.

## What is built and verified (engine, command line, local API)

- Encryption at rest. Every item is armored ciphertext, encrypted to the public
  keys of its recipients. The on-disk file is safe at rest.
- Multi-recipient sharing. Register a user, share an item (re-encrypt to include
  them), revoke (re-encrypt to the remaining recipients).
- Service-account access. Mint a scoped grant; only a hash of it is retained.
  Read, write, and delete actions are matched against independent item globs.
- Recovery + emergency access. A recovery recipient is on every item, so losing
  the daily identity never loses data; time-delayed emergency grants share the
  vault with a trusted user after an operator-chosen moment.
- Admin policy. Minimum generated length and per-item rules, checked before the
  relevant operation.
- Tamper-evident audit. An append-only journal where each line carries the prior
  line hash; verify-chain detects any retroactive edit. Appends take a lock
  file beside the journal and re-read the predecessor from disk inside it,
  because the chain is read-modify-write and every CLI invocation is a
  separate process: two writers that each cached the same tail once produced
  two lines claiming one predecessor. Verification reports linkage and digests
  apart — linkage is free and covers everything, digests cost one `shasum` per
  line — and always names the journal it read, since the default path and
  `$SKARBIEC_AUDIT_FILE` are different files.
- Runtime injection. resolve writes an owner-only shell file of canonical login
  variables and returns its path — values land in the file, never on stdout;
  expand fills skarbiec reference lines in a template.
- Generator, one-time codes, breach health. Login-string and passphrase
  generation from operating-system entropy; current one-time code from a saved
  seed; breach check under k-anonymity (only a hash prefix leaves the host).
- Sync. Git-backed transfer of the encrypted file for many devices — only
  ciphertext crosses the wire.
- Local HTTP API. Loopback-only server the separate clients integrate with.

Verified end to end against the compiled binary: init, save, lossless
round-trip decrypt, generate, grant-gated resolve (allow and deny), verify-chain
intact, delete and restore, share, and policy — all green. Every row decrypts losslessly.

## The client boundary

The vault engine, local API, browser extension, and native-messaging host are
part of this repository. The extension in `browser/` uses the host to exchange
framed requests with the loopback API; the browser process never receives the
vault bearer or encryption keys. `skarbiec browser-host-install` provisions the
owner-private host registration and its narrow `read:login-*` grant.

The following remain distinct applications on different toolchains:

- Desktop and mobile clients. Native apps (their own toolchains) for unlock,
  browse, and biometric gating. The macOS client also finds the vaults a
  machine already holds and creates one, because a vault is a file rather
  than a registry entry: it reads the conventional locations, parses each
  candidate's plaintext envelope for owner and counts without decrypting
  anything, and shows no item name — those names are the sensitive map. It
  runs `init` for creation and holds the chosen vault itself, overriding
  `SKARBIEC_VAULT_FILE`, so which vault is on screen is not a property of
  whichever shell launched the app.
- Administrative web console. A web interface over the admin endpoints for user,
  policy, and audit management.

### Local HTTP API contract (what those clients call)

Loopback only. Started with `skarbiec serve` (port configurable with `--port`).
The stable generic item surface is:

- `POST /v1/items/list` — metadata for items covered by a `read:` scope.
- `POST /v1/items/read` with `{"id":"..."}` — one decrypted JSON item.
- `PUT /v1/items` with `{"id":"...","type":"...","value":...}` — create a new
  encrypted version while preserving existing recipients and tags.
- `DELETE /v1/items` with `{"id":"..."}` — soft-delete an item.

Every generic endpoint requires `X-Consumer` and `Authorization: Bearer ...`.
The grant must match the action-specific `read:`, `write:`, or `delete:` scope
for the item. A legacy bare scope is read-only. Values occur only in authorized
request/response bodies and are never included in audit records.

The one-time field surface is separate:

- `POST /v1/acquisitions` with `{"id":"...","field":"..."}` and a request-only
  bootstrap bearer issues an opaque short-TTL bearer bound to that exact
  consumer, item, and field.
- `POST /v1/acquisitions/read` with the same body and the issued bearer returns
  only that field, atomically removes the bearer hash, and returns unauthorized
  on replay, expiry, or any binding mismatch.

Bootstrap grants have no direct item scopes. Acquisition state contains only
hashes, bindings, and expiry metadata and is persisted by owner-safe atomic
rename under an exclusive lock.

Compatibility endpoints remain available: metadata-only `GET /list`, `GET /audit`,
and login-oriented `POST /resolve`.

`GET /health` proves the key material is still usable rather than that the
process is running. It opens the lowest-id live item and reports `503` with
`error_code: infra_down` when the stored ciphertext cannot be decrypted,
because a broker holding items it can no longer read is down however healthy
its socket looks. The probe is deterministic, so repeated calls exercise the
same ciphertext; the decrypted value is discarded and never returned or
logged. Reads of an item that exists but will not decrypt answer `503` with
the same code instead of dropping the connection.

## MCP server (agent surface)

A stdio Model Context Protocol server, started with the mcp command, exposes the
same programmatic-safe boundary as the loopback HTTP API to MCP-capable agents.
It runs in-process, reusing the same resolve/list/audit dispatchers as the
command line, so there is one policy and audit source of truth. JSON-RPC frames
go to stdout; diagnostics go to stderr. Exposed tools:

- skarbiec_health — liveness probe.
- skarbiec_list — item metadata (ids, type, revision counts, tags); never values.
- skarbiec_resolve — resolve a platform's admin login the sanctioned way;
  policy- and grant-gated, emits an owner-only env file and returns only its path
  plus the exported variable NAMES. Values are never returned.
- skarbiec_audit — the tamper-evident audit journal.

The value-revealing and mutating verbs (item get, mint, rotation, export) are
deliberately not exposed over MCP.

Because an agent is not an operator with vault keys at a terminal, resolve over
MCP is gated more tightly than the raw command line and stays disabled until the
server process is configured:

- SKARBIEC_MCP_CONSUMER — the consumer identity to gate by.
- SKARBIEC_MCP_TOKEN or SKARBIEC_MCP_TOKEN_FILE — the consumer's scoped grant,
  read from the server's own environment, never a tool argument, so it never
  lands in a transcript, log, or child argv.
- SKARBIEC_MCP_OUT_DIR — a required, absolute directory for the emitted owner-only
  env files; relative paths are refused so launch-cwd cannot place files in a repo.

With any absent, skarbiec_resolve returns a graceful "disabled: configure ..."
error while health, list, and audit remain available.

## The identity-provider boundary (single sign-on / directory)

Single sign-on and directory provisioning (for example SAML, OpenID Connect, or
directory sync) are an external identity-provider integration, not built into
this binary. The integration point is explicit: an identity-provider subject
maps onto a skarbiec consumer (for machine access, via a minted grant) or onto a
recipient (for a human, via their public key). A future connector would
translate a verified provider identity into either a grant issuance or a
recipient registration; the vault already models both, so no engine change is
required to add that connector.

## Cryptographic model (summary)

- Each item is sealed to its recipient group (owner, recovery, and any shared
  users) via public-key encryption. Reading requires holding a recipient (or the
  recovery) matching private half.
- Master rotation re-encrypts to a fresh recipient group; full re-key generates
  a new sealing and re-encrypts every item and its history.
- Values are emitted only into owner-only files or an authorized API response,
  never into logs, prompts, or the audit journal.
