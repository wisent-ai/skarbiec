# Consumer

Who is on the other end of a machine read? A consumer: a named identity in
the vault's `tokens` section that authenticates without ever holding a
recipient key. Humans are recipients and decrypt; consumers are granted and
served.

## What it is

A consumer is one exact name — `[A-Za-z0-9._-]{1,128}`, refused otherwise
with `consumer must be one exact name` (`src/access/tokens.rs`) — mapping to
one [grant](grant.md) entry: capabilities, expiry, audience, and either a
bearer hash or a workload public key. Two shapes exist and cannot be mixed in
one grant (`acquire capabilities cannot share a grant with direct
capabilities`):

| Shape | Authenticates by | Standing secret |
| --- | --- | --- |
| Direct consumer | `X-Consumer` + `Authorization: Bearer <token>`; the vault compares SHA-256 hashes | The bearer, shown exactly once at mint |
| Acquisition identity | Ed25519 signature over a domain-separated, timestamped, nonced request | None — `"token": null` in the mint response |

The identity is always presented explicitly. Over HTTP, `X-Consumer` names
the consumer on every authenticated route; over the CLI, `--consumer` (for
`resolve`) or the first positional (for `acquisition-request`/`-read`) does.

## Lifecycle

1. **Mint** — `token-mint <consumer> --capabilities ...` creates or replaces
   the entry ([grant](grant.md));
   `invite <item> --field <field> --for <consumer>` mints an acquisition
   identity and additionally returns a non-secret redemption contract for
   the workload ([CLI reference](../CLI.md#workload-invitation)).
2. **Serve** — every call re-reads the live vault entry; there is no session,
   cache, or refresh token. Expiry is checked per call (`active()`).
3. **Widen** — `token-ensure-read` adds one read capability idempotently;
   any other change requires `--replace-capabilities true`.
4. **Revoke** — `token-revoke <consumer>` removes the entry. Revocation is
   immediate: the next call, including a correctly signed acquisition proof,
   is `unauthorized` — demonstrated in
   [the acquisition walkthrough](../walkthrough-acquisition-broker.md).

## Observing consumers

- `tokens` lists every consumer with capabilities, `workload_bound`,
  `audience`, and `expires_at` — never a bearer or hash.
- `POST /v1/tokens/introspect` answers what an inbound bearer is — identity
  and capabilities, never a value — for a gateway that holds a secret and
  nothing else. An unknown bearer and an expired one answer the same way, so
  the caller learns whether this credential is usable and nothing else about
  the vault (`src/access/tokens.rs::introspect`). The asking consumer needs an
  `introspect` capability; without one:
  `403 {"error":"consumer not authorized to introspect tokens"}`.
- `audit-query --consumer <name>` returns the consumer's journal trail
  ([WORM audit](worm-audit.md)).

## Well-known consumers

| Consumer | Held by |
| --- | --- |
| `skarbiec-browser-host` | The native-messaging host; minted by `browser-host-install` with only `read:login-*` eligibility ([SECURITY.md](../SECURITY.md#the-browser-boundary)). |
| `<mcp consumer>` | The MCP server's gate, named by `SKARBIEC_MCP_CONSUMER` ([configuration](../configuration.md#mcp-server)). |
| Weles writers | The credential lifecycle's exact writer identities; items they create are `management.mode = "external"` or `"managed"` and refuse other writers ([item](item.md#who-may-write-it)). |

## Invariants

- A consumer never decrypts. The broker process holding a recipient key
  decrypts one authorized field and serves it; copying the vault file plus
  every grant in it still yields nothing without a recipient private key.
- Consumer names are not secret; they ride in audit entries and refusal
  sentences. The bearer (direct shape) and private key (acquisition shape)
  are the secrets, and neither is stored in the vault.
- One consumer, one grant: there is no group, role, or inheritance. Two
  processes that need different fields are two consumers
  ([grants and consumers](../grants-and-consumers.md)).

## Not to be confused with

- **A recipient.** Recipients (`add-user`, `share`) hold `gpg` keys and can
  open ciphertext; consumers are served single fields under grant rules.
- **A workload id.** The acquisition proof carries a free-form `workload_id`
  (1–128 chars) naming the requesting process instance; the consumer is the
  granted identity the proof authenticates against
  ([capability token](capability-token.md)).
- **An audience.** `audience` is an advisory label on the grant (defaults to
  the consumer name); authorization always checks the consumer entry itself.
