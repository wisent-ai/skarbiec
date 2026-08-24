# HTTP API

`skarbiec serve [--port <n>]` starts the broker: a loopback-only HTTP
listener on `127.0.0.1`, port `8787` by default. Machine consumers, the
sync channel, the credential lifecycle, and the local operator console all
arrive here. There is no remote listener and no TLS termination in this
binary; the boundary is the loopback interface.

Consumer endpoints authenticate with two headers: `X-Consumer` naming the
consumer, and `Authorization: Bearer <token>` carrying its bearer. The
grant must carry the exact capability the route checks
([grants and consumers](grants-and-consumers.md)). Mutating routes
serialize process-wide behind a write lock; read-only routes stay parallel.

## Health

| Endpoint | What it does |
| --- | --- |
| `GET /health` | Opens a deterministic canary item (lowest live id) and drops the plaintext. Answers `{"ok":true,"service":"skarbiec"}`, or `503` with `error_code: infra_down` when stored ciphertext cannot be decrypted — a broker holding items it can no longer read is down however healthy its socket looks. |

## Items

| Endpoint | Capability | What it does |
| --- | --- | --- |
| `POST /v1/items/list` | `read` | Metadata for the items the consumer's `read` capabilities cover; never values. |
| `POST /v1/items/read` `{"id":..,"field":..}` | `read:<item>#<field>` | One decrypted field. A trashed item is `410 Gone` (`not_found`), a legacy envelope is `409 Conflict` (`config`), ciphertext that will not open is `503` (`infra_down`). An in-flight adopt candidate is refused with `409`. |
| `PUT /v1/items` `{"id":..,"field":..,"operation_id":..,"mode":..,"value":..}` | `stage:<item>#<field>` | Managed field write. `mode:"acquire"` creates a new Weles-managed item from a provider-verified canonical payload; `mode:"stage"` writes one field of an item this exact Weles writer controls. Lifecycle-owned records and items another writer controls are refused. |
| `DELETE /v1/items` `{"id":..}` | `trash:<item>` | Soft-delete. Refused for items owned by the credential lifecycle or not controlled by an authority this consumer speaks for. |
| `POST /v1/tokens/introspect` | `introspect` | What an inbound bearer is: an identity and its capabilities, never a value. |

Every `error_code` comes from the fleet's failure package,
[`wisent-errors`](https://github.com/wisent-ai/wisent-errors), pinned by
commit in `Cargo.toml`; Skarbiec emits `not_found`, `config`, and
`infra_down`. Statuses and the 400-character `detail` bound are Skarbiec's
own.

## Acquisitions

The one-time field surface ([grants and consumers](grants-and-consumers.md#acquisition-grants-no-standing-secret)):

| Endpoint | What it does |
| --- | --- |
| `POST /v1/acquisitions` | `X-Consumer` plus the Ed25519 proof fields; no standing bearer is sent. Verifies the signed workload proof and issues an opaque short-TTL bearer bound to workload, consumer, item, and field. |
| `POST /v1/acquisitions/read` `{"id":..,"field":..}` | With the issued bearer: returns only the bound field and atomically consumes the bearer before the value is returned. Replay, expiry, or a binding mismatch is `401 unauthorized`. |

## Credential lifecycle

| Endpoint | Capability | What it does |
| --- | --- | --- |
| `POST /v1/credential/operations` | `lifecycle:<item>` | Submit or resume one operation. The body carries no directory identity and no provider — both come from the sealed item contract. `adopt` is refused here because its password only exists on operator stdin. |
| `GET /v1/credential/operations/<item-id>` | `lifecycle:<item>` | The persisted state of that item's operation, with its receipt and quarantine block. The poll can commit a staged revision, so it serializes with every other writer. |

`lifecycle` never authorizes reading a credential value. The full lifecycle
contract is in
[the CLI reference](CLI.md#externally-managed-credentials-through-weles).

## Sync, donations, enrollment

The bond serve channel ([CLI reference](CLI.md#synchronization-bonds-donations-and-invitations)):

| Endpoint | Capability | What it does |
| --- | --- | --- |
| `GET /v1/vault` | `sync:pull` | The whole ciphertext vault document; items are served exactly as stored and never decrypted here. |
| `GET /v1/owner-pubkey` | none | The vault owner's armored public key, so a donor can seal a donation to this vault; the public half is not secret. |
| `POST /v1/donations` | `donate:<item-id>` | Enqueue one sealed item into the donation inbox; the owner merges with `donation-accept`. An existing id admits the donation only when its `written_by` matches the donor's `from` claim. |
| `POST /v1/enroll` | `enroll:<uid>` | A replica sends its armored public key and item ids; the source registers the key and re-seals exactly those items to it. |

## Compatibility

| Endpoint | What it does |
| --- | --- |
| `GET /list` | Item metadata, no authentication beyond the loopback boundary. |
| `GET /audit` | Item count summary. |
| `POST /resolve` | Grant-gated login resolution; the emitted values land in an owner-only file, per [`resolve`](CLI.md#runtime-injection). |

## Operator routes

`/v1/operator/` is reserved whole for the local operator console (the
desktop app). Every route is `POST` with a JSON body; a body may name its
vault in an optional `vault` member, applied for exactly that request. The
trust model: the listener is loopback-only, and each route carries exactly
the authority that invoking the binary on this machine already carries —
the local keyring decides what opens either way. What the surface
deliberately does not carry is a value: `get`, `export`, and `resolve` are
absent, and `grants/mint` strips the bearer from its answer (the vault
keeps only the digest).

Reads: `items`, `recipients`, `audit`, `audit-query`, `chain`, `policy`,
`grants`, `doctor`, `status`, `vaults`, `donations`, `emergency`,
`recovery`, `key-doctor`, `bonds`, `version`, `routes/list`,
`routes/verify`.

Mutations: `vaults/create`, `items/trash`, `items/reclaim`,
`items/restore`, `items/purge`, `items/share`, `items/revoke`,
`recipients/add`, `grants/mint`, `grants/revoke`, `donations/accept`,
`donations/reject`, `credential` (operations `status`, `acquire`, `rotate`,
`resume`, always against this vault file), `emergency/grant`,
`emergency/cancel`, `emergency/activate`, `recovery/drill`, `policy/set`,
`sync/init`, `sync/push`, `sync/pull`, `routes/add`, `routes/reconcile`.

Every handler delegates to the same dispatcher the matching CLI command
uses, so a console and an operator reading the same vault cannot drift.

## Other server surfaces

Beside `serve`, the binary exposes a stdio MCP server (`skarbiec mcp`) with
metadata, audit, and a tightly gated `resolve` — no raw reads, minting, or
export ([SECURITY.md](SECURITY.md#the-mcp-boundary-is-tighter-than-the-cli))
— and a length-framed browser native-messaging bridge
(`skarbiec native-host`) that alone holds the browser consumer's token and
calls this loopback API
([SECURITY.md](SECURITY.md#the-browser-boundary)).
