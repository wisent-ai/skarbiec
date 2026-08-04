# CLI reference

Every command prints a JSON result to stdout. The vault path comes from
`SKARBIEC_VAULT_FILE` (default `~/.local/share/skarbiec/skarbiec.vault.json`). Run
`skarbiec help` for the raw command list.

Flags are `--key value` or bare `--flag`; everything else is positional.

## Vault items

| Command | What it does |
| --- | --- |
| `init <owner-uid>` | Create the vault, sealed to a fresh `gpg` owner key and a `skarbiec-recovery <owner>` key. |
| `set <id> --type <t> --field k=v ... [--recipients a,b] [--tags x,y]` | Create or update a schema-validated typed item. `--type` defaults to `login`; canonical field names depend on the type. |
| `get <id>` | Return one item's decrypted fields as JSON. |
| `list [--all]` | List item metadata (id, type, revision count, tags) — never values. `--all` includes trashed items. |
| `delete <id>` | Move an item to the trash (recoverable). |
| `restore <id>` | Bring a trashed item back. |
| `purge <id>` | Permanently remove a trashed item. |
| `restore-version <id> <at>` | Roll an item back to an earlier version by its timestamp. |

```sh
skarbiec set github --type login --field username=alice@example.com --tags dev,ci
skarbiec list --all
skarbiec restore-version github 2026-07-01T12:00:00Z
```

## Externally managed credentials through Weles

| Command | What it does |
| --- | --- |
| `credential acquire <item-id> --provider <provider> --consumer <consumer> [--account <email>] [--purpose <purpose>] [--dry-run]` | Acquire or adopt one exact allowlisted provider credential. A pre-existing local item without Weles provenance is rejected rather than reported as ready. |
| `credential rotate <item-id> --provider <provider> --consumer <consumer> [--account <email>] [--purpose <purpose>] [--dry-run]` | Ask Weles to rotate the credential at the provider, freshly authenticate it, and commit the exact value to Skarbiec. |
| `credential verify <item-id> --provider <provider> --consumer <consumer> [--account <email>] [--purpose <purpose>] [--dry-run]` | Ask Weles to authenticate the stored value at the provider. A successful check rewrites the same value with the operation request ID as provenance. |
| `credential remove <item-id> --provider <provider> --consumer <consumer> [--account <email>] [--purpose <purpose>] [--dry-run]` | Request provider-side revocation and local removal. Providers without a safe revocation contract fail closed. |
| `credential status <item-id>` | Poll the exact Weles action-log ID, persist queued/failure/review/completed state, and verify that the current encrypted item is attributable to that request. A merely present item is `managed` or `unmanaged`, never externally verified. |

`SKARBIEC_WELES_CREDENTIAL_COMMAND` must name an absolute,
owner-controlled, non-symlink executable. Skarbiec passes
`skarbiec.credential-operation.v1` JSON on stdin and accepts only a bounded,
sanitized JSON response on stdout. The bridge owns the finite mapping from item
IDs to Weles lifecycle contracts; an unknown item/provider/operation tuple fails
closed.

Install the bridge from the public
[`wisent-ai/weles-client`](https://github.com/wisent-ai/weles-client)
repository, then configure the organization-scoped hosted service values:

```sh
git clone https://github.com/wisent-ai/weles-client
npm install --global ./weles-client

export WELES_URL=https://weles.wisent.com/api/v1/
export WISENT_ORGANIZATION_ID=<organization-uuid>
export WELES_TOKEN=<organization-scoped-token>
export SKARBIEC_WELES_CREDENTIAL_COMMAND="$(npm root --global)/@wisent-ai/weles-client/bin/weles-skarbiec-acquire.mjs"

skarbiec credential rotate weles-microsoft-primary-password \
  --provider microsoft \
  --consumer support-ops \
  --account owner@example.com \
  --purpose incident-remediation

skarbiec credential status weles-microsoft-primary-password
```

The Snapchat contract writes canonical field `api_key` to
`weles-snapchat-snap-kit-api`. Before queueing a real acquisition, provision
the Weles host with the exact `stage:weles-snapchat-snap-kit-api#api_key`
capability in the owner-only writer token file; no broader writer or global
bearer is accepted.

Microsoft password rotation and verification use item IDs matching
`weles-microsoft-<account-alias>-password`; the exact account is independently
bound by `--account`. Weles writes canonical `username` and `password` fields,
plus protected request and operation metadata through item-specific `stage`
capabilities. It changes the provider first, performs a fresh password
authentication, and only then writes the managed item. MFA or passkey challenges
stop as `needs_human_approval` without changing Skarbiec.

Once an item carries Weles provenance, owner-side `set`, `set-json`, `delete`,
`restore`, `purge`, `restore-version`, and import overwrites are refused. Use
the matching `credential` lifecycle operation so local and provider state
cannot be changed independently.

## Recipients and sharing

| Command | What it does |
| --- | --- |
| `add-user <uid> [--import <pubkey-file>] [--role r]` | Register a recipient by uid; import their public key or generate one. Registering does **not** re-encrypt items already stored — use `share` to grant those. Refused for `--role owner`, which would leave an owner holding a key that opens nothing. |
| `users` | List registered recipients. |
| `export-key <uid>` | Print a recipient's armored public key (for sharing the vault). |
| `share <item-id> <uid>` | Re-encrypt an item to also include that recipient. |
| `revoke <item-id> <uid>` | Re-encrypt an item to the remaining recipients, dropping that uid. |
| `rotate-owner <uid>` | Install a new owner: rewrap every current and historical ciphertext onto that uid's key, keep the recovery recipient, and report the item and version counts. This is the only correct way to change owner. |

## Service-account grants

| Command | What it does |
| --- | --- |
| `token-mint <consumer> --capabilities action:item[#field] [--workload-public-key-file PATH]` | Register exact structured capabilities. `acquire`, `stage`, `rotate`, and `verify` require a field. `acquire` requires an Ed25519 workload public key and returns no standing bearer; direct capabilities return a bearer once and retain only its hash. Replacing an existing capability set requires `--replace-capabilities`. |
| `token-register-acquisitions <absolute-catalog> --workload-public-key-file PATH [--ttl-seconds N] [--replace-capabilities]` | Atomically register a validated `consumer\|item\|field` catalog as workload-bound `acquire` capabilities. |
| `token-verify <consumer> <resource> --action ACTION [--field FIELD] --token T` | Check one exact action/resource/field binding. |
| `token-revoke <consumer>` | Drop a direct grant or acquisition workload identity. |
| `tokens` | List consumers, structured capabilities, expiry, audience, and whether each identity is workload-bound. |
| `acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX` | Verify an Ed25519 workload proof and issue an opaque short-TTL bearer bound to that workload, consumer, item, and field. |
| `acquisition-read <consumer> <item> <field> --token T` | Return only the bound field and atomically consume the acquisition bearer. Replay, expiry, or a binding mismatch is unauthorized. |

Acquisition identities have no standing bearer hash and only `acquire`
capabilities, so they cannot read or list an item directly. The operator registers an owner-controlled PEM
public key; the workload retains only its matching private key. Each request
signs the domain-separated consumer, item, field, workload id, epoch timestamp,
and random nonce. Skarbiec verifies the signature, rejects proofs outside the
short clock window, and records accepted nonce hashes until replay is impossible.
Each acquisition request and response names exactly one field. Issued bearer
hashes live in an owner-only acquisition state file; a successful read removes
the hash under an exclusive state lock before the value is returned.
`SKARBIEC_ACQUISITION_TTL_SECONDS` may set the nonsecret TTL from one through
300 seconds; the default is 30.

HTTP clients use `POST /v1/acquisitions` with `X-Consumer` and the proof fields,
then immediately call `POST /v1/acquisitions/read` with the one-time bearer.
No standing authorization bearer is sent on the issue request.

The complete executable proof is
[`examples/acquire-one-field.sh`](examples/acquire-one-field.sh). It generates
an isolated Ed25519 workload key, signs the exact domain-separated payload,
consumes the returned field once, repeats the same read to demonstrate
`unauthorized`, and prints the corresponding audit records.

## Recovery and emergency access

| Command | What it does |
| --- | --- |
| `key-doctor` | Whether any key on this machine can still open the vault, and if not, the exact `private-keys-v1.d/<KEYGRIP>.key` files a restore has to produce. Reads the vault document and the keyring directly, never the HTTP API, so it answers while the service is down. Opens a deterministic canary item as proof and discards the plaintext. |
| `recovery-status` | Report the recovery recipient, the item count it covers, and whether its secret half is on this machine — which it should not be, since offline material sharing a keyring with the owner key is one failure domain, not two. |
| `recovery-drill <recipient-uid\|recovery>` | In an isolated recovery keyring, require exactly the named vault opener, decrypt and discard a deterministic live canary, and append the pass/fail evidence to the audit chain. Use a separate `GNUPGHOME` on the custodian machine. |
| `emergency-grant <grantee> --activate-after <iso>` | Arrange a time-delayed share to a trusted user. |
| `emergency-list` | List pending emergency grants. |
| `emergency-cancel <grantee>` | Cancel a pending emergency grant before it activates. |
| `emergency-activate <grantee>` | Activate an emergency grant once its moment has passed. |

## Policy

| Command | What it does |
| --- | --- |
| `policy-set <key> <value>` | Set an admin rule (for example, a minimum generated length). |
| `policy-get` | Print the current policy. |
| `policy-check-length <candidate>` | Check a candidate string against the length rule. |

## Audit

| Command | What it does |
| --- | --- |
| `audit` | Print the complete append-only journal. |
| `audit-query [--op OP] [--consumer ID] [--item ID] [--since ISO] [--until ISO] [--limit N]` | Query local provenance by operation, workload consumer, item, and time window. Returns the newest matching bounded slice in chronological order. |
| `verify-chain` | Verify the hash chain; report any retroactive edit. |

## Runtime injection

| Command | What it does |
| --- | --- |
| `resolve <platform> [--consumer c --token t] [--emit --out dir]` | Resolve one item's canonical login mapping. With `--emit`, the values land in an owner-only (mode-0600) env file and the command returns only its path plus the exported variable NAMES; values never reach stdout. Gated by the consumer grant when `--consumer` is given. |
| `expand <template> --out <file>` | Copy a template to `--out`, replacing each `NAME=skarbiec://<id>/<field>` line with the resolved value. The output file is written mode-0600. |

```sh
skarbiec resolve github --consumer ci --token "$GRANT" --emit --out /run/ci
# -> { "status": "ready", "out_file": "/run/ci/github.env", "names": ["ADMIN_EMAIL", ...] }
```

## Utilities

| Command | What it does |
| --- | --- |
| `version` | Report the crate version and the versioned, provenance-stamped release coordinate the artifact was built for. A source build says so instead of guessing, so a supervisor never has to identify a build by counting the commands it answers. |
| `generate --length N [--symbols]` | Generate a login string of length N from OS entropy. |
| `generate --passphrase --words N` | Generate an N-word passphrase. |
| `totp <item-id>` | Print the current one-time code from an item's saved seed (needs `oathtool`). |
| `breach-check <item-id> [--field password]` | Check a field against the breach corpus under k-anonymity (only a hash prefix leaves the host). |

## Sync

| Command | What it does |
| --- | --- |
| `sync-init <remote-url>` | Point sync at a git remote for the encrypted file. |
| `sync-push` | Push the encrypted vault to the remote. |
| `sync-pull` | Pull the encrypted vault from the remote. |

Only ciphertext crosses the wire.

## Servers

| Command | What it does |
| --- | --- |
| `serve [--port <n>]` | Start the loopback HTTP API (see [ARCHITECTURE.md](ARCHITECTURE.md)). |
| `mcp` | Start the stdio Model Context Protocol server for agents. |
| `native-host` | Run the length-framed browser native-messaging bridge. |
| `browser-host-install [--binary <path>]` | Rotate the narrow browser grant and atomically register the installed native host. |

See [SECURITY.md](SECURITY.md) for how `resolve`, grants, and the servers are gated.

## Examples

Executable examples live in [`examples/`](examples/README.md). Start with the
default workload path:

1. [Acquire one exact field once](examples/acquire-one-field.sh)
2. [Create a vault](examples/create-skarbiec.sh)
3. [Create three isolated vaults](examples/create-three-skarbiecs.sh)
4. [Rotate the owner](examples/rotate-skarbiec-owner.sh)
5. [Share a credential with another recipient](examples/sharing/share-credential-with-user.sh)
