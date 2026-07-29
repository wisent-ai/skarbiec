# CLI reference

Every command prints a JSON result to stdout. The vault path comes from
`SKARBIEC_VAULT_FILE` (default `~/.stado/skarbiec.vault.json`). Run
`skarbiec help` for the raw command list.

Flags are `--key value` or bare `--flag`; everything else is positional.

## Vault items

| Command | What it does |
| --- | --- |
| `init <owner-uid>` | Create the vault, sealed to a fresh `gpg` owner key and a `skarbiec-recovery <owner>` key. |
| `set <id> --type <t> --field k=v ... [--recipients a,b] [--tags x,y]` | Create or update an item. Fields are free-form `key=value` pairs; `--type` defaults to `login`. |
| `get <id>` | Return one item's decrypted fields as JSON. |
| `list [--all]` | List item metadata (id, type, revision count, tags) — never values. `--all` includes trashed items. |
| `delete <id>` | Move an item to the trash (recoverable). |
| `restore <id>` | Bring a trashed item back. |
| `purge <id>` | Permanently remove a trashed item. |
| `restore-version <id> <at>` | Roll an item back to an earlier version by its timestamp. |

```sh
skarbiec set github --type login --field login_email=alice@example.com --tags dev,ci
skarbiec list --all
skarbiec restore-version github 2026-07-01T12:00:00Z
```

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
| `token-mint <consumer> --scopes a,b` | Issue a direct scoped grant for a consumer. Scopes are `read:<glob>`, `write:<glob>`, or `delete:<glob>`; a legacy bare glob is read-only. Only a hash is retained; the grant is shown once. |
| `token-mint <consumer> --acquisition-scopes item#field` | Issue a request-only bootstrap grant for one exact existing item field. Direct and acquisition scopes cannot be combined. Wildcards and globs are rejected. |
| `token-verify <consumer> <item-id> --token T` | Check whether a presented direct grant authorizes read access to that item. |
| `token-revoke <consumer>` | Drop a consumer's grant. |
| `tokens` | List consumers and direct/acquisition scope metadata (no grant values). |
| `acquisition-request <consumer> <item> <field> --token T` | Exchange an authorized bootstrap grant for an opaque short-TTL bearer bound to that consumer, item, and field. |
| `acquisition-read <consumer> <item> <field> --token T` | Return only the bound field and atomically consume the acquisition bearer. Replay, expiry, or a binding mismatch is unauthorized. |

Bootstrap grants have an empty direct-scope list, so they cannot read or list an
item. Each acquisition request and response names exactly one field. Issued
bearer hashes live in an owner-only acquisition state file; a successful read
removes the hash under an exclusive state lock before the value is returned.
Failed binding checks do not broaden or consume the bearer; expired bearers are
removed and rejected. `SKARBIEC_ACQUISITION_TTL_SECONDS` may set the nonsecret
TTL from one through 300 seconds; the default is 30.

The loopback item API retains existing action/item scope behavior. Acquisition
clients use `POST /v1/acquisitions` followed immediately by
`POST /v1/acquisitions/read`, with `X-Consumer` and the applicable bearer.

## Recovery and emergency access

| Command | What it does |
| --- | --- |
| `key-doctor` | Whether any key on this machine can still open the vault, and if not, the exact `private-keys-v1.d/<KEYGRIP>.key` files a restore has to produce. Reads the vault document and the keyring directly, never the HTTP API, so it answers while the service is down. Opens a deterministic canary item as proof and discards the plaintext. |
| `recovery-status` | Report the recovery recipient, the item count it covers, and whether its secret half is on this machine — which it should not be, since offline material sharing a keyring with the owner key is one failure domain, not two. |
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
| `audit` | Print a summary of the append-only journal. |
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
| `version` | Report the crate version, and the immutable release coordinate the artifact was published at. A source build says so instead of guessing, so a supervisor never has to identify a build by counting the commands it answers. |
| `generate --length N [--symbols]` | Generate a login string of length N from OS entropy. |
| `generate --passphrase --words N` | Generate an N-word passphrase. |
| `totp <item-id>` | Print the current one-time code from an item's saved seed (needs `oathtool`). |
| `breach-check <item-id> [--field login_password]` | Check a field against the breach corpus under k-anonymity (only a hash prefix leaves the host). |

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

See [SECURITY.md](SECURITY.md) for how `resolve`, grants, and the servers are gated.
