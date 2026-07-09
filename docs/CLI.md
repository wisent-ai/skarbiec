# CLI reference

Every command prints a JSON result to stdout. The vault path comes from
`SKARBIEC_VAULT_FILE` (default `skarbiec.vault.json`). Run `skarbiec help` for the
raw command list.

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
| `add-user <uid> [--import <pubkey-file>] [--role r]` | Register a recipient by uid; import their public key or generate one. |
| `users` | List registered recipients. |
| `export-key <uid>` | Print a recipient's armored public key (for sharing the vault). |
| `share <item-id> <uid>` | Re-encrypt an item to also include that recipient. |
| `revoke <item-id> <uid>` | Re-encrypt an item to the remaining recipients, dropping that uid. |

## Service-account grants

| Command | What it does |
| --- | --- |
| `token-mint <consumer> --scopes a,b` | Issue a scoped grant for a consumer. Only a hash is retained; the grant is shown once. |
| `token-verify <consumer> <item-id> --token T` | Check whether a presented grant authorizes that consumer for that item. |
| `token-revoke <consumer>` | Drop a consumer's grant. |
| `tokens` | List consumers and their scope globs (no grant values). |

A consumer resolves an item only by presenting a grant whose scope glob matches
the item id.

## Recovery and emergency access

| Command | What it does |
| --- | --- |
| `recovery-status` | Report which items carry the recovery recipient. |
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
