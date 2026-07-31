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

## Credential acquisition through Weles

| Command | What it does |
| --- | --- |
| `credential acquire <item-id> --provider <provider> --consumer <consumer> [--purpose <purpose>] [--dry-run]` | Ask the fixed Weles bridge to acquire one exact allowlisted credential. An existing live item returns `ready`; a duplicate pending request returns the original request. The request and Weles job identifiers are encrypted in `request:credential/<item-id>`; secret values never enter the request or audit journal. |
| `credential status <item-id>` | Return `pending`, `failed`, or `ready`. Once the exact item exists, the pending request is retired. |

`SKARBIEC_WELES_ACQUIRE_COMMAND` must name an absolute, owner-controlled,
non-symlink executable. Skarbiec passes
`skarbiec.credential-request.v1` JSON on stdin and accepts only a bounded,
sanitized JSON response on stdout. The bridge owns the finite mapping from item
IDs to Weles acquisition contracts; an unknown item/provider pair fails closed.

```sh
export SKARBIEC_WELES_ACQUIRE_COMMAND="$HOME/weles/scripts/secrets/skarbiec-acquire.mjs"

skarbiec credential acquire weles-snapchat-snap-kit-api \
  --provider snapchat \
  --consumer content-platform \
  --purpose snap-kit-production

skarbiec credential status weles-snapchat-snap-kit-api
```

The Snapchat contract writes field `api_token` to
`weles-snapchat-snap-kit-api`. Before queueing a real acquisition, provision
the Weles host with the exact writer grant in the owner-only file
`~/.stado/weles-snapchat-snap-kit-api-writer-skarbiec-token`; no broader writer
or global bearer is accepted.

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
| `token-mint <consumer> --scopes a,b` | Issue a legacy direct scoped bearer for a consumer. Scopes are `read:<glob>`, `write:<glob>`, or `delete:<glob>`; a legacy bare glob is read-only. Only a hash is retained; the bearer is shown once. |
| `token-mint <consumer> --acquisition-scopes item#field --workload-public-key-file PATH` | Register a request-only workload identity for one exact existing item field. The output token is null: the private workload signing key, not a standing bearer, authenticates acquisitions. Direct and acquisition scopes cannot be combined. |
| `token-verify <consumer> <item-id> --token T` | Check whether a presented legacy direct grant authorizes read access to that item. |
| `token-revoke <consumer>` | Drop a direct grant or acquisition workload identity. |
| `tokens` | List consumers, direct/acquisition scope metadata, and whether acquisition is workload-bound (no bearer or key material). |
| `acquisition-request <consumer> <item> <field> --workload-id ID --workload-timestamp EPOCH --workload-nonce NONCE --workload-signature HEX` | Verify an Ed25519 workload proof and issue an opaque short-TTL bearer bound to that workload, consumer, item, and field. |
| `acquisition-read <consumer> <item> <field> --token T` | Return only the bound field and atomically consume the acquisition bearer. Replay, expiry, or a binding mismatch is unauthorized. |

Acquisition identities have an empty direct-scope list and no bearer hash, so
they cannot read or list an item. The operator registers an owner-controlled PEM
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
| `native-host` | Run the length-framed browser native-messaging bridge. |
| `browser-host-install [--binary <path>]` | Rotate the narrow browser grant and atomically register the installed native host. |

See [SECURITY.md](SECURITY.md) for how `resolve`, grants, and the servers are gated.

## Stan operacyjny (2026-07-28, po incydencie rotacji)

Aktywny vault: `~/.stado/brama-runtime-config/local.vault.json` (383 itemy).
Klucz właściciela: `skarbiec-owner-20260728 <lukasz.bartoszcze@wisent.ai>`;
fraza w `~/.skarbiec-unlock` (600); eksport recovery:
`~/.skarbiec-recovery-20260728.asc` (do trzymania poza maszyną). Stary vault
`~/.stado/skarbiec.vault.json` (378 itemów) jest zasealowany na utracone
klucze i pozostaje archiwum.

Codzienna praca:

```sh
export SKARBIEC_BIN=~/Documents/CodingProjects/Wisent/skarbiec/target/release/skarbiec
export SKARBIEC_VAULT_FILE=~/.stado/brama-runtime-config/local.vault.json
export SKARBIEC_UNLOCK_FILE=~/.skarbiec-unlock
skarbiec list | get <id> [--field f] | set <id> --type t pole=v | audit
```

Aplikacje trzymają w configach referencje `skarbiec://<item>/<pole>`,
rozwiązywane przez CLI przy starcie (np. `game_asset_creator/pipeline.config.json`).
Konsument HTTP: launchd `com.wisent.skarbiec` (tokeny z zakresami `read:<item>`).
Brama (model-router) czyta subskrypcje z Supabase, nie z vaulta; Weles trzyma
kopię `platform-admin-*` w vaultcie przy źródle w tabelach Supabase Weles.

Zasady pożarowe po incydencie:

1. Rotacja wyłącznie przez `rotate-owner` (re-szyfruje wszystko), nigdy przez
   `add-user --role owner` (zabronione przez CLI).
2. Przed rotacją: eksport klucza offline + testowy decrypt poza sesją.
3. Recovery (`75709EF1…`, pusta fraza) — eksport `.asc` poza maszyną.
4. Wartości tylko przez stdin/pliki/zmienne — nigdy inline w komendach.
5. Braki po incydencie: `~/.stado/brama-runtime-config/still-missing.txt`.

## Examples — skarbiec w praktyce

Praktyczne przykłady mieszkają w folderze [`examples/`](examples/README.md):

1. [create-skarbiec.sh](examples/create-skarbiec.sh)
2. [create-three-skarbiecs.sh](examples/create-three-skarbiecs.sh)
3. [rotate-skarbiec-owner.sh](examples/rotate-skarbiec-owner.sh)
4. [add-credential.sh](examples/add-credential.sh)
5. [sharing/share-credential-with-user.sh](examples/sharing/share-credential-with-user.sh)
