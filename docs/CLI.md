# CLI reference

`skarbiec` is a JSON-first command-line interface. Finite commands print one
JSON value to stdout. `serve`, `mcp`, `native-host`, and `sync-daemon` are
long-running process interfaces instead. Commands that return a credential
(`get`, `acquisition-read`, `totp`) necessarily place that value in their JSON
response; metadata-only reads such as `list`, `status`, `tokens`, and `bonds`
never do.

The vault path comes from `SKARBIEC_VAULT_FILE` and defaults to
`~/.local/share/skarbiec/skarbiec.vault.json`. Git synchronization uses
`SKARBIEC_SYNC_DIR` and defaults to `~/.skarbiec-sync`.

Arguments use this grammar:

```text
skarbiec <command> [positionals...] [--key value | --key=value] [--flag]
```

Flags are single-valued: if a flag is repeated, the last value wins. Commands
that accept several values use comma-separated flags or positional values.
In particular, fields passed to `set` are positional `name=value` arguments,
not repeated `--field` flags.

Run `skarbiec help` for the machine-readable public command inventory. The
current contract contains the following 64 command names:

```text
Vault:       status init set set-json get list delete restore purge
             restore-version
Data:        generate import migrate-v2
Recipients:  add-user rotate-owner share revoke users export-key
Access:      token-mint token-revoke token-verify tokens
             acquisition-request acquisition-read
Recovery:    key-doctor recovery-status recovery-drill emergency-grant
             emergency-cancel emergency-list emergency-activate
Policy:      policy-set policy-get policy-check-length
Audit:       audit audit-query verify-chain
Runtime:     resolve expand totp breach-check
Sync:        sync-init sync-push sync-pull pull donate donations
             donation-accept donation-reject enroll sync-daemon sync-status
             invite bond-add bond-list bond-remove bonds
Credentials: credential
Servers:     serve mcp native-host browser-host-install
Build:       version
```

## Vault items

| Command | What it does |
| --- | --- |
| `status` | Return the vault path and counts of items, recipients, tokens, and bonds, plus the recovery fingerprint and whether its secret key is present locally. |
| `init <owner-uid>` | Create the vault, sealed to a fresh `gpg` owner key and a `skarbiec-recovery <owner>` key. |
| `set <id> [--type <t>] name=value ... [--recipients a,b] [--tags x,y]` | Create or update a schema-validated typed item. `--type` defaults to `login`; canonical field names depend on the type. |
| `set-json <id> [--type <t>] [--recipients a,b] [--tags x,y]` | Read one canonical item payload from stdin, validate its `kind` and fields, and create or update the item. `--type` overrides the payload's `kind` only when both describe the same valid schema. |
| `get <id>` | Return one item's decrypted fields as JSON. |
| `list [--all]` | List item metadata (id, type, revision count, tags)—never values. `--all` includes trashed items. |
| `delete <id>` | Move an item to the trash (recoverable). |
| `restore <id>` | Bring a trashed item back. |
| `purge <id>` | Permanently remove a trashed item. |
| `restore-version <id> <at>` | Roll an item back to an earlier version by its timestamp. |

```sh
skarbiec set github --type login \
  username=alice@example.com password=correct-horse-battery-staple \
  --tags dev,ci
printf '%s\n' '{"kind":"token","token":"value-from-stdin"}' |
  skarbiec set-json deployment-token
skarbiec list --all
skarbiec restore-version github 2026-07-01T12:00:00Z
```

`managed:weles` is a reserved tag. Once an item has authenticated Weles
provenance, direct owner mutation is refused; use the `credential` lifecycle
described below.

## Import and migration

| Command | What it does |
| --- | --- |
| `import <file.json>` | Import a JSON array of canonical rows. Each row requires `id` and `payload`; `recipients` and `tags` are optional arrays. Rows without `id` are counted as skipped. Schema-invalid rows, reserved Weles state, and attempts to overwrite a Weles-managed item fail closed. |
| `migrate-v2 [--snapshot PATH]` | Copy the current vault to a new mode-0600 snapshot and migrate the live document to v2. The default snapshot is `<vault>.pre-v2.<epoch>`. An existing snapshot path is never overwritten. |

Canonical import shape:

```json
[
  {
    "id": "deployment-token",
    "payload": {
      "kind": "token",
      "token": "value"
    },
    "recipients": [],
    "tags": ["production"]
  }
]
```

`import` is not a legacy-format detector. Convert legacy data explicitly with
`migrate-v2` before importing canonical rows.

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
| `token-mint <consumer> --capabilities action:item[#field] [--workload-public-key-file PATH] [--ttl-seconds N] [--audience NAME] [--replace-capabilities]` | Register exact structured capabilities. `acquire`, `stage`, `rotate`, and `verify` require a field. `acquire` requires an Ed25519 workload public key and returns no standing bearer; direct capabilities return a bearer once and retain only its hash. The TTL defaults to 30 days and the audience to the consumer. Replacing a different existing capability set requires `--replace-capabilities`. |
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
| `generate --passphrase --words N [--separator TEXT]` | Generate an N-word passphrase. The separator defaults to `-`. |
| `totp <item-id>` | Print the current one-time code from an item's saved seed (needs `oathtool`). |
| `breach-check <item-id> [--field password]` | Check a field against the breach corpus under k-anonymity (only a hash prefix leaves the host). |

## Synchronization, bonds, donations, and invitations

All synchronization moves the encrypted vault document or an item sealed to
the destination owner. It never merges two whole vault files. Pull operations
therefore protect against obvious local-item loss and require an explicit
`--force` to cross the documented regression guard.

### Git synchronization

| Command | What it does |
| --- | --- |
| `sync-init <remote-url>` | Initialize `SKARBIEC_SYNC_DIR` as a Git repository and replace its `origin` with the exact remote URL. |
| `sync-push [--branch NAME] [--message TEXT]` | Copy the live vault to `vault.enc.json`, commit it, and push it. The branch defaults to `main`; the message defaults to `skarbiec sync`. A no-op commit is allowed. |
| `sync-pull [--branch NAME] [--force]` | Pull `vault.enc.json`, back up the live vault, and replace it. Without `--force`, refuse when live non-trashed item IDs are absent from the mirror. |

`sync-pull` creates `<vault>.pre-pull-<timestamp>` before its regression check.
The reported backup remains available whether the replacement proceeds or is
refused.

### Serve-channel replication

| Command | What it does |
| --- | --- |
| `pull --from <base-url> --token <token> [--consumer NAME] [--bond NAME] [--force]` | Fetch `GET /v1/vault` using the exact `sync:pull` grant and atomically replace the local vault. `--consumer` defaults to `replica`. The local `bond` registry is retained. Without `--force`, a remote vault with fewer item records is refused. |
| `enroll --as <uid> --to <base-url> --token <token> [--items a,b,c] [--consumer NAME]` | Send the local owner's public key to the source using the exact `enroll:<uid>` grant. The source registers `uid` and re-seals exactly the named items to that recipient. `--consumer` defaults to `enroll`; the next `pull` brings the re-sealed ciphertext to the replica. |
| `sync-daemon --bond <name> --token <token> [--consumer NAME]` | Repeatedly run serve-channel pulls using the bond's address and `interval_seconds`. It handles SIGTERM and reports the last pull when it exits. A service manager must provide persistence. |
| `sync-status [--bond <name>] [--token <token>] [--consumer NAME]` | Return per-bond configuration, last-pull state, local item count, and serve-channel health. Supplying a token also permits the remote item count to be read. `--consumer` defaults to `replica`. |

The source must run `skarbiec serve`. `pull` requires `sync:pull`; `enroll`
requires `enroll:<uid>`, where `<uid>` exactly equals the value passed to
`--as`. Both are direct capabilities minted on the source vault:

```sh
skarbiec token-mint replica --capabilities sync:pull
skarbiec token-mint enroll --capabilities enroll:replica-1
```

### Bond registry

| Command | What it does |
| --- | --- |
| `bond-add <name> --mode <mode> --role <role> --channel <type:address> [--peers fpr,fpr] [--interval SECONDS]` | Create or replace non-secret bond configuration in the vault. Modes: `replica`, `hub`, `p2p`, `git`. Roles: `source`, `replica`, `consumer`, `peer`. Channel types: `serve`, `git`, `file`. |
| `bond-list` | Return the complete bond registry. |
| `bonds` | Alias of the read-only `bond-list`. |
| `bond-remove <name>` | Remove one named bond and append the mutation to the audit chain. It does not modify vault items. |

`sync-daemon` requires a bond whose channel contains both an address and
`interval_seconds`; define the latter with `bond-add --interval`.

### Item donations

| Command | What it does |
| --- | --- |
| `donate <item-id> --to <base-url> --consumer <name> --token <token> [--from WRITER]` | Fetch the destination owner's public key, decrypt the local item, re-encrypt its canonical payload to that owner, and enqueue it remotely using the exact `donate:<item-id>` grant. `--from` defaults to the token consumer. |
| `donations` | List pending donation metadata without returning armored or plaintext payloads. |
| `donation-accept <donation-id>` | Recheck provenance, decrypt the queued payload, and append or overwrite the item when the donor is allowed to do so. |
| `donation-reject <donation-id>` | Remove a pending donation without modifying the vault. |

Inbound donations are review-first. A new item ID may be appended. An existing
ID may be overwritten only when its `written_by` matches the donation's `from`;
older items without provenance reject the collision. The destination vault must
mint a direct capability for the exact donated item and consumer:

```sh
skarbiec token-mint donor --capabilities donate:shared-item
```

### Workload invitation

| Command | What it does |
| --- | --- |
| `invite <item> --field <field> --for <consumer> --workload-public-key-file PATH` | Register one exact workload-bound `acquire:<item>#<field>` capability and return a non-secret redemption contract. The file must be an owner-controlled regular file containing an Ed25519 PEM public key. |

The invitation never contains the field value or a standing bearer. The
workload signs an acquisition proof and then uses `acquisition-request` followed
by the one-use `acquisition-read`.

## Servers

| Command | What it does |
| --- | --- |
| `serve [--port <n>]` | Start the loopback HTTP API (see [ARCHITECTURE.md](ARCHITECTURE.md)). |
| `mcp` | Start the stdio Model Context Protocol server for agents. |
| `native-host` | Run the length-framed browser native-messaging bridge. |
| `browser-host-install [--binary <path>]` | Rotate the narrow browser grant and atomically register the installed native host. |

See [SECURITY.md](SECURITY.md) for how `resolve`, grants, and the servers are gated.

## Examples

Executable examples live in [`examples/`](examples/README.md). They are plain
command sequences and refuse to overwrite their disposable vaults.

1. [Acquire one exact field once](examples/acquire-one-field.sh)
2. [Create a vault](examples/create-skarbiec.sh)
3. [Create three isolated vaults](examples/create-three-skarbiecs.sh)
4. [Rotate the owner](examples/rotate-skarbiec-owner.sh)
5. [Build a serving host](examples/operations/build-skarbiec-host.sh)
6. [Move a serving host](examples/operations/change-skarbiec-host.sh)
7. [Synchronize two hosts through Git](examples/git/git-sync-two-hosts.sh)
8. [Enroll a replica](examples/bond/enroll-replica.sh)
9. [Review a donation inbox](examples/bond/donation-inbox.sh)
10. [Create a workload invitation](examples/bond/invite-person.sh)
11. [Share a credential with another recipient](examples/sharing/share-credential-with-user.sh)
12. [Donate an item to another host](examples/sharing/donate-item-to-host.sh)
