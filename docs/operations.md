# Operating Skarbiec

How a Skarbiec host is configured, what each part of it owns, and the exact
recipes an operator runs. The [README](../README.md) covers what the product
is and how to install it; this page covers running one.

## Operational model

### Configuration

| Setting | Meaning |
| --- | --- |
| `SKARBIEC_VAULT_FILE` | Explicit local vault path. Otherwise Stado's `secrets.skarbiec.vault_file` selects the local owner; with only `secrets.skarbiec.url`, `get`, `list`, `set` and `status` use the fleet owner instead of a leftover client copy, and every other command, `init` included, refuses the default file naming the route (`this machine holds no Skarbiec vault: …`). A host whose config names neither but which publishes the canonical forward `~/.stado/forwards/skarbiec.local` (or `$STADO_FORWARDS_DIR/skarbiec.local`), the address Stado then reads the vault through, refuses the default file the same way, naming the forward; its `status` answers `holds_vault: false` with `owner_route`, `owner_route_declared_by` and `copy_present` (whether a leftover copy lies at the default path), and `doctor`'s `vault` check says the same. A Stado config that is not JSON refuses the default file naming the config. Without any declaration, the default remains `~/.local/share/skarbiec/skarbiec.vault.json`. `tests/selection/unchosen_copy.sh` runs each of these cases. |
| `SKARBIEC_AUDIT_FILE` | Override the local append-only journal path |
| `SKARBIEC_KEYS_FILE` | The key file this vault's keys are read from and written to. Otherwise `<vault without .json>.keys.json` beside the vault file, so each vault on a host has its own keys and a copy of the vault file alone carries none |
| `SKARBIEC_UNLOCK_FILE` | Owner-only file holding the unlock phrase the key file's secret halves are sealed under, for a persistent service |
| `SKARBIEC_UNLOCK` | Single-invocation unlock phrase; prefer the file for services |
| `SKARBIEC_MCP_CONSUMER` | Server-side consumer identity required to enable MCP route resolution |
| `SKARBIEC_MCP_TOKEN_FILE` | Server-side compatibility grant file; never a tool argument |
| `SKARBIEC_MCP_OUT_DIR` | Required absolute directory for mode-0600 MCP route-resolution output |
| `SKARBIEC_READINESS_ITEMS` | Comma-separated additional item ids `/readyz` must decrypt |

Every override is read one way: only an unset or blank variable is absent.
A path override is taken as the operating system hands it over, so a path that
is not UTF-8 is still that path and never the default file. A text override
(`SKARBIEC_UNLOCK`, an MCP token) that is set but not UTF-8 is refused naming
the variable. The default unlock file `~/.stado/skarbiec-unlock` is absent
only when it does not exist; one that cannot be inspected is refused with its
cause, one owned by another account is refused naming its owner, and one with
any permission bit beyond owner read and write is refused with `Skarbiec unlock
file <path> must be mode 0600 (it is <mode>), so no other account reads it:
chmod 600 <path>`. The key file is held to the same rule.

### Keys and cryptography

Every cryptographic step runs inside the Skarbiec process, on Skarbiec's own
library (`crates/crypto`), which depends on no other crate and runs no
program: no `gpg`, `gpg-agent`, `keyboxd` or `openssl`. Every dependency is
code that runs with the vault's secrets in reach and that someone else can
change — a crate's next release, a maintainer account taken over, a build
script, a transitive dependency nobody reviewed — so the vault depends on
none: each primitive is a published standard checked against its published
test vectors (`crates/crypto/README.md` lists them). The external programs
went for a second reason: a vault that decrypted by running `gpg` depended on
`gpg-agent` and `keyboxd` answering, and when they did not every read waited
behind them. A function call leaves no daemon behind.

New items are sealed in Skarbiec's own format (`-----BEGIN SKARBIEC
SEALED-----`): a random content key under ChaCha20-Poly1305, wrapped for each
recipient with X25519 and HKDF-SHA256. Items gpg wrote before (`-----BEGIN
PGP MESSAGE-----`, ECDH over Curve25519 with AES-256 in OCB or in CFB with an
MDC) are still read, in this process, until `skarbiec reseal` moves them.
Recipients keep their identity: a recipient's key is the OpenPGP key it
always was, named by the same fingerprint, and an item is sealed to that
key's Curve25519 subkey.

The keys live in the **key file**, owner-only JSON beside the vault
(`SKARBIEC_KEYS_FILE` overrides it): each key's public half, and the secret
half of the keys this host holds. `init`, `owner key mint` and `recipient
add` without `--import` write new keys there; `recipient add --import`,
`recipient rekey` and `enroll` add public halves. A host that held its keys
in GnuPG brings them over once with `skarbiec keys import`, which reads the
GnuPG home's own files (`public-keys.d/pubring.db` or `pubring.kbx`, and
`private-keys-v1.d/<keygrip>.key`) without running anything:

```bash
skarbiec keys import                         # every key the vault names, from ~/.gnupg
skarbiec keys import --gnupg-home <dir> --keys <fingerprint,...>
```

A key whose public half the GnuPG home lacks is refused naming it; a
protected GnuPG key opens with the unlock phrase configured below, and one it
does not open is refused saying so.

The key file is read only when it is a regular file of this account with no
permission bit beyond owner read and write; anything else is refused naming
the file, why, and the `chmod`/`chown` that fixes it. With an unlock phrase
configured (`SKARBIEC_UNLOCK`, the file `SKARBIEC_UNLOCK_FILE` names, or the
default `~/.stado/skarbiec-unlock`), each secret half is written sealed under
it: iterated and salted SHA-256 (RFC 4880 section 3.7.1.3, 65,011,712 bytes)
derives a key that seals the half with ChaCha20-Poly1305, bound to its
fingerprint. A sealed half without a configured phrase, or with another
phrase, is refused naming the key and the setting to fix; every other key
still works.

What the key file protects against, and what it does not:

- Without an unlock phrase the secret halves are in the clear inside an
  owner-only file. That protects them from other accounts on the host and
  from anything that copies the vault file alone (a backup, the Git mirror,
  a replica pull, an export, a placement move: none of them carries the key
  file). It does not protect them from anyone who can read files as this
  account, from root, or from a disk read outside the operating system (an
  unencrypted disk image, a backup of the whole home directory). That is the
  same protection the unprotected GnuPG key files had.
- With an unlock phrase the halves at rest are sealed, so a copy of the key
  file alone opens nothing; the phrase file is then what must be kept apart.
  A running service holds the unlocked halves in memory while it runs.
- Back the key file up apart from the vault: `keys check` names it. A vault
  restored without its key file opens only with the recovery key.

`skarbiec reseal` moves every stored ciphertext to the sealed format, once,
on the vault owner:

```bash
skarbiec keys import          # once per host that opens the vault
skarbiec reseal               # how many OpenPGP ciphertexts; refuses a key the key file lacks
skarbiec reseal --apply       # reseal, keep <vault>.pre-reseal-<stamp>, prove every ciphertext opens
skarbiec reseal --verify      # repeat the proof
```

`--apply` opens every OpenPGP current value, saved version and staged value
and seals it again to the same recipients, refusing before anything is
written when one does not open. It copies the vault file, owner-only, to
`<vault>.pre-reseal-<stamp>`, writes once, and then opens every ciphertext
again from the file on disk. Until that proof passes the vault records the
run, and a second `--apply` is refused naming the copy; `--verify` repeats
the proof once the missing key is imported, or `skarbiec backup restore
<copy> --yes` puts the vault back. The copy is kept until the operator
removes it. Every Skarbiec that opens the vault — the owner, each replica,
each host a bond pulls to — runs a build that reads the sealed format before
the owner reseals; an older build cannot open a sealed item.

`skarbiec serve` is one process. It answers requests on its own threads and
starts no other program for a read, a write, `/health`, `/readyz` or key
work. The recurring work is one command, `skarbiec maintain`: it proves
readiness by decrypting the canary items, pulls every bond this vault pulls
once, and, on the host that publishes the Git ciphertext mirror, pushes the
mirror once. Every step runs; the command fails, naming every failed step,
when any of them did. A Stado schedule pinned to the host runs it:

```bash
stado schedule create --pinned-host HOST --cron '* * * * *' 'skarbiec maintain'
```
Replication discovery distinguishes an absent vault from a failed filesystem inspection: an inaccessible vault fails the pass with its path and operating-system cause. If both a pull and its failure-audit write fail, the refusal retains the bond, source address, original pull cause and audit-write cause together.

Only the vault's owner publishes its mirror: a replica that pushed would
replace the owner's ciphertext with its own copy, so a mirror existing never
makes a host publish. `skarbiec mirror publish` records it in the mirror's own
Git configuration (`skarbiec.publish`, in `$SKARBIEC_SYNC_DIR`, by default
`~/.skarbiec-sync`); `skarbiec mirror unpublish` stops it. The operator API
answers the same verbs at `POST /v1/operator/sync/publish` and
`POST /v1/operator/sync/unpublish`. A failed push fails the pass as
`skarbiec maintain: mirror push: mirror: git <step> in <dir> failed: <git's
error>`, or `mirror push: git push origin HEAD:refs/heads/<branch> failed:
<git's error>`; `maintain` answers `"mirror": null` on a host that does not
publish, and the push's answer on the one that does. A mirror whose Git
configuration cannot be read fails the pass with `git config --bool
skarbiec.publish in <dir>: <git's error>` instead of reading as a host that
does not publish.

`skarbiec doctor` carries a `mirror` check, read from disk without a fetch.
It passes when the live vault is byte for byte the vault in the last pushed
branch (`the live vault is the one pushed to refs/remotes/origin/main at
<time>`), fails when it is not (`the live vault changed after the last push to
refs/remotes/origin/main, at <time>, and nothing published it since`) or when
the mirror never pushed, and is `not_configured` on a host without a mirror.
The desktop's Posture shows a failing `mirror` check as "Mirror failed" with
that sentence. `mirror init` creates the mirror on branch `main`; `mirror push`
and `mirror pull` without `--branch` use the branch the mirror has checked out. `mirror pull` keeps the live vault as `<vault>.pre-pull-<stamp>` and renames the synced vault over it, so it never leaves the vault path empty. A vault file that is gone is refused naming the newest `<vault>.<suffix>` copy beside it that reads as a vault and `skarbiec backup restore <copy>`, not only `init`.

On a machine Stado makes a client of the vault owner (`secrets.skarbiec.url`
declared, or the canonical forward published, and no
`secrets.skarbiec.vault_file`), `skarbiec doctor`'s `vault` check does not
report a missing vault: it passes with `this host holds no vault: Stado reads
the fleet vault through <declaration> (<route>); <default path> is not used`,
or `... is a leftover copy and is not used` when a file lies at the default
path, which it leaves untouched. A Stado config that cannot be read fails the
check naming the file. Whether the route answers is the `endpoint` check's.

On a machine Stado makes a client of the vault owner (`secrets.skarbiec.url`
declared, or the canonical forward published, and no
`secrets.skarbiec.vault_file`), `skarbiec doctor`'s `vault` check does not
report a missing vault: it passes with `this host holds no vault: Stado reads
the fleet vault through <declaration> (<route>); <default path> is not used`,
or `... is a leftover copy and is not used` when a file lies at the default
path, which it leaves untouched. A Stado config that cannot be read fails the
check naming the file. Whether the route answers is the `endpoint` check's.

`/health` decrypts nothing: it proves the journal takes an entry and the vault
document opens. `/readyz` also opens its canary items with the keys this host
holds. Both run in the serving process and wait on no other program.
`/livez` and metadata-only routes do not decrypt canaries.

A canary this host cannot open answers 503 with `stored item <id> cannot be
decrypted` followed by the key file's own sentence: `no key held here is a
recipient of this sealed item; it is sealed to key id(s) <ids>; the key file
<path> holds the secret half of <n> key(s), none of them a recipient: import
the recipient's key here (skarbiec keys import)` when the item is sealed to a
recipient whose secret half this host does not hold, and the key and the
setting to fix when a sealed secret half has no unlock phrase or another one.
`skarbiec readers <id>` names each key the item is sealed to and whether this
host holds it; `skarbiec keys check` names the key file to restore. The real
test is `SKARBIEC=<binary> SKARBIEC_TEST_SOURCE_REVISION=<commit>
SKARBIEC_TEST_HTTP_PORT=<port> node tests/health/undecryptable.mjs`.

Run `skarbiec status` for the serving vault path and non-sensitive counts. Remote status also records `source.kind`, `source.route` and `source.endpoint`; `recovery_present_locally` describes the serving owner. A `stado://service/skarbiec?consumer=operator` route is resolved through Stado's declared directory; every wait and actual owner refusal stays on stderr, while credential stdout keeps its local shape.
The owner and client must carry the owner-item API contract. `get`, including roles, fields and `--revision`, and `set`, including metadata preservation and `--if-absent`, share their implementations with the operator API. An unavailable or older owner is refused rather than replaced with a copied vault. The graphical operator API returns configuration selection failures and the complete owner error chain in its JSON `error`; it does not drop the connection or replace the underlying cause with only the forwarding step. See the canonical [get contract](https://skarbiec.wisent.com/docs/cli/get).
The real fleet journey is `node tests/vault/remote_owner.mjs`. Its environment must declare `SKARBIEC` (candidate executable), `SKARBIEC_TEST_SOURCE_REVISION` (full source revision), `SKARBIEC_TEST_STADO_CONFIG` (actual non-owner declaration), and `SKARBIEC_TEST_CLIENT_ENDPOINT` (the real non-owner operator listener). Before vault access, the executable's `version.commit` must match the declared revision and clean checkout; a source build with no embedded commit is refused. The returned candidate identity is retained with its binary hash. The journey proves that CLI and listener reach the same owner, that a second-forwarded read and write are refused without creating an item, and that ordinary owner item operations still work. It retains source-bound results under `target/real-tests/remote-owner` and purges only its uniquely created item. Client-copy preservation is checked even when the journey or cleanup fails; `clientCopyError`, `cleanupError` and the original `error` remain distinct in the retained report. Use `skarbiec keys check` for key diagnosis, `/livez` for liveness and `/readyz` (or `/health`) for readiness.
Commands that are not forwarded, `init` among them, refuse the default vault on a machine Stado routes to the owner: `this machine holds no Skarbiec vault: Stado reads the fleet vault through secrets.skarbiec.url (<route>), so <path> is a copy and is neither read nor written`; where only the canonical forward declares the route, the sentence names the forward file instead of `secrets.skarbiec.url`. `init` is refused before it makes any key. The copy is not created or changed; naming it with `SKARBIEC_VAULT_FILE` still opens it, so its items can be moved out. A Stado config that cannot be read refuses the default vault with `<path> is the default vault and <cause>, ... repair the config, or name a vault with SKARBIEC_VAULT_FILE`. The real journey is `SKARBIEC=<binary> tests/selection/unchosen_copy.sh`, which also runs the declared-vault and no-route fallback cases.

### TOTP diagnostics

`skarbiec totp seed [<item-id>]` validates `totp_secret` through the same Base32-to-six-digit-code path used by `skarbiec totp code`; it does not equate a non-empty field with a working second factor and never emits the seed or the computed code. Every row includes `seed_state`, a `description`, a `reason` when the seed is `invalid` (not padded RFC 4648 Base32, or no bytes once decoded), and a state-specific `repair` when the vault can name the next action.
A clock that reads before the Unix epoch is no seed's fault: `totp code`, `totp seed` and `totp set` refuse with `the system clock reads a time before the Unix epoch`, and the browser fill reports it as `totp_unavailable`, rather than marking a seed `invalid`.

| State | Meaning |
| --- | --- |
| `present` | The field has the supported Base32 shape and the TOTP consumer produced a six-digit code. This does not prove that the account still has that seed enrolled. |
| `placeholder` | The field contains an uppercase underscore-delimited placeholder such as `WELES_ADMIN_GOOGLE_TOTP_SECRET`, not a secret. Replace the placeholder account values with a real account before enrolling and storing TOTP. |
| `invalid` | The field is non-empty but is not usable Base32 TOTP material or cannot produce a six-digit code; `reason` says which. |
| `declared_empty` | The item kind declares `totp_secret`, but no non-blank text is stored in the field. |
| `field_absent` | The item kind does not declare a `totp_secret` field and must be stored as a `login` before it can carry one. |
| `unreadable` | The item could not be opened; the output includes the read error rather than guessing a seed state. |

`skarbiec totp` reports `has_seed: true` only for `present`; placeholder and
invalid values return no code. The shared credential resolver also rejects
uppercase placeholders, so `route verify`, the `doctor` credentials check,
and `grant capability` cannot call placeholder text a usable credential.

### Ownership by concern

| Concern | Current owner and contract |
| --- | --- |
| Configuration | Operator-owned environment variables and owner-only files; the supported settings and defaults are listed above. There is no configuration file and no reload: an explicit variable wins over the built-in default, and each invocation reads the environment it was given |
| State | Three owner-only local files: the encrypted vault, the one-use acquisition state written beside it as `<vault>.acquisitions.json`, and the append-only audit journal, which defaults to `~/.local/state/skarbiec/audit.jsonl`. State documents use mode-0600 temporary files, `fsync`, and `rename`, so a reader sees the old document or the new one and never a partial write. Acquisition updates serialize through the owner-only `<vault>.acquisitions.json.advisory.lock` file and a kernel lock that is released when the process exits; the operator chooses the durable filesystem and its backups |
| Credentials | Values live in the vault only as per-recipient sealed ciphertext (items written before the cutover stay OpenPGP until `reseal`). Plaintext exists in exactly three places: Skarbiec's own memory during a read or write, stdin when a value is stored, and the mode-0600 `<item>.env` file that `route resolve --emit` writes on request. The keys live in the owner-only key file beside the vault, their secret halves sealed under the unlock phrase when one is configured. Acquisition state stores only the SHA-256 hash of a one-use bearer, so the bearer itself cannot be recovered from disk. Scope is one exact consumer, item, and field; wildcards are refused. Rotation is `owner rotate`, which rewraps every current and historical ciphertext onto the new recipient set or fails without writing anything. Revocation is `revoke`, which re-encrypts the item to the remaining recipients, `grant revoke` for a compatibility grant, and automatic deletion of a one-use capability once it is consumed or expires. The operator protects owner, workload, unlock, and recovery private material, and backs the key file up apart from the vault |
| Networking | `serve` binds only the IPv4 loopback address, on the port `--port` names; the unit declares it, and `serve` without `--port` or `--no-http` is refused. Every accepted connection is served on a thread of its own in the one `serve` process; no read, write, health or readiness request starts another program. No request line, header block, body, token file, name or detail is cut or refused for its length. When the system refuses a thread, that request is answered `503` with `error_code` `infra_down` and the system's own reason (`skarbiec could not start a thread for this request: …`). The one connection Skarbiec itself initiates outward is `breach check`, which sends the first five characters of a SHA-1 to `api.pwnedpasswords.com` and matches the returned suffixes locally. Ciphertext sync uses `git` against the remote the operator configures |
| Browsers | No route answers a web page. Every request is refused `403` with the reason when its `Host` does not name a loopback host (`localhost` or a loopback IP, as a DNS-rebinding page's would not), when it carries `Origin`, or when it carries `Sec-Fetch-Site` other than `none`: browsers send those for requests a page makes, and a page could otherwise drive the unauthenticated operator routes with a cross-site `text/plain` POST. An operator `POST` (`/v1/operator/*`) is also refused `403` unless it declares `Content-Type: application/json`, a type no page can send across sites without a preflight Skarbiec never answers. Local programs (the CLI, the desktop app, Stado, Brama, Weles) send none of the browser headers and post JSON |
| Cost | The Apache-2.0 local core has no license fee or hosted dependency; the operator bears its host, storage, network, and operations costs. The paid fleet audit service is the separate product skarbiec-web, priced in its own repository |
| Observability | Skarbiec provides `/livez`, `/health` (journal and vault document; decrypts nothing), `/readyz` (that, and the canary decrypts), `status`, `keys check`, `audit list`, `audit epoch`, and `audit verify`. The journal is synchronously durable before an audited operation returns; a signed epoch checkpoint preserves a broken historical journal without rewriting it. A line nothing can parse is reported as a `malformed` fault naming the line number and the parser's reason, and counted in the report's `malformed` field, while every other line is still linked and digested: one broken line never hides the entries after it. A line that parses but whose `at`, `op`, `prev` or `hash` is absent or not text — or an epoch start without a text `previous_tail`, `checkpoint` or `signed_checkpoint` — is also a `malformed` fault, whose detail names those fields; it is never read as empty and reported as a linkage, digest or epoch fault |
| Upgrades | The operator pins a release tag and its published SHA-256, performs an atomic rollout, and retains the prior exact coordinate for rollback. A tag whose name disagrees with the version declared in `Cargo.toml` is refused before the first tagged artifact is built, and the publication workflow refuses to replace an existing asset, so changed bytes require a new tag |
| Recovery | Skarbiec preserves the recovery recipient through owner rotation and supplies `recovery status` and `recovery drill`; the custodian stores the private half off-host and exercises it before an incident. If no secret half present on the machine opens the vault and no recovery key is available, the ciphertext is readable by no one — there is no cloud fallback and no vendor-held copy |
| Owner rotation | `owner rotate` moves control with the ownership: every item the outgoing owner controlled becomes the new owner's, so retag, rotate and delete keep working. A vault rotated by a release before 0.4.8 left those items under the former owner, which nothing could write (`<id> is not owner-controlled`); `upgrade` reports them as `control.former_owner_items` and `upgrade --apply` moves every item a former owner (a recipient with `owner_until`) controls to the current owner. Items under the credential lifecycle or tagged `managed:weles` keep their controller, and no field, tag or revision changes |

The operator owns:

- the OS account, file permissions, the key file, and unlock material;
- an exact release tag and checksum, with deliberate rollout and rollback;
- moving the recovery private half off the workload host and exercising
  `recovery drill`;
- ciphertext backups or sync, service supervision, and broker availability;
- treating cleartext item ids, tags, recipient names, and audit identifiers as
  sensitive metadata where appropriate.

Skarbiec owns:

- atomic, locked vault and acquisition-state writes;
- per-recipient encryption and exact consumer/item/field authorization;
- replay, expiry, and binding checks before a value is returned;
- failure-closed behavior and distinct authorization versus infrastructure
  errors;
- a hash-chained audit trail that reveals no secret values.

GPG remains the external encryption and key-custody boundary; service tokens
are 32 bytes read from `/dev/urandom` in-process, and SHA-256 journal hashing
and timestamps run in-process too, so an audit entry cannot exhaust subprocess
capacity. See the complete
[security model](https://skarbiec.wisent.com/docs/security) and [architecture](https://skarbiec.wisent.com/docs/architecture).

### Signing material

The macOS and iOS signing material, the fields each release reads and the
tools that mint and publish it, are [Signing material](signing-material.md).

### Item tags

An item's tags are cleartext metadata, and they carry two different kinds of
meaning. A tag with no colon claims no namespace: it is the operator's own
label, governed by nobody and filtered on by nobody, and Skarbiec has no
standing over it. A tag containing a colon claims a namespace, and a claim has
to be honoured — so a write that *introduces* a namespaced tag is refused
unless that namespace is registered. The registry in `src/core/schema.rs` is
the authority: a namespace exists because it is a row there, and a refusal
names the tag, says what is wrong with it, and lists the registered set.

A namespace comes in one of two shapes, and they are not interchangeable. An
exact namespace is the whole statement and must match exactly, so
`brama:subscription:anything` is a different, unregistered tag. A valued
namespace carries the content in its value, and a bare prefix is a declaration
with its subject missing; the value must be 1 to 128 bytes and carry no NUL,
newline, or carriage return.

| Registered namespace | Shape | What it marks |
| --- | --- | --- |
| `managed:weles` | exact | The item is managed by Weles rather than by hand |
| `brama:subscription` | exact | The item is a subscription, not merely provider-shaped |
| `brama:agent:<agent>` | valued | Which agent the subscription routes to |
| `brama:provider:<provider>` | valued | Which provider the subscription is held with |
| `brama:id:<id>` | valued | The subscription's own identifier |
| `brama:login:<login>` | valued | Which login item a subscription signs in through, for any provider it is held with |
| `brama:account:<account>` | valued | Which provider account the credential belongs to, written from the address the provider signed into the grant |
| `fleet:host-account` | exact | Registered for the fleet tooling that shares this vault; Skarbiec does not write it |
| `fleet:target:<name>` | valued | Registered for the fleet tooling that shares this vault; Skarbiec does not write it |
| `fleet:tailnet-tls` | exact | Registered for the fleet tooling that shares this vault; Skarbiec does not write it |
| `stado:role:<role>` | valued | Registered for Stado: what a secret is for. A release recipe, job or agent grant asks for a role and Stado selects the one live item carrying this tag, so the item's id decides nothing; Skarbiec does not write it |
| `lifecycle:quarantined` | exact | Written and cleared by the credential lifecycle when it freezes or releases an item, and read back to decide whether an item is frozen |
| `skrzynka:mailbox` | exact | Registered for Skrzynka, which lists its mailboxes by it: `skrzynka mailbox declare` writes it and `skrzynka mailbox undeclare` removes it; Skarbiec does not write it |
| `weles:record:<kind>` | valued | Registered for Weles: the kind of record an item holds (trajectory account, service credential, runtime setting, email-domain status). Weles lists its records of a kind by this tag and matches each record's sealed context, so the item's id decides nothing; Skarbiec does not write it |
| `weles:login-method:<method>` | valued | Registered for Weles: how it signs into a login row, `google_sso` or `email_password`, for a row whose sealed context declares no `login_method`. An operator writes it on the vault owner with `stado credentials item retag`; Weles reads it beside the context; Skarbiec does not write it |

Only what a write introduces is judged. A tag the item already carries is left
alone, because writes deliberately preserve tags they do not mention and
re-reading that preserved list through the gate would turn every unrelated
rotation of an already-tagged item into a refusal. An unregistered tag already
in the vault — including one carried in by a migration — is therefore preserved
rather than re-judged: it is a migration to run, not a rotation to break.

The registry governs writes from every direction that reaches an item's tags:
CLI and API item writes, imports, sharing and rewraps, donation acceptance,
retagging, and managed writes. Registering a namespace means adding a row in
the same commit that starts writing it; nothing else registers anything.

`skarbiec retag <id> --tags tag[,tag...]` replaces every tag the item carries
and leaves its payload untouched. The list is required: `--tags ""` removes
every tag, and a call without `--tags` is refused as a usage error rather than
read as an empty list.

### An item lost from the live vault, still in a backup

A host's vault document can be replaced by a sync that does not carry an item
written locally on that host. The item is then absent from the live document
with no delete, trash or purge entry in the audit journal, while its consumer
grant survives — so every acquisition fails as `503 infra_down` instead of
`401`, because a grant whose item is gone is an authority error, not a
refusal. A backup beside the vault may still hold it; the backup is
ciphertext for the same owner key, so only that host can read it.

```sh
sh scripts/restore-item-from-backup.sh ~/.stado/<vault backup>.json <item>
```

It carries the item's kind, tags and recipients over from the backup envelope,
moves the value from `get` to `set` through one pipe, and refuses when the
item already exists in the live vault: it restores an absence, and rolling a
live item back is `skarbiec restore <item> --at <at>`.

