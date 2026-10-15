# Operating Skarbiec

How a Skarbiec host is configured, what each part of it owns, and the exact
recipes an operator runs. The [README](../README.md) covers what the product
is and how to install it; this page covers running one.

## Operational model

### Configuration

| Setting | Meaning |
| --- | --- |
| `SKARBIEC_VAULT_FILE` | Explicit local vault path. Otherwise Stado's `secrets.skarbiec.vault_file` selects the local owner; with only `secrets.skarbiec.url`, `get`, `list`, `set-json` and `status` use the fleet owner instead of a leftover client copy, and every other command, `init` included, refuses the default file naming the route (`this machine holds no Skarbiec vault: …`). A Stado config that is not JSON refuses the default file naming the config. Without either declaration, the default remains `~/.local/share/skarbiec/skarbiec.vault.json`. `tests/selection/unchosen_copy.sh` runs each of these cases. |
| `SKARBIEC_AUDIT_FILE` | Override the local append-only journal path |
| `SKARBIEC_UNLOCK_FILE` | Owner-only file supplying a protected key's unlock phrase to a persistent service |
| `SKARBIEC_UNLOCK` | Single-invocation unlock phrase, passed to `gpg` over stdin; prefer the file for services |
| `SKARBIEC_MCP_CONSUMER` | Server-side consumer identity required to enable MCP route resolution |
| `SKARBIEC_MCP_TOKEN_FILE` | Server-side compatibility grant file; never a tool argument |
| `SKARBIEC_MCP_OUT_DIR` | Required absolute directory for mode-0600 MCP route-resolution output |
| `SKARBIEC_READINESS_ITEMS` | Comma-separated additional item ids `/readyz` must decrypt |
| `SKARBIEC_GPG_DAEMON_MEMORY_LIMIT_MB` | Required for the daemon ceiling: physical footprint above which `skarbiec maintain` replaces `keyboxd` or `gpg-agent`. No default; without it `maintain` and `doctor` report the setting as missing |

Every override is read one way: only an unset or blank variable is absent.
A path override is taken as the operating system hands it over, so a path that
is not UTF-8 is still that path and never the default file. A text override
(`SKARBIEC_UNLOCK`, an MCP token) that is set but not UTF-8 is refused naming
the variable. The default unlock file `~/.stado/skarbiec-unlock` is absent
only when it does not exist; one that cannot be inspected is refused with its
cause, and one with any permission bit beyond owner read and write is refused
with `Skarbiec unlock file <path> must be mode 0600`.

With an unlock phrase, `gpg` reads the phrase and the ciphertext from one
standard input, the phrase up to its first line break and the message after
it, so nothing is written to disk for a decryption and the phrase never
reaches the command line. A phrase that holds a line break is refused with
`the Skarbiec unlock phrase holds a line break; gpg reads a phrase only up to
its first line break`.

`skarbiec serve` answers requests and nothing else. The recurring work is one
command, `skarbiec maintain`: it replaces GnuPG daemons over their memory
ceiling, proves readiness by decrypting the canary items, and pulls every bond
this vault pulls once. Every step runs; the command fails, naming every failed
step, when any of them did. A Stado schedule pinned to the host runs it:

```bash
stado schedule create --pinned-host HOST --cron '* * * * *' 'skarbiec maintain'
```
Replication discovery distinguishes an absent vault from a failed filesystem inspection: an inaccessible vault fails the pass with its path and operating-system cause. If both a pull and its failure-audit write fail, the refusal retains the bond, source address, original pull cause and audit-write cause together.

Cryptographic children run without a concurrency cap. Each running `gpg`
holds a shared permit; daemon recovery takes an exclusive permit after the
children that are still progressing finish, so it cannot replace their
daemons during a decryption. A child that asked gpg-agent for its key and
heard nothing is not waited for: it waits on the wedge the recovery clears,
and the recovery ends every `gpg` child of this account's Skarbiec processes
started against the daemons it replaced. Other cryptographic tools do not
wait for a GnuPG slot.

`/readyz` decrypts its canaries and therefore waits while daemon recovery
holds the exclusive permit. It does not wait behind a held keyring lock: when
a `gpg` run of this vault is in flight and a keyring lock file names a holder,
`/readyz` answers 503 with that holder — pid, host, what it runs now and since
when — instead of accepting the connection and never answering, which is what
every reader through Stado's resolver and every hook judge saw while one
process kept the key database. `/livez` and metadata-only routes do not
decrypt canaries.

A canary this host cannot open answers 503 with `stored item <id> cannot be
decrypted` followed by gpg's own sentence: `gpg failed (<exit status>): …
decryption failed: No secret key` when the item is sealed to a recipient
whose secret half is not in this keyring. Daemon recovery does not repair
that: compare the item's recipients with `skarbiec key-doctor`, or open the
item with the recovery key. The real test is `SKARBIEC=<binary>
SKARBIEC_TEST_SOURCE_REVISION=<commit> SKARBIEC_TEST_HTTP_PORT=<port> node
tests/health/undecryptable.mjs`.

Run `skarbiec status` for the serving vault path and non-sensitive counts. Remote status also records `source.kind`, `source.route` and `source.endpoint`; `recovery_present_locally` describes the serving owner. A `stado://service/skarbiec?consumer=operator` route is resolved through Stado's declared directory; every wait and actual owner refusal stays on stderr, while credential stdout keeps its local shape.
The owner and client must carry the owner-item API contract. `get`, including roles, fields and `--revision`, and `set-json`, including metadata preservation and `--if-absent`, share their implementations with the operator API. An unavailable or older owner is refused rather than replaced with a copied vault. The graphical operator API returns configuration selection failures and the complete owner error chain in its JSON `error`; it does not drop the connection or replace the underlying cause with only the forwarding step. See the canonical [get contract](https://skarbiec.wisent.com/docs/cli/get).
The real fleet journey is `node tests/vault/remote_owner.mjs`. Its environment must declare `SKARBIEC` (candidate executable), `SKARBIEC_TEST_SOURCE_REVISION` (full source revision), `SKARBIEC_TEST_STADO_CONFIG` (actual non-owner declaration), and `SKARBIEC_TEST_CLIENT_ENDPOINT` (the real non-owner operator listener). Before vault access, the executable's `version.commit` must match the declared revision and clean checkout; a source build with no embedded commit is refused. The returned candidate identity is retained with its binary hash. The journey proves that CLI and listener reach the same owner, that a second-forwarded read and write are refused without creating an item, and that ordinary owner item operations still work. It retains source-bound results under `target/real-tests/remote-owner` and purges only its uniquely created item. Client-copy preservation is checked even when the journey or cleanup fails; `clientCopyError`, `cleanupError` and the original `error` remain distinct in the retained report. Use `skarbiec key-doctor` for key diagnosis, `/livez` for liveness and `/readyz` (or `/health`) for readiness.
Commands that are not forwarded, `init` among them, refuse the default vault on a machine Stado routes to the owner: `this machine holds no Skarbiec vault: Stado reads the fleet vault through secrets.skarbiec.url (<route>), so <path> is a copy and is neither read nor written`. The copy is not created or changed; naming it with `SKARBIEC_VAULT_FILE` still opens it, so its items can be moved out. A Stado config that cannot be read refuses the default vault with `<path> is the default vault and <cause>, ... repair the config, or name a vault with SKARBIEC_VAULT_FILE`. The real journey is `SKARBIEC=<binary> tests/vault/client_copy/refusal.sh`, which also runs the declared-vault and no-route fallback cases.

### TOTP diagnostics

`skarbiec totp-seed-state [<item-id>]` validates `totp_secret` through the same
Base32-to-six-digit-code path used by `skarbiec totp`; it does not equate a
non-empty field with a working second factor and never emits the seed or the
computed code. Every row includes `seed_state`, a `description` of what was
found, and a state-specific `repair` when the vault can name the next action:

| State | Meaning |
| --- | --- |
| `present` | The field has the supported Base32 shape and the TOTP consumer produced a six-digit code. This does not prove that the account still has that seed enrolled. |
| `placeholder` | The field contains an uppercase underscore-delimited placeholder such as `WELES_ADMIN_GOOGLE_TOTP_SECRET`, not a secret. Replace the placeholder account values with a real account before enrolling and storing TOTP. |
| `invalid` | The field is non-empty but is not usable Base32 TOTP material or cannot produce a six-digit code. |
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
| Credentials | Values live in the vault only as per-recipient GPG ciphertext. Plaintext exists in exactly three places: the `gpg` child process and Skarbiec's own memory during a read or write, stdin when a value is stored, and the mode-0600 `<item>.env` file that `route resolve --emit` writes on request. On the protected-key path the unlock phrase and the ciphertext reach `gpg` together over stdin, so nothing is staged on disk and the phrase never reaches argv. Acquisition state stores only the SHA-256 hash of a one-use bearer, so the bearer itself cannot be recovered from disk. Scope is one exact consumer, item, and field; wildcards are refused. Rotation is `rotate-owner`, which rewraps every current and historical ciphertext onto the new recipient set or fails without writing anything. Revocation is `revoke`, which re-encrypts the item to the remaining recipients, `grant revoke` for a compatibility grant, and automatic deletion of a one-use capability once it is consumed or expires. The operator protects owner, workload, unlock, and recovery private material |
| Networking | `serve` binds `127.0.0.1` only, on the port `--port` names; the unit declares it, and `serve` without `--port` or `--no-http` is refused. Every accepted connection is served on a thread of its own, and no count caps concurrent cryptographic children either; a GnuPG daemon recovery waits for every running child that is still progressing. No request line, header block, body, token file, name or detail is cut or refused for its length. When the system refuses a thread, that request is answered `503` with `error_code` `infra_down` and the system's own reason (`skarbiec could not start a thread for this request: …`). The one connection Skarbiec itself initiates outward is `breach-check`, which sends the first five characters of a SHA-1 to `api.pwnedpasswords.com` and matches the returned suffixes locally. Ciphertext sync uses `git` against the remote the operator configures |
| Cost | The Apache-2.0 local core has no license fee or hosted dependency; the operator bears its host, storage, network, and operations costs. Hosted Hub pricing is not published because that service is not shipped |
| Observability | Skarbiec provides `/livez`, `/readyz`, compatibility alias `/health`, `status`, `key-doctor`, `audit list`, `audit epoch`, and `audit verify`. The journal is synchronously durable before an audited operation returns; a signed epoch checkpoint preserves a broken historical journal without rewriting it. A line nothing can parse is reported as a `malformed` fault naming the line number and the parser's reason, and counted in the report's `malformed` field, while every other line is still linked and digested: one broken line never hides the entries after it. A line that parses but whose `at`, `op`, `prev` or `hash` is absent or not text — or an epoch start without a text `previous_tail`, `checkpoint` or `signed_checkpoint` — is also a `malformed` fault, whose detail names those fields; it is never read as empty and reported as a linkage, digest or epoch fault |
| GnuPG daemons | Every read and write runs `gpg`, which talks to the account's `gpg-agent` and `keyboxd` over sockets Skarbiec does not own. A daemon that wedges answers `keydb_search failed: Broken pipe` or drops a live decryption, and the vault then refuses items whose keys are present. A recoverable failure repairs those daemons and retries once, by itself; `recover-daemons` performs the same repair on demand, for the case where a long-lived reader elsewhere — the HTTP listener, a browser host, an agent — is the one holding the wedge. It reports which daemons it signalled and what each running one held before it was replaced (`before`, in bytes, against `limit_bytes`), needs no unlock material, and restarts nothing: `gpg` starts its own daemons on the next call. `gpg` never stops them either, and `keyboxd` grows with every lookup it answers: on one always-on host it held 15 GiB after twelve days while `ps` reported 327 MiB, because the rest was compressed and swapped. The running service therefore measures both daemons' physical footprint on every readiness pass and replaces them, through the same serialized repair, when one stands above `SKARBIEC_GPG_DAEMON_MEMORY_LIMIT_MB`; the replacement is logged and journalled as `daemon-recycle` with the daemons and sizes it found. `doctor` reports the same measurement as `gpg_daemons`: `pass` names each running daemon, its pid and size against the ceiling; `fail` names the daemon over it and the two repairs, the service's next pass or `recover-daemons`; a daemon that cannot be measured is also `fail`, with the reason. A process other than the daemons can keep the key database's lock, and `gpg` then waits on it for tens of minutes per read before `keydb_search failed: Operation timed out`. The same repair therefore considers the locks GnuPG keeps beside the key databases of this home (`public-keys.d/pubring.db.lock`, `pubring.kbx.lock`), with every `gpg` of the service drained first. A lock must name a positive process id and this host: a missing host, another host or an invalid pid is left alone with the reason, because a shared keyring may have a live owner elsewhere. For a lock belonging to this host, a pid that runs nothing here is treated as stale. GnuPG executable identities are the canonical paths decoded from the `pgmname` field in `gpgconf --list-components` records (`name:description:pgmname:`), not the empty trailing field or a basename. A different executable, an unreadable executable path or an unresolved configured path is left alone with the specific cause; none proves that a lock can safely be removed. A lock a configured GnuPG program held past gpg's own wait has that program ended with `TERM`, as a wedged daemon is. Each action is written to stderr as `skarbiec: keyring lock: <what was done>`, or `left <lock> alone: <why>` when ownership cannot be established. A read that still fails after its repair names, for each of those lock files, the pid and host it records, what that pid runs now and when the lock was taken: `<lock> is held by pid <pid> on <host> (running <command>), taken <time>`, or `not running on this host` for a lock its holder left behind |
| Upgrades | The operator pins a release tag and its published SHA-256, performs an atomic rollout, and retains the prior exact coordinate for rollback. A tag whose name disagrees with the version declared in `Cargo.toml` is refused before the first tagged artifact is built, and the publication workflow refuses to replace an existing asset, so changed bytes require a new tag |
| Recovery | Skarbiec preserves the recovery recipient through owner rotation and supplies `recovery status` and `recovery drill`; the custodian stores the private half off-host and exercises it before an incident. If no secret half present on the machine opens the vault and no recovery key is available, the ciphertext is readable by no one — there is no cloud fallback and no vendor-held copy |
| Owner rotation | `rotate-owner` moves control with the ownership: every item the outgoing owner controlled becomes the new owner's, so retag, rotate and delete keep working. A vault rotated by a release before 0.4.8 left those items under the former owner, which nothing could write (`<id> is not owner-controlled`); `upgrade` reports them as `control.former_owner_items` and `upgrade --apply` moves every item a former owner (a recipient with `owner_until`) controls to the current owner. Items under the credential lifecycle or tagged `managed:weles` keep their controller, and no field, tag or revision changes |

Stale-lock removal remains GnuPG's operation on the next read or retry, not
Skarbiec's `unlink`: a lock can be replaced between observing its recorded
holder and removing its path. Skarbiec leaves that ownership decision to the
keyring implementation; it never unlinks a lock based on a process snapshot.
Live-holder signals are bound to the inspected process lifetime: macOS uses
one audit token for executable lookup and `SIGTERM`; Linux opens a pidfd before
lookup and signals that handle. Identity acquisition, path lookup or signaling
failure leaves the holder alone with the actual kernel error, never a PID-only retry. Daemon control uses this keyring's `gpgconf --kill` only: it never falls back to account-wide executable-name signals. Every failed daemon control remains in `recover-daemons`' unsuccessful receipt, with its operation, exit status and cause; one successful daemon control cannot hide another failure.

The real recovery journey needs an isolated OS account, never a live vault host.
It refuses existing GnuPG processes, checks encrypted values across recovery,
and preserves foreign-host, invalid-PID and non-GnuPG locks with their diagnostics. It invokes `purge ITEM --yes --help` on its real encrypted item, requires byte-identical vault and audit files, then reads the original value again. A non-directory keyring must produce a failed recovery receipt naming the rejected control operation, followed by a successful read from the valid isolated keyring.
The native identity case signals an owned pipe-reader process, verifies SIGTERM,
then requires the dead identity to refuse another signal while a new reader lives.
Run these explicit tests on each supported OS in the authorized qualification stage:

```sh
SKARBIEC=/absolute/path/to/candidate \
SKARBIEC_TEST_SOURCE_REVISION=<full-source-revision> \
cargo test --test read-recovery -- --ignored
```

The source checkout must be clean and match that revision. Command arguments,
exit statuses, stdout, stderr and lock before/after files remain under
`target/real-tests/recovery/`; `report.json` is passed only after the real
reads, ownership refusals and keyring cleanup succeed. The isolated keyring is
removed; the encrypted test vault and audit remain as evidence. The journey is
ignored by default because it exercises real GnuPG process ownership and recovery.

The operator owns:

- the OS account, file permissions, GPG keyring, and unlock material;
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
moves the value from `get` to `set-json` through one pipe, and refuses when the
item already exists in the live vault: it restores an absence, and rolling a
live item back is `skarbiec restore <item> --at <at>`.

