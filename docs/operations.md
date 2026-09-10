# Operating Skarbiec

How a Skarbiec host is configured, what each part of it owns, and the exact
recipes an operator runs. The [README](../README.md) covers what the product
is and how to install it; this page covers running one.

## Operational model

### Configuration

| Setting | Meaning |
| --- | --- |
| `SKARBIEC_VAULT_FILE` | Vault path; defaults to `~/.local/share/skarbiec/skarbiec.vault.json` |
| `SKARBIEC_AUDIT_FILE` | Override the local append-only journal path |
| `SKARBIEC_UNLOCK_FILE` | Owner-only file supplying a protected key's unlock phrase to a persistent service |
| `SKARBIEC_UNLOCK` | Single-invocation unlock phrase, passed to `gpg` over stdin; prefer the file for services |
| `SKARBIEC_ACQUISITION_TTL_SECONDS` | One-use capability TTL from 1 through 300 seconds; default 30 |
| `SKARBIEC_MCP_CONSUMER` | Server-side consumer identity required to enable MCP route resolution |
| `SKARBIEC_MCP_TOKEN_FILE` | Server-side compatibility grant file; never a tool argument |
| `SKARBIEC_MCP_OUT_DIR` | Required absolute directory for mode-0600 MCP route-resolution output |
| `SKARBIEC_HTTP_WORKERS` | Maximum concurrent HTTP handlers; default 16 |
| `SKARBIEC_HTTP_QUEUE` | Waiting HTTP requests before overload is refused; default 32 |
| `SKARBIEC_CRYPTO_CONCURRENCY` | Maximum concurrent external cryptographic tools; default 8 |
| `SKARBIEC_GPG_CONCURRENCY` | Maximum concurrent `gpg` processes sharing the keyring; default 2 |
| `SKARBIEC_CRYPTO_TIMEOUT_SECONDS` | Deadline after which a cryptographic child is killed and reaped; default 30 |
| `SKARBIEC_READINESS_ITEMS` | Comma-separated additional item ids `/readyz` must decrypt |

The two concurrency limits are nested, and the narrow one is taken first: a
`gpg` process claims a GnuPG slot and only then a general cryptographic slot,
so a decryption waiting its turn on the keyring holds no capacity anything
else needs. Taken the other way round, eight parked `gpg` children own the
whole general pool and every cheap tool queues behind them — `shasum`, which
verifies the bearer on every authenticated route, and `openssl`, which mints a
token. On 2026-09-05 a fleet host's four verifier sweeps read 48 mapped items
through one broker while a queue agent asked it for the metadata of its own
grant: that call decrypts nothing and took 14.4s, `GET /readyz` on the same
broker took 9.7s, and the fleet's own check reported the broker unmeasured
while it answered every request with 200.

`/readyz` decrypts its canaries, so it waits for GnuPG capacity by design;
`/livez` and the metadata routes do not.

Run `skarbiec status` for the vault path and non-sensitive counts,
`skarbiec key-doctor` for key and decryptability diagnosis, `/livez` for process
liveness, and `/readyz` (or compatibility alias `/health`) for readiness.

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
| Credentials | Values live in the vault only as per-recipient GPG ciphertext. Plaintext exists in exactly three places: the `gpg` child process and Skarbiec's own memory during a read or write, stdin when a value is stored, and the mode-0600 `<item>.env` file that `route resolve --emit` writes on request. The protected-key path stages ciphertext — never plaintext — to a temporary file, and an unlock phrase reaches `gpg` over stdin rather than argv. Acquisition state stores only the SHA-256 hash of a one-use bearer, so the bearer itself cannot be recovered from disk. Scope is one exact consumer, item, and field; wildcards are refused. Rotation is `rotate-owner`, which rewraps every current and historical ciphertext onto the new recipient set or fails without writing anything. Revocation is `revoke`, which re-encrypts the item to the remaining recipients, `grant revoke` for a compatibility grant, and automatic deletion of a one-use capability once it is consumed or expires. The operator protects owner, workload, unlock, and recovery private material |
| Networking | `serve` binds `127.0.0.1` only, on port 8787 unless `--port` says otherwise. A fixed worker set and bounded waiting queue cap connections; overload is refused before it can consume cryptographic or file-descriptor capacity. The one connection Skarbiec itself initiates outward is `breach-check`, which sends the first five characters of a SHA-1 to `api.pwnedpasswords.com` and matches the returned suffixes locally. Ciphertext sync uses `git` against the remote the operator configures |
| Cost | The Apache-2.0 local core has no license fee or hosted dependency; the operator bears its host, storage, network, and operations costs. Hosted Hub pricing is not published because that service is not shipped |
| Observability | Skarbiec provides `/livez`, `/readyz`, compatibility alias `/health`, `status`, `key-doctor`, `audit-query`, `audit-epoch-start`, and `verify-chain`. The journal is synchronously durable before an audited operation returns; a signed epoch checkpoint preserves a broken historical journal without rewriting it. A line nothing can parse is reported as a `malformed` fault naming the line number and the parser's reason, and counted in the report's `malformed` field, while every other line is still linked and digested: one broken line never hides the entries after it |
| GnuPG daemons | Every read and write runs `gpg`, which talks to the account's `gpg-agent` and `keyboxd` over sockets Skarbiec does not own. A daemon that wedges answers `keydb_search failed: Broken pipe` or drops a live decryption, and the vault then refuses items whose keys are present. A recoverable failure repairs those daemons and retries once, by itself; `recover-daemons` performs the same repair on demand, for the case where a long-lived reader elsewhere — the HTTP listener, a browser host, an agent — is the one holding the wedge. It reports which daemons it signalled, needs no unlock material, and restarts nothing: `gpg` starts its own daemons on the next call |
| Upgrades | The operator pins a release tag and its published SHA-256, performs an atomic rollout, and retains the prior exact coordinate for rollback. A tag whose name disagrees with the version declared in `Cargo.toml` is refused before the first tagged artifact is built, and the publication workflow refuses to replace an existing asset, so changed bytes require a new tag |
| Recovery | Skarbiec preserves the recovery recipient through owner rotation and supplies `recovery-status` and `recovery-drill`; the custodian stores the private half off-host and exercises it before an incident. If no secret half present on the machine opens the vault and no recovery key is available, the ciphertext is readable by no one — there is no cloud fallback and no vendor-held copy |

The operator owns:

- the OS account, file permissions, GPG keyring, and unlock material;
- an exact release tag and checksum, with deliberate rollout and rollback;
- moving the recovery private half off the workload host and exercising
  `recovery-drill`;
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

GPG remains the external encryption and key-custody boundary; OpenSSL supplies
high-entropy tokens, while SHA-256 journal hashing and timestamps run in-process
so an audit entry cannot exhaust subprocess capacity. See the complete
[security model](https://skarbiec.wisent.com/docs/security) and [architecture](https://skarbiec.wisent.com/docs/architecture).

### The macOS signing certificate

Stado reads the signing material from `desktop-release-developer-id`, which is the
name its own `DEVELOPER_ID_ITEM` constant carries. The release manifests declare
`wisent-apple-developer-id#…` in their `secret_env`, and Stado reads that
coordinate nowhere; the fields are the same three either way:

```text
MACOS_CERT_P12       wisent-apple-developer-id#certificate_p12_base64
MACOS_CERT_PASSWORD  wisent-apple-developer-id#certificate_password
MACOS_SIGN_IDENTITY  wisent-apple-developer-id#sign_identity
```

`scripts/apple-developer-id.py` is the tool for that item. It reads an App Store
Connect key from this vault rather than from a file, so no key material lands on
disk, and writes the item as one canonical `bundle` payload through stdin, so no
secret is ever a command-line argument:

```sh
SKARBIEC_VAULT_FILE=~/.stado/skarbiec.vault.json \
  python3 scripts/apple-developer-id.py roles   # who may do what
SKARBIEC_VAULT_FILE=~/.stado/skarbiec.vault.json \
  python3 scripts/apple-developer-id.py list    # what the account already holds
SKARBIEC_VAULT_FILE=~/.stado/skarbiec.vault.json \
  python3 scripts/apple-developer-id.py mint    # create one and store it
```

### The iOS signing material

Every `*-ios` release manifest and TestFlight workflow declares the same
coordinates, and no item had ever been created for them either:

```text
IOS_DIST_P12_B64        wisent-ios-distribution#certificate_p12_base64
IOS_DIST_P12_PASSWORD   wisent-ios-distribution#certificate_password
IOS_SIGN_IDENTITY       wisent-ios-distribution#sign_identity
IOS_PROFILE_B64         <repository>-signing#provisioning_profile_base64
```

`scripts/apple-ios-signing.py` is the tool for those items, built on the same
`apple_asc.py` helpers as the Developer ID tool. An iOS distribution certificate
is not reserved for the Account Holder, so the whole path is the REST API: the
certificate from a CSR generated locally, the bundle id by identifier, the App
Store profile from the two, and the seven GitHub Actions secrets of one
repository piped into `gh secret set` through stdin — the six signing values
above plus `WISENT_PACKAGES_TOKEN`, the vault's `GITHUB_TOKEN`, with which a
GitHub-hosted runner clones the private `wisent-ai` Swift packages:

```sh
python3 scripts/apple-ios-signing.py list                     # certificates, bundle ids, apps, profiles
python3 scripts/apple-ios-signing.py mint-certificate         # once per certificate; refuses to overwrite
python3 scripts/apple-ios-signing.py profile \
  --repository jeden-ios --bundle-id ai.wisent.jeden --app-name Jeden
python3 scripts/apple-ios-signing.py app-record \
  --bundle-id ai.wisent.jeden --app-name Jeden --sku jeden-ios
python3 scripts/apple-ios-signing.py check-login              # one sign-in, nothing else
python3 scripts/apple-ios-signing.py publish --repository jeden-ios
```

A profile is immutable at Apple, so one that exists under the pinned name but
names a revoked certificate — the state `Oko CI AppStore` was found in — is
deleted and recreated, and the tool says so. The one write the API refuses is
the App Store Connect app record itself (`POST /v1/apps` answers "The resource
'apps' does not allow 'CREATE'"), which a TestFlight upload needs to exist. For
that one write `scripts/apple_web.py` does what the site does, with no browser:
an SRP-6a sign-in at `idmsa.apple.com` with the Apple ID the vault holds
(`weles-apple-control-account`), the second factor read from the trusted-device
prompt on this Mac by Stado's signed `stado-apple-challenge-capture` helper —
preflighted before the password submit and installed for the GUI user the
registry binds the account to — and then
`iris/v1/apps`, carrying the `appStoreVersionLocalizations` relationship iris
refuses the create without. `profile` runs it when the bundle id has no record;
`app-record` runs it alone. The trusted session's cookies stay owner-only under
`~/.stado/work`, so a second run inside Apple's trust window signs in without a
prompt. It has run: app `6807934112` for `ai.wisent.jeden` was created this way
on 2026-09-02, and the first `jeden-ios` build reached TestFlight the same day.

Three vault items hold this one Apple ID and two of them were stale, which is
why the Weles Apple trajectory had never completed: a password nothing checks is
a password nobody knows is wrong. `check-login` is that check — one sign-in and
nothing else, with a throwaway cookie jar, because reusing the trusted session
would answer "fine" without ever sending the password. All three items now carry
the value that opens the account, verified through it.

Development and distribution certificates are issued through the App Store
Connect API with no browser at all. A Developer ID Application certificate is
the exception Apple reserves for the Account Holder, and it has its own
automated path through Weles: a tracked trajectory, one authorization per
password submit, and a Stado relay that captures the second factor in the exact
registered Aqua session and stores it in the execution host's one-use Skarbiec
challenge.

The whole procedure — both paths, the recorded provenance of a certificate the
API already issued, and what still blocks a Developer ID run — is
[Apple Developer Certificates](https://skarbiec.wisent.com/docs/apple-developer-certificates).
It is documented there rather than here so there is one copy to keep true.

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
| `brama:login:<login>` | valued | Which login item a Codex subscription belongs to |
| `fleet:host-account` | exact | Registered for the fleet tooling that shares this vault; Skarbiec does not write it |
| `fleet:target:<name>` | valued | Registered for the fleet tooling that shares this vault; Skarbiec does not write it |
| `fleet:tailnet-tls` | exact | Registered for the fleet tooling that shares this vault; Skarbiec does not write it |
| `lifecycle:quarantined` | exact | Written and cleared by the credential lifecycle when it freezes or releases an item, and read back to decide whether an item is frozen |

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

### An item lost from the live vault, still in a backup

A host's vault document can be replaced by a sync that does not carry an item
written locally on that host. Measured on charless-mac-mini on 2026-09-02:
`weles-figma-personal-access-token`, acquired on 2026-08-12 and present in the
2026-08-17 backup beside the vault, was absent from the live document with no
delete, trash or purge entry in the audit journal, while its consumer grant
survived — so every acquisition failed as `503 infra_down` instead of `401`,
because a grant whose item is gone is an authority error, not a refusal. The
backup is ciphertext for the same owner key, so only that host can read it.

```sh
sh scripts/restore-item-from-backup.sh ~/.stado/skarbiec.vault.before-stado-local-agent-bearer-rotation.json weles-figma-personal-access-token
```

It carries the item's kind, tags and recipients over from the backup envelope,
moves the value from `get` to `set-json` through one pipe, and refuses when the
item already exists in the live vault: it restores an absence, and rolling a
live item back is `skarbiec restore-version`.

