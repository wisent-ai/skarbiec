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
Diagnosis:   doctor
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
| `list [--all]` | List item metadata (id, type, revision count, recipient UIDs, tags)—never values. `--all` includes trashed items. |
| `delete <id>` | Move an item to the trash (recoverable). |
| `reclaim <id>` | Return one item to owner control when its recorded controller can no longer write it. Refuses anything under the Weles credential lifecycle. Changes control only: no field, tag, recipient or revision moves. |
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

### When an item has no writer left

`management` records who may write an item, and it is written from the identity
of whoever created it: the owner gets `{"mode":"owner"}`, any other writer gets
`{"mode":"external","controller":"<consumer>"}`. Afterwards only that same
authority may change it, which is what stops two systems from fighting over one
credential.

That invariant has a failure mode. A consumer that wrote through an API this
broker no longer serves leaves the item with **no writer at all**: the owner is
refused as "not owner-controlled", and the consumer's own path is gone. `set`,
`set-json`, `delete` and `import` all decline, the last one silently accepting
only writes that change nothing. Three fleet SSH host keys reached that state,
and a key that cannot be rotated cannot be revoked either.

`reclaim <id>` is the repair. It moves control back to the owner and touches
nothing else, so the material stays exactly as the previous controller left it
and the next ordinary owner write is what changes anything. It refuses items
under the Weles credential lifecycle — mode `managed` or the `managed:weles`
tag — because their local state must not diverge from the provider's, and it
records the previous controller in the audit journal as `item-reclaimed`.

## Canonical item schema (`skarbiec.item.v2`)

Every item payload is one JSON object validated against the schema in
`src/core/schema.rs`. Allowed top-level properties are `schema` (must equal
`skarbiec.item.v2`), `kind`, `fields` (a non-empty object), `context` (an
object, required), and `extensions` (an optional object).

| Kind | Fields (`*` = required) |
| --- | --- |
| `login` | `username*`, plus at least one of `password`, `totp_secret`, `recovery_codes` |
| `host-account` | `username*`, `password*`, and `context.account_ref` naming `<user>@<host>` |
| `note` | `value*` |
| `api-key` | `api_key*`, `api_user`, `username`, `client_ip` |
| `access-key` | `access_key_id*`, `secret_access_key*`, `session_token` |
| `token` | `token*` |
| `oauth-client` | `client_id*`, `client_secret*` |
| `proxy` | `username*`, `password*`, `host`, `ports`, `zone` |
| `key-pair` | `private_key*`, `public_key`, `passphrase`, `key_id`, `issuer_id`, `team_id` |
| `certificate` | `certificate*`, `private_key*`, `chain`, `passphrase` |
| `service-account` | `credential_json*` |
| `credential-operation` | `value*` |
| `bundle` | free-form fields (see below) |
| `stado-secret` | free-form fields (see below) |
| `internal-authority` | free-form fields (see below) |

Typed kinds reject fields outside their list. The free-form kinds accept any
field whose name is 1–128 ASCII alphanumerics plus `.`, `_`, `-`, with arbitrary
JSON values; `credential-operation` additionally requires `value`. `host-account`
is the one kind that also constrains its context, because an account credential
that does not name its host cannot be matched to the host it opens.

`context` carries provenance rather than secrets: `source_kind`, `provider`,
`account_ref`, `tenant_ref`, `request_id`, `operation`, `session_label`,
`login_method`, `name`, `login_url`, and `domains` are the recognized keys, and
`migrate-v2` maps legacy metadata onto them.

Example — a Brama Desktop provider subscription is a `bundle` discovered by
tags, not by its id: `brama:subscription` marks the role, `brama:agent:<agent>`
scopes it to an agent, and `brama:provider:` / `brama:id:` carry the provider
and subscription id. The item id itself is opaque; renaming it breaks nothing.

```sh
printf '%s' '{"schema":"skarbiec.item.v2","kind":"bundle",
  "fields":{"value":"..."},
  "context":{"source_kind":"ai-cli","provider":"codex"}}' |
  skarbiec set-json provider:codex:brama-sub-wisent-app-codex-primary \
    --recipients 'skarbiec-owner-20260728 <lukaszbartoszcze@wisent.ai>' \
    --tags 'brama:subscription,brama:agent:wisent-app,brama:provider:codex,brama:id:brama-sub-wisent-app-codex-primary'
```

### Tag namespaces: role, not shape

`kind` states what shape a secret has. What an item is *for* belongs in `tags`,
and a consumer that needs to find its own items MUST filter on them. Parsing an
item id is not a discovery mechanism: a rename then silently removes the item
from a listing, while a wrong tag is visible in `list`.

Two properties make tags the only candidate. They are plaintext in the envelope,
so `list` and a `sync:pull` document expose them without a recipient key, while
`fields` and `context` are inside the ciphertext and unreadable to a consumer
holding only field grants. And they are a set, so one item can carry several
independent roles where an id can encode one hierarchy.

| Namespace | Owner | Meaning |
|---|---|---|
| `managed:weles` | Weles | Externally managed credential; owner mutation is refused in favour of the `credential` lifecycle. Reserved — `set`, `set-json` and `import` refuse it. |
| `brama:subscription` | Brama | The item is a provider subscription. |
| `brama:agent:<agent>` | Brama | Which agent owns that subscription; repeated per agent. |
| `brama:provider:<provider>` | Brama | Provider family the credential belongs to. |
| `brama:id:<id>` | Brama | Subscription id the control plane and its clients exchange. |
| `fleet:host-account` | Stado | The item is one fleet host's operating-system account. |
| `fleet:target:<name>` | Stado | The registry target that account belongs to; a reader with a host name filters on this. |
| `fleet:tailnet-tls` | Stado | The item is a private certificate authority the fleet's tailnet endpoints are anchored on; its `private_key` is the only copy. |

Rules for a new namespace:

1. Shape it `<product>:<role>[:<value>]`, lowercase, and register it in this
   table in the same commit that starts writing it.
2. Never put a secret, a token, or a personal identifier in a tag — anything
   holding a list or pull grant reads them.
3. Never make a tag the only record of a credential's meaning that a human
   needs; `context` remains the provenance of record inside the ciphertext.
4. A consumer reading a namespace it does not own is doing discovery on someone
   else's contract; give it its own tag instead.

### Fleet host accounts

The operating-system account of a fleet host is a credential, so it lives here as
a `host-account` item and nowhere else. The registry carries only the pointer:
the target gains `account_ref` holding the item id, which is the fleet's one way
from a host name to that host's account. `read-host-account.py <target>` in
wisent-compute follows the pointer and reports the username, the password's
length and digest, and which consumers hold a capability on the item — never the
value. When the value is genuinely needed,
`stado host install-credential <host> <item> password <basename>` delivers that
one field to that one host as an owner-only file and prints nothing. That command
authenticates as a Skarbiec consumer, so the consumer it uses must hold
`read:<item>#password` and the `serve` process answering it must have that grant
loaded: a capability minted after a long-running service started is not in effect
until the service reads the vault again, and an unloaded grant is indistinguishable
from a missing one at the HTTP boundary.

A chat transcript is not a credential store. An operator who hands over a machine
account in a session has told exactly one agent, once: the next agent cannot read
it, no consumer can read it, and nothing rotates it. Store it during the session
it arrives, through an owner-only delivery file that `put-host-account.py` reads,
pipes into `set-json` on stdin, and deletes — so the value never reaches argv, a
shell history, or a log.

A `host-account` is deliberately not a `login`. Login trajectories enumerate
`login` items to drive browsers, and a host account inside that set would be
typed into a web form. The two kinds stay disjoint, which is why this one exists
rather than a `login` with a tag on it.

Holding the account licenses nothing further about the host. Automatic login,
`/etc/kcpassword`, and any other change to a host's security posture remain
refused: the credential exists so a repair can authenticate, not so a machine can
be left unlocked.

Where it must **not** be is part of the convention. A `host-account` exists so
something else can authenticate *to* that host, so it belongs in the vault of
whoever does the authenticating and never in the vault of the machine it opens:
a host holding its own admin account means taking the host also hands over the
account. `read-host-account.py` encodes exactly that — run on the host a target
names, an absent item is reported as correct posture, and a present one is a
fault. Note that `$HOME/.stado/skarbiec.vault.json` is a path rather than an
identity: several fleet hosts have one, with the same owner key and different
item sets, so `wisent-compute/scripts/audit-vault-identity.py` prints a
comparable owner/count/id-digest line per host and names any two credential
paths that a reader would treat as one and that disagree.

### Fleet certificate authorities

A private certificate authority the fleet anchors on is a `certificate` item here,
carrying both `certificate` and `private_key`, tagged `fleet:tailnet-tls`, in the
vault of the host that serves under it. The item id is named from the unit and the
installers that reference the certificate paths, so an operator reads an id rather
than searching a filesystem.

That is written down because of what it cost when it was not. The fleet's tailnet
authority was minted by hand on one host and its private key was never kept:
establishing that took an exact search of 845 candidate files across three hosts,
comparing each candidate's derived public half against the certificate's, and the
conclusion turned a re-issue into a replacement that re-anchored every consumer.
An authority whose key exists only in a shell's history is a fleet-wide outage with
a delay on it.

Two properties of the certificate matter as much as the key. `basicConstraints`
must be `critical,CA:TRUE` and `keyUsage` must be `critical,keyCertSign,cRLSign`:
an anchor missing the latter is accepted by macOS and refused by OpenSSL as `CA
cert does not include key usage extension`, so a fleet can appear to work for
months while every Linux host is quietly excluded from the store.

### Finding an item

There are two searchable surfaces, and they are not equally visible.

The **envelope** — id, `kind`, `tags`, recipients — is plaintext. `list` returns
it, a `sync:pull` document carries it, and any holder of either can index it.
The **context** — which account, service or session a credential belongs to —
lives inside the ciphertext. No grant holder can search it, and no listing can
index it, which is deliberate: the map of what this vault holds is itself
sensitive.

So an owner holding the key is the only party that can answer "which items
belong to this service", and `scripts/search-items.py` is that query. It opens
each item locally and matches the pattern against the id, tags, field names and
context, printing coordinates and never a value:

```sh
python3 scripts/search-items.py gmail          # id, tags and context
python3 scripts/search-items.py --fast google   # envelope only, opens nothing
python3 scripts/search-items.py --json drive    # machine-readable
```

Two consequences worth stating, because both have already cost time:

- **An id is not an index.** Adding a searchable dimension to a name makes every
  consumer parse names, and a rename then silently changes results. Put the
  dimension in a tag when grant holders must see it, in `context` when only the
  owner should.
- **A context match is not a credential for that service.** `account_ref` records
  which account a login was registered with, so a query for a mail domain returns
  every account that used an address there. Read `source_kind` to separate the
  credential of a service from an account merely named after one.

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

Every `credential` command is a thin client of the canonical Skarbiec, which is
the only remote hop of a credential lifecycle. The endpoint comes from
`${STADO_FORWARDS_DIR:-$HOME/.stado/forwards}/skarbiec.local`: an owner-owned
regular file without group or world write, holding exactly one `https` URL or
one loopback `http` URL with an exact port. Anything else fails closed as
`SKARBIEC_ENDPOINT_UNRESOLVED`, and a canonical endpoint this binary cannot
reach without a TLS client fails as `SKARBIEC_ENDPOINT_TLS_UNSUPPORTED`. A `409`
reply that reports a stale service directory is surfaced as
`SERVICE_DIRECTORY_STALE`. Client calls authenticate with `--as <caller>` and
`--token-file <path>` (or `SKARBIEC_CREDENTIAL_TOKEN_FILE`); the bearer is read
from an owner-only file so it never reaches argv.

`--local` is the only way to act on this vault file directly. `adopt`,
`seal-directory`, `reseal`, and `resolve-quarantine` hold the vault file and the
operator's own secrets, so they exist only in local mode.

### Which vault file is the canonical one

One vault file is the canonical Skarbiec for a directory credential, and the
`--local` commands — `adopt`, `seal-directory`, `reseal`, `resolve-quarantine`
— must run against that exact file, on the host that holds it. A second vault
on a second machine may well hold an item with the same id; sealing a contract
or rotating a password there produces a credential nobody reads.

Skarbiec never infers that file from a path, a hostname, or a default. The
criterion that decides it, for one exact item:

1. The vault where both consumers of that item are registered: the writer
   holding `write:<item-id>` and the reader bound to the field the item
   carries.
2. Which is the same vault backing the Skarbiec service declared for that
   credential in the Stado registry — the service this host's launcher starts.
3. And in which the item itself is live.

All three name one file, or the question is not settled yet. An operator
confirms a candidate read-only before deciding:

```
SKARBIEC_VAULT_FILE=<candidate>.vault.json skarbiec tokens
SKARBIEC_VAULT_FILE=<candidate>.vault.json skarbiec list
SKARBIEC_VAULT_FILE=<candidate>.vault.json skarbiec credential status <item-id> --local
```

The first names the registered consumers and the exact field each one reads,
the second proves the item is live in that file, and the third reports whether
it is eligible for a lifecycle at all. Where two candidate files exist on two
machines, choosing between them is an operator decision made once and recorded;
running a lifecycle against the wrong one is not recoverable by rerunning it
against the right one.

### Directory identity is an item contract, never a call argument

An item carries its directory identity as a sealed block written once:

```json
{
  "provider": "microsoft_entra",
  "tenant_id": "23572277-0021-42ac-b2b9-10bd86c7d2af",
  "principal_object_id": "4c888895-03cf-4ab1-a11e-46942c568217",
  "account_upn": "jakub@wisent.ai",
  "sealed_at": "2026-08-05T09:14:02Z"
}
```

No lifecycle command accepts that identity: Skarbiec reads it from the item and
puts the four canonical fields on the wire itself, so no caller can rotate one
principal's password while naming another. `sealed_at` stays item-local. The
sealed block lives in the item's canonical `context.directory` and, so it also
survives an item that does not exist yet, in an owner-controlled record at
`directory:credential/<item-id>`. The two copies must agree; a divergence is
`DIRECTORY_CONTRACT_DIVERGED` and refuses every operation until a reseal.

`--expect-tenant`, `--expect-object-id`, and `--expect-upn` are a cross-check
only. They supply nothing: a value that does not match the sealed contract fails
as `DIRECTORY_EXPECTATION_MISMATCH` before anything reaches the bridge.

| Command | What it does |
| --- | --- |
| `credential seal-directory <item-id> --provider <p> --tenant <uuid> --object-id <uuid> --account-upn <email> --local` | Seal the directory identity of one item, once. The item does not have to exist yet. An item that already carries a sealed contract is refused. |
| `credential reseal <item-id> --provider <p> --tenant <uuid> --object-id <uuid> --account-upn <email> --as <consumer> --token-file <path> --local` | Replace a sealed contract. Requires a `reseal` capability on that exact item. No lifecycle operation ever writes or overwrites the block. |
| `credential acquire <item-id> --consumer <consumer> [--purpose <purpose>]` | Acquire a new provider credential Weles generates. A pre-existing local item without Weles provenance is rejected rather than reported as ready. |
| `credential adopt <item-id> --provider <p> --consumer <consumer> --password-stdin --local` | Take over a password the operator already knows. The password is read from stdin only, never from argv or an endpoint body, and its buffer is zeroed after use. Skarbiec stages the candidate, Weles performs a fresh login and returns only a verdict, and the value is committed on `operation_completed`. After a committed adopt the item is `managed` and `rotate` is available. An item that is already `managed` is refused. |
| `credential rotate <item-id> --consumer <consumer> [--purpose <purpose>]` | Rotate a credential whose current value Skarbiec already manages. Because the current value is known, a failed change can be rolled back. |
| `credential reset <item-id> --consumer <consumer> [--purpose <purpose>]` | Set a new password when the current one is unknown, so no rollback value exists. Interactive identity verification stops as `needs_human_approval`; a reset is never queued as a `rotate`. Directory providers only. |
| `credential verify <item-id> --consumer <consumer> [--purpose <purpose>]` | Authenticate the stored value at the provider with a fresh login and rewrite the same value with this request as provenance. |
| `credential remove <item-id> --consumer <consumer> [--purpose <purpose>]` | Request provider-side revocation and local removal. Providers without a safe revocation contract fail closed. |
| `credential resume <item-id> --approval <id> --resume-token <token>` | Resume the operation that stopped as `needs_human_approval`. `--resume-token-file <path>` reads the token from an owner-only file instead of argv. Resubmitting the operation is not a way to resume it. |
| `credential resolve-quarantine <item-id> --confirm '<phrase>' [--staged keep\|activate\|discard] --as <consumer> --token-file <path> --local` | Settle a quarantined item. Requires an `admin` capability on that exact item (on its operation record when the item does not exist) and the exact confirmation phrase `I know which password this provider account accepts`. Writes an audit entry and returns the item to `unmanaged`, so knowing the password again is always an explicit act. |
| `credential status <item-id> [--follow]` | Poll the exact Weles action-log ID, persist queued/failure/review/completed state, commit or roll back the staged revision, and report the item's lifecycle state, receipt, quarantine block, and whether it is eligible for a lifecycle at all. `--follow` repeats that same persisted poll every 5 seconds for at most 30 minutes. |
| `credential declare-endpoint [<url>]` | Write the owner-only forward file every remote `credential` call resolves. Defaults to `http://127.0.0.1:8787`, the port `serve` binds. Validated through the same reader the calls use, so a file this writes is never one they refuse, and the report says whether anything answers. |

`--dry-run` is a local-mode flag: it plans one operation without taking the
operation lock or writing a request record. `adopt` has no dry run because it
would have to read the operator's password for nothing.

A fresh installation has no forward file, so every remote `credential` call
refuses with `SKARBIEC_ENDPOINT_UNRESOLVED` until one exists. Until
`declare-endpoint`, nothing in this product created it: the reader enforced a
precise contract — owner-owned, no group or world write, exactly one bounded
URL naming host and port and no path — that an operator had to satisfy by
hand, from the error message alone.

```console
$ skarbiec credential declare-endpoint
{
  "forward": "/Users/you/.stado/forwards/skarbiec.local",
  "endpoint": "http://127.0.0.1:8787",
  "authority": "127.0.0.1:8787",
  "answering": true
}
```

`answering` is reported separately from the write on purpose: whether the
declaration is well formed and whether a service is up are different
questions, and a bare connection error answers neither.

### The item's field is a contract, not a mapping

A provider contract writes one exact field: `password` for `microsoft_entra`
and `microsoft`, `api_key` for anything else. Before a managed item begins any
operation, Skarbiec checks that the item already carries that exact field. An
item whose field is named something else — `login_password`, say — is refused
as `CREDENTIAL_FIELD_CONTRACT_MISMATCH`, naming both the field the item carries
and the field the contract writes.

There is no alias, and no automatic migration. Mapping one name onto the other
is what allowed one credential to be known by two names in the first place, and
a lifecycle that wrote `password` beside `login_password` would leave the
password the provider now accepts in a key none of that item's readers resolve.
An item with a non-canonical field is not eligible for a lifecycle, and making
it eligible is an explicit operator decision:

1. Establish which name is canonical for that item, and which name its
   registered readers actually read (`skarbiec tokens`).
2. Move the item and every consumer registration onto that one name, or leave
   the item outside the lifecycle entirely.
3. Only then seal its directory contract and run the first operation.

Skarbiec takes none of those steps on an operator's behalf, and refuses every
operation until they are taken.

### One command answers why an item is not ready

`credential status` reports `lifecycle_eligible`, and whenever it is false,
every reason at once in `lifecycle_blockers`. Readiness is one question with
one answer, not one refused operation per reason:

| `reason` | What it means |
| --- | --- |
| `legacy_envelope` | The item still uses the pre-v2 envelope; run `migrate-v2`. Its payload cannot be read at all, so its field cannot be judged until that envelope is gone. |
| `noncanonical_field` | The item's field is not the one its provider contract writes. The detail names both. |
| `no_directory_contract` | No sealed directory block resolves for the item, or its two copies disagree. |
| `quarantined` | The item is frozen until `credential resolve-quarantine` settles it. |

```json
{
  "lifecycle_eligible": false,
  "lifecycle_blockers": [
    {"reason": "legacy_envelope", "detail": "<item-id> still uses the pre-v2 envelope; run migrate-v2 before any lifecycle operation"},
    {"reason": "no_directory_contract", "detail": "<item-id> has no sealed directory block; seal it with credential seal-directory before any lifecycle operation"}
  ]
}
```

The list is never cut short at the first reason found, and an empty list with
`lifecycle_eligible: true` is the only statement that an item is ready.

### Provider effect and retries

Every response carries what the operation did to the password the provider
accepts:

| `provider_effect` | Automatic retry |
| --- | --- |
| `none` | Allowed. |
| `changed` | Refused until a `verify` succeeds or a rollback is confirmed (`PROVIDER_EFFECT_CHANGED_RETRY_BLOCKED`). |
| `unknown` | Always refused. The item is quarantined. |

A rollback reported as `failed` or `unknown` quarantines the item for the same
reason: nobody knows which password is live. So does a failed operation that
reports `changed` without a confirmed rollback — the provider may hold exactly
the value Skarbiec staged, so that staged candidate is frozen rather than rolled
back away, and `credential resolve-quarantine --staged activate` is how an
operator adopts it once they have checked.

### Item lifecycle states

`unmanaged`, `managed`, `adopting`, or `quarantined`. An unknown stored state is
a refusal, not a guess.

A quarantined item blocks every operation until `credential
resolve-quarantine`. The freeze is recorded in the operation record, as an item
tag, and — whenever the item has no staged revision to preserve — in
`context.quarantine`. A staged candidate is never discarded on the way into
quarantine, because it may be the value the provider now accepts; `--staged`
decides its fate at resolution time.

`adopting` means an operator-supplied candidate is in flight. Such an item never
reports as externally verified, and the candidate is readable only by the adopt
verification path: an active adopt for that exact item, request ID, field, and
presenting consumer. Any other read is refused. Because an item can only enter
Weles management at creation, `adopt` is the sole legitimate entry point into
`managed` for a password whose value is already known; if adopt created the item
and then failed, it trashes exactly what it created and nothing else.

### Approval as a resource

A `needs_human_approval` response carries all six fields or none:

```json
{
  "approval": {
    "approval_id": "review-8842",
    "phase": "identity_verification",
    "provider_effect": "none",
    "expires_at": "2026-08-05T10:14:02Z",
    "resume_token": "0f3c...",
    "instruction": "Approve the sign-in prompt on the enrolled device."
  }
}
```

`credential resume` refuses an approval that does not match the waiting
operation, and an expired `expires_at` releases the operation instead of
resuming it: the staged candidate goes back, the record stops blocking, and a
fresh submit is the only way forward (`APPROVAL_EXPIRED`).

### Receipt persisted with the revision it proves

After a terminal success Skarbiec stores a receipt in the item's
`context.receipt`, so `credential status` answers "was exactly this principal
rotated" without reading a mailbox or a log:

```json
{
  "receipt": {
    "tenant_id": "23572277-0021-42ac-b2b9-10bd86c7d2af",
    "principal_object_id": "4c888895-03cf-4ab1-a11e-46942c568217",
    "account_upn": "jakub@wisent.ai",
    "operation": "rotate",
    "request_id": "<64 hex>",
    "evidence_digest": "<64 hex>",
    "execution_host": "weles-worker-3",
    "changed_at": "2026-08-05T09:41:55Z",
    "verified_at": "2026-08-05T09:42:07Z",
    "action_log_id": "task-77213"
  }
}
```

`changed_at` may be null, `verified_at` may not, and `request_id` and
`evidence_digest` are 64 hexadecimal characters. A receipt naming another
principal, request, or operation rejects the whole response. For provider
`microsoft_entra` a completed operation without a valid receipt cannot be
attributed to the sealed principal, so the item is quarantined instead of
committed.

### Serve endpoints

| Endpoint | What it does |
| --- | --- |
| `POST /v1/credential/operations` | Submit or resume one operation. Body: `{item, operation, consumer, purpose?, expect?, approval?, resume_token?}`. It carries no directory identity and no provider: both come from the item contract, so an item with neither a sealed contract nor an earlier operation fails closed. `adopt` is refused here because its password only exists on operator stdin. |
| `GET /v1/credential/operations/<item-id>` | The persisted state of that item's operation, with its receipt and quarantine block. The poll can commit a staged revision, so it serializes with every other writer. |

Both endpoints require one exact `lifecycle` capability on that exact item, and
`lifecycle` never authorizes reading a credential value.

### Bridge contract

`SKARBIEC_WELES_CREDENTIAL_COMMAND` must name an absolute, owner-controlled,
non-symlink executable. Skarbiec passes `skarbiec.credential-operation.v3` JSON
on stdin and accepts only a bounded, sanitized JSON response on stdout. Wire
versions `v1` and `v2` are not accepted anywhere, including in persisted
operation records. The bridge owns the finite mapping from item IDs to Weles
lifecycle contracts; an unknown item/provider/field/writer-consumer or operation
tuple fails closed. The bridge resolves the Weles admission endpoint through the
Stado forward directory
(`${STADO_FORWARDS_DIR:-$HOME/.stado/forwards}/weles-admission.local`) on the
Weles host loopback, never from a `WELES_URL` environment variable; an absent or
unsafe forward file is an explicit `needs_configuration` failure.

Provider `microsoft_entra` requires a sealed directory contract, always writes
canonical field `password`, and accepts only `adopt`, `rotate`, `verify`, and
`reset`. Provider `microsoft` requires `--account <email>` and no sealed
contract. Any other combination fails closed instead of guessing a contract.

Beyond `status`, `message`, and the action-log IDs, Skarbiec accepts and emits
these diagnostic fields when Weles reports them. Any value outside the accepted
set rejects the whole response.

| Field | Meaning |
| --- | --- |
| `code` | Machine-readable cause, `^[A-Z][A-Z0-9_]{0,63}$`, for example `ENTRA_IDENTITY_MISMATCH`. |
| `phase` | Where the operation stopped: `admission`, `placement`, `credential_read`, `entra_sign_in`, `identity_verification`, `password_change`, `fresh_login_verification`, `skarbiec_stage`, `skarbiec_commit`, or `rollback`. |
| `retryable` | Whether the same request can be resubmitted unchanged. |
| `provider_effect` | `none`, `changed`, or `unknown`: what the operation did to the password the provider accepts. |
| `rollback_status` | `none`, `completed`, `failed`, or `unknown`. |
| `execution_host` | Worker host that ran the trajectory. |
| `tenant_id`, `principal_object_id` | Directory identity Weles acted on; a mismatch with the sealed contract rejects the response. |
| `approval` | The approval resource described above. |
| `receipt` | The receipt described above. |

Install the bridge from the public
[`wisent-ai/weles-client`](https://github.com/wisent-ai/weles-client)
repository, then configure the organization-scoped hosted service values:

```sh
git clone https://github.com/wisent-ai/weles-client
npm install --global ./weles-client

export WISENT_ORGANIZATION_ID=<organization-uuid>
export WELES_TOKEN=<organization-scoped-token>
export SKARBIEC_WELES_CREDENTIAL_COMMAND="$(npm root --global)/@wisent-ai/weles-client/bin/weles-skarbiec-acquire.mjs"

skarbiec credential seal-directory weles-microsoft-jakub-wisent-ai-password \
  --provider microsoft_entra \
  --tenant 23572277-0021-42ac-b2b9-10bd86c7d2af \
  --object-id 4c888895-03cf-4ab1-a11e-46942c568217 \
  --account-upn jakub@wisent.ai \
  --local

printf '%s' "$CURRENT_PASSWORD" | skarbiec credential adopt \
  weles-microsoft-jakub-wisent-ai-password \
  --provider microsoft_entra \
  --consumer weles-microsoft-jakub-wisent-ai-password-writer \
  --local --password-stdin

skarbiec credential rotate weles-microsoft-jakub-wisent-ai-password \
  --consumer weles-microsoft-jakub-wisent-ai-password-writer \
  --expect-upn jakub@wisent.ai \
  --purpose incident-remediation \
  --as skarbiec-operator --token-file /etc/skarbiec/lifecycle.token

skarbiec credential status weles-microsoft-jakub-wisent-ai-password --follow --local
```

The Snapchat contract writes canonical field `api_key` to
`weles-snapchat-snap-kit-api`. Before queueing a real acquisition, provision
the Weles host with the exact `stage:weles-snapchat-snap-kit-api#api_key`
capability in the owner-only writer token file; no broader writer or global
bearer is accepted.

Entra password adoption, rotation, reset, and verification use item IDs matching
`weles-microsoft-<account-alias>-password`, and the exact account is bound by the
sealed directory contract of that item. The two accounts this exists for today
are `weles-microsoft-jakub-wisent-ai-password` (`jakub@wisent.ai`, object ID
`4c888895-03cf-4ab1-a11e-46942c568217`) and
`weles-microsoft-lukasz-wisent-com-password` (`lukasz@wisent.com`, object ID
`1f636f97-b07f-4e9b-952a-5d069ccc5b20`), both in tenant
`23572277-0021-42ac-b2b9-10bd86c7d2af`. Weles writes canonical `username` and
`password` fields plus protected request and operation metadata through
item-specific `stage` capabilities. It confirms the signed-in tenant, object ID,
and UPN before touching the password and again after the fresh login, changes the
provider first, and only then writes the managed item. MFA or passkey challenges
stop as `needs_human_approval` without changing Skarbiec.

Once an item carries Weles provenance, owner-side `set`, `set-json`, `delete`,
`restore`, `purge`, `restore-version`, and import overwrites are refused. Use
the matching `credential` lifecycle operation so local and provider state
cannot be changed independently. Operation records
(`operation:credential/<item-id>`) and sealed directory contracts
(`directory:credential/<item-id>`) are owned end to end by the lifecycle: no
item API, import, or donation may touch them.

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
| `token-mint <consumer> --capabilities action:item[#field] [--workload-public-key-file PATH] [--ttl-seconds N] [--audience NAME] [--replace-capabilities]` | Register exact structured capabilities. `acquire`, `stage`, `rotate`, and `verify` require a field; `share`, `trash`, `purge`, `admin`, `lifecycle`, and `reseal` are item-scoped and must not name one. `lifecycle` drives credential operations on that exact item and grants no read of its value, so it cannot share a grant with a `read` capability; `reseal` may replace that item's sealed directory contract. `acquire` requires an Ed25519 workload public key and returns no standing bearer; direct capabilities return a bearer once and retain only its hash. The TTL defaults to 30 days and the audience to the consumer. Replacing a different existing capability set requires `--replace-capabilities`. |
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
| `audit [--limit N]` | Print the append-only journal, oldest first. `--limit` returns only the final N, read from the file's tail instead of parsing the whole journal. |
| `audit-query [--op OP] [--consumer ID] [--item ID] [--since ISO] [--until ISO] [--limit N]` | Query local provenance by operation, workload consumer, item, and time window. Returns the newest matching bounded slice in chronological order. |
| `verify-chain [--tail N]` | Verify the hash chain and name the journal verified. |

`verify-chain` reports two properties apart, because they fail for different
reasons and cost different amounts:

- **Linkage** — each line's recorded predecessor is the line before it. Two
  string comparisons, so it always covers the whole journal. This is what a
  second process breaks when it appends against a tail another process has
  already moved.
- **Digests** — the line's own fields still hash to the hash it carries. This
  is what a retroactive edit breaks, and it costs one `shasum` process per
  line: a 75,000-entry journal takes about fifteen minutes. `--tail N` bounds
  it to the newest N lines.

Neither scan stops at the first fault, and the report names the file it read.
That matters more than it sounds: this binary's default journal
(`~/.local/state/skarbiec/audit.jsonl`) and the journal Stado gives its
callers (`$SKARBIEC_AUDIT_FILE`) are different files, so an unqualified
`intact: true` over an empty default reads exactly like a clean bill of health
for the vault actually in service.

```json
{
  "journal": "/Users/you/.stado/skarbiec.audit.jsonl",
  "entries": 74982,
  "linkage_checked": 74982,
  "linkage_verified": 74981,
  "digests_checked": 200,
  "digests_verified": 200,
  "intact": false,
  "broken_at": "2026-07-30T23:16:21Z",
  "faults": [{"line": 2311, "at": "2026-07-30T23:16:21Z", "op": "http-item-read", "fault": "linkage"}]
}
```

## Diagnosis

| Command | What it does |
| --- | --- |
| `doctor` | Report the vault, the audit chain, the canonical endpoint, and WORM receipts, each as `pass`, `fail`, or `not_configured`, with a tally. |

`doctor` reads the vault file, the journal, the forward marker and a socket
directly — never through the HTTP API it is diagnosing — so it still answers
when that API does not. `not_configured` is deliberately not a failure: a
fresh install has switched on no WORM receipts, and calling that an outage
teaches an operator that red means nothing.

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
| `sync-init <remote-url>` | Initialize `SKARBIEC_SYNC_DIR` as a Git repository, replace its `origin` with the exact remote URL, and configure the repository-local automated commit identity. |
| `sync-push [--branch NAME] [--message TEXT]` | Copy the live vault to `vault.enc.json`, commit it, and push the current `HEAD` to the selected remote branch. The branch defaults to `main`; the message defaults to `skarbiec sync`. A no-op commit is allowed. |
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
