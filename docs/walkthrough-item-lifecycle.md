# Walkthrough: one item's whole life

Executed against a disposable vault on 2026-08-24 with a source build
(`cargo build`, `target/debug/skarbiec`). Every block below is pasted
output. The demo values are not secrets.

## Isolation

Everything lives under one temporary directory; removing it removes every
trace. `HOME` is overridden so even `doctor`'s endpoint probe reads no
operator state:

```sh
export HOME=/tmp/skarbiec-wt-item
export GNUPGHOME=/tmp/skarbiec-wt-item/gnupg          # fresh keyring, mode 0700
export SKARBIEC_VAULT_FILE=/tmp/skarbiec-wt-item/demo.vault.json
export SKARBIEC_AUDIT_FILE=/tmp/skarbiec-wt-item/demo.audit.jsonl
```

`gpg`, OpenSSL 3, and `shasum` must be on the PATH
([configuration](configuration.md#external-tools)).

## Create, write, write again

```text
$ skarbiec init demo-owner
{
  "ok": true,
  "owner_fpr": "F9AE755BFAF3D7471FF69D99407F0FBBB5D1CB78",
  "recovery_fpr": "B25D486ED54EE04BB0BBBD84B5D65687AE635465",
  "vault": "/tmp/skarbiec-wt-item/demo.vault.json"
}

$ skarbiec set demo-api --type token token=demo-value-one --tags demo,walkthrough
{
  "id": "demo-api",
  "kind": "token",
  "ok": true
}

$ skarbiec set demo-api --type token token=demo-value-two --tags demo,walkthrough
{
  "id": "demo-api",
  "kind": "token",
  "ok": true
}

$ skarbiec get demo-api
{
  "context": {},
  "fields": {
    "token": "demo-value-two"
  },
  "kind": "token",
  "schema": "skarbiec.item.v2"
}
```

The second write did not replace the first: it pushed revision 1 into
`history` ([item](concepts/item.md#lifecycle)).

## Roll back by timestamp

`restore-version <id> <at>` names a version by its `created_at`. The
envelope is plaintext metadata, so the timestamps are readable without any
key — which is also the demonstration that they are not secrets
([SECURITY.md](SECURITY.md#what-is-encrypted-and-what-is-not)):

```text
$ jq '.items["demo-api"].history[].created_at' demo.vault.json
"2026-08-24T22:34:05Z"

$ skarbiec restore-version demo-api 2026-08-24T22:34:05Z
{
  "ok": true
}

$ skarbiec get demo-api
{
  "context": {},
  "fields": {
    "token": "demo-value-one"
  },
  "kind": "token",
  "schema": "skarbiec.item.v2"
}

$ skarbiec list
[
  {
    "deleted": false,
    "id": "demo-api",
    "kind": "token",
    "management": {
      "controller": "demo-owner",
      "mode": "owner"
    },
    "recipients": [],
    "revision": 3,
    "state": "active",
    "tags": ["demo", "walkthrough"],
    "updated_at": "2026-08-24T22:34:07Z",
    "versions": 3
  }
]
```

Note `revision: 3`: the rollback re-encrypted the old payload as a *new*
revision instead of activating historical ciphertext in place. A wrong
timestamp is refused with `Error: no version at <at> for demo-api`.

## Trash, refuse, restore

```text
$ skarbiec delete demo-api
{
  "ok": true
}

$ skarbiec list
[]

$ skarbiec get demo-api
Error: item is in trash: demo-api (restore it first)

$ skarbiec restore demo-api
{
  "ok": true
}
```

`list` hides the trashed item (`list --all` would show it with
`"deleted": true`); reading it is refused with the way out in the sentence
([trash and purge](concepts/trash-and-purge.md)).

## Purge, and what a purged item answers

```text
$ skarbiec delete demo-api
{
  "ok": true
}

$ skarbiec purge demo-api
{
  "ok": true
}

$ skarbiec purge demo-api
Error: use the item's controlling lifecycle instead of direct owner remove

Caused by:
    item not found: demo-api

$ skarbiec restore demo-api   # after purge
Error: use the item's controlling lifecycle instead of direct owner acquire

Caused by:
    item not found: demo-api
```

A missing item surfaces through the owner-mutation gate, so the top line is
the gate's sentence (verb `remove` for purge, `acquire` for restore) and the
cause underneath is the fact ([item](concepts/item.md#who-may-write-it)).

## The record

The journal carries exactly one `item-write` per revision — three writes,
three entries; trash, restore, and purge appended nothing:

```text
$ skarbiec audit --limit 3
[
  {
    "at": "2026-08-24T22:34:05Z",
    "extra": {
      "item": "demo-api", "kind": "token", "revision": 1,
      "tags": 2, "tags_requested": 2,
      "pid": 16953, "process": ".../target/debug/skarbiec",
      "parent_pid": "16907", "parent_process": "sh"
    },
    "hash": "f1828832eae6b5446169fbe8f54d4d0dbc8b3af5379e6539af2bef6798dfa65a",
    "op": "item-write",
    "prev": ""
  },
  { "...": "revision 2, prev = hash of revision 1's line" },
  { "...": "revision 3, prev = hash of revision 2's line" }
]

$ skarbiec verify-chain
{
  "broken_at": null,
  "digests_checked": 3,
  "digests_verified": 3,
  "entries": 3,
  "faults": [],
  "intact": true,
  "journal": "/tmp/skarbiec-wt-item/demo.audit.jsonl",
  "linkage_checked": 3,
  "linkage_verified": 3
}

$ skarbiec doctor
{
  "checks": [
    {"check": "vault",    "status": "pass",
     "detail": "0 items, 0 grants, at /tmp/skarbiec-wt-item/demo.vault.json"},
    {"check": "audit",    "status": "pass",
     "detail": "3 of 3 entries linked, newest 3 digests intact, in /tmp/skarbiec-wt-item/demo.audit.jsonl"},
    {"check": "endpoint", "status": "not_configured",
     "detail": "SKARBIEC_ENDPOINT_UNRESOLVED: no canonical forward at /tmp/skarbiec-wt-item/.stado/forwards/skarbiec.local; declare it with `skarbiec credential declare-endpoint <url>`"},
    {"check": "worm",     "status": "not_configured",
     "detail": "set SKARBIEC_WORM_RECEIPT_DIR and SKARBIEC_WORM_CHECKPOINT to enable write-once receipts"}
  ],
  "failed": 0,
  "not_configured": 2,
  "pass": 2
}
```

`doctor` on a fresh isolated vault: two passes, two `not_configured`, zero
failures — `not_configured` is "nobody switched this on", never an outage
([WORM audit](concepts/worm-audit.md)).

## Cleanup

```sh
rm -rf /tmp/skarbiec-wt-item
```

The vault, keyring, journal, and every lock file live under that one
directory; nothing else on the machine changed.
