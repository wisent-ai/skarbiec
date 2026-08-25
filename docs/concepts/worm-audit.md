# WORM audit

Two write-once surfaces prove what a vault did: the hash-chained audit
journal every mutation appends to, and the optional write-once receipt store
`doctor` checks. Neither ever carries a stored value — "only operation names
and non-sensitive identifiers" (`src/runtime/audit.rs`).

## The journal

One JSON line per event, at `SKARBIEC_AUDIT_FILE` (default
`~/.local/state/skarbiec/audit.jsonl`, directory forced to `0700`, file to
`0600`):

```json
{"at": "2026-08-24T22:34:05Z",
 "op": "item-write",
 "extra": {"item": "demo-api", "kind": "token", "revision": 1,
           "tags": 2, "tags_requested": 2,
           "pid": 16953, "process": ".../skarbiec", "parent_pid": "16907", "parent_process": "sh"},
 "prev": "",
 "hash": "f1828832…"}
```

- `prev` is the previous line's `hash`; the genesis line carries `""`. Each
  `hash` is `sha256(prev|at|op|extra)`, so any retroactive edit breaks every
  hash after it.
- `extra` names identifiers only — item, field, consumer, kind, revision —
  never a value. Writes additionally record pid, process, and parent
  process, and both `tags` (stored) and `tags_requested` (passed), so a tag
  count that falls to zero names the writer that emptied it
  ([tag](tag.md)).
- Mutating operations append synchronously (`append_sync`) so evidence is
  durable before the response returns; high-frequency read paths enqueue to
  one background worker so hashing (two subprocess spawns per line) never
  lands on a consumer's latency.

## One journal, many processes

Appends are read-modify-write on the chain tail, so they serialize behind a
lock *file* beside the journal (`<journal>.append.lock`) — a process-wide
mutex cannot see the other process. The comments record the incident that
forced this: on 2026-07-30 a mutating command raced an HTTP read, two
writers each read the same tail, and one doubled `prev` made `verify-chain`
refuse the whole record. A waiting writer gives up after five seconds:

```text
Error: audit journal lock <path>.append.lock is still held; no entry was written
```

A lock file older than 30 seconds is treated as abandoned (a holder that
died leaves a file nobody removes) and is deleted by the next writer. Both
numbers are in `acquire_append_lock` / `lock_is_abandoned`; the
[runbook](../runbook.md#audit-journal-lock-is-still-held) shows this failing
live and what to do.

## Verifying the chain

`verify-chain` checks three properties:

- **Linkage** — each ordinary line's `prev` is the line before it.
- **Epoch signature** — a new period carries a GPG-signed checkpoint naming the
  prior tail, so historical damage is preserved rather than rewritten.
- **Digest** — each line's fields still hash to the `hash` it carries. A
  retroactive edit breaks this. SHA-256 runs in-process; `--tail N` bounds CPU
  and disk work, and `doctor` uses `--tail 200`.

Neither scan stops at the first fault — stopping is what hid seventy-two
thousand well-formed entries behind one raced append. The report names the
journal it read, because the default path and the path in service can be
different files (measured in the source comments: 67 entries versus
74,835). Executed, after editing one byte of line 2:

```text
$ skarbiec verify-chain
{
  "broken_at": "2026-08-24T22:34:07Z",
  "digests_checked": 3,
  "digests_verified": 2,
  "entries": 3,
  "faults": [
    {"at": "2026-08-24T22:34:07Z", "fault": "digest", "line": 2, "op": "item-write"}
  ],
  "intact": false,
  "journal": "/tmp/skarbiec-wt-item/demo.audit.jsonl",
  "linkage_checked": 3,
  "linkage_verified": 3
}
```

## Reading the journal

- `audit [--limit N]` — the journal oldest first; `--limit` reads only the
  file's tail (refusal: `--limit must be at least one`).
- `audit-query [--op X] [--consumer C] [--item I] [--since T] [--until T]
  [--limit N]` — filtered; limit 1–10000, default 100 (refusal: `--limit
  must be between one and 10000`). `audit-query --consumer <name>` is a
  consumer's whole trail ([consumer](consumer.md#observing-consumers)).
- `doctor`'s `audit` check runs the same report over the newest 200 digests:
  `3 of 3 entries linked, newest 3 digests intact, in <journal>`.

## Write-once receipts

The WORM receipt store is external: an operator points
`SKARBIEC_WORM_RECEIPT_DIR` and `SKARBIEC_WORM_CHECKPOINT` at a write-once
filesystem or bucket mirror, and `doctor` verifies both paths exist
(`src/runtime/doctor.rs::worm_check`). The three verdicts, executed:

```text
unset          → {"status":"not_configured","detail":"set SKARBIEC_WORM_RECEIPT_DIR and SKARBIEC_WORM_CHECKPOINT to enable write-once receipts"}
both present   → {"status":"pass","detail":"receipts in /tmp/skarbiec-wt-item/receipts"}
set but absent → {"status":"fail","detail":"configured but absent: <dir>, <checkpoint>"}
```

`not_configured` is deliberately not a failure: a fresh install has
configured no receipts, "and reporting that as a failure is how a dashboard
teaches its operator that red means nothing."

## Not to be confused with

- **A credential receipt.** The Weles lifecycle stores its proof-of-rotation
  in the item's `context.receipt`
  ([CLI reference](../CLI.md#receipt-persisted-with-the-revision-it-proves));
  the journal records that the operation happened, the receipt proves what
  it did to the provider.
- **Item history.** Every superseded revision stays inside the item
  ([item](item.md#lifecycle)); the journal is the cross-item, append-only
  timeline. A purge removes history but cannot rewrite the journal
  ([trash and purge](trash-and-purge.md)).
- **The donation inbox or sync log.** Those move ciphertext between vaults;
  the journal is per-vault evidence.
