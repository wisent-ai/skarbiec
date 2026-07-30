# What Skarbiec is for

A password manager for the agent era, and the thing that ends `.env`.

The comparison to a consumer password manager is exact in one way and misleading
in another, and the difference is the whole product.

**Exact:** one vault, one owner, per-recipient sharing, recovery material, an
audit trail. The primitives match.

**Misleading:** a consumer manager's client is a human at a keyboard who unlocks
with a master secret and then holds the item. Skarbiec's clients are processes —
non-interactive, numerous, short-lived, spawned by schedulers and by other
processes, sometimes on machines nobody is sitting at. There is no human to
prompt, no session to unlock, and no reason a client should ever hold an item.

Everything worth building follows from that.

## Three generations, and where we actually are

**A file of values.** `.env` is a copy of every secret a process might need,
sitting in plaintext, duplicated into every checkout, every container image and
every CI runner. It cannot be rotated, because nobody knows where the copies
are. This is what we are replacing.

**A vault with standing grants.** A consumer holds a long-lived bearer with
scopes and asks for items. Better: the values live in one place, access is
scoped, and every request is recorded. But the consumer still holds a standing
secret, and that secret is the new `.env` — smaller, still copied, still
long-lived, still unrotatable in practice. **This is where we are.** Dozens of
`~/.stado/<consumer>-skarbiec-token` files exist right now, plaintext,
permanent, one per consumer.

**A capability requested per use.** The consumer holds no secret at all. It
proves what it *is* — a workload identity, an executable path, a host, a signed
attestation — and receives one field, once, bound to that identity and that
field, expiring in seconds. Rotation becomes possible for the first time,
because nothing anywhere holds a copy to invalidate.

The third generation is not aspirational: two of its pieces are already written.
The acquisition flow in `access/acquisition` issues exactly that kind of bearer —
request-only bootstrap grants that cannot read an item, exchanged for a
single-use bearer bound to one consumer, item and field, dying on replay, expiry
or any binding mismatch. And `access/capability` on the `vendored-superset`
branch carries the identity half: a workload registry keyed by executable path,
a trust root, delegation with a depth bound, leases, rate policy and checkpoint
records.

They have never been joined, and neither is the default path. The default is
still a standing grant against `/v1/items/read`.

## What this means for priorities

An earlier review in this repository ranked the `vendored-superset` features
last, on the grounds that each should argue for itself against the crate's
dependency posture. That ranking was made without reading `access/capability`,
and it is wrong about that file. Capability brokering is not a feature; it is
the thesis. It belongs on the main line, and the dependency argument applies to
the card, mailbox and Apple-challenge verbs beside it — not to it.

Revised order, superseding the feature-parity note in the architecture review:

1. **Durable, atomic, locked writes.** Unchanged and still first. A product whose
   claim is "the only copy lives here" cannot have a write path that truncates
   the only copy.
2. **Acquisition becomes the default.** Standing direct scopes become the legacy
   compatibility path, documented as such. Every new consumer gets a
   request-only bootstrap grant.
3. **Join capability to acquisition.** Replace the bootstrap token file with a
   workload identity, so the edge holds an identity instead of a secret. This is
   the step that actually retires `.env`, because the bootstrap token is the last
   `.env`.
4. **Recovery fit for a fleet.** One offline key that a single agent can delete
   is a consumer-manager answer to a fleet-shaped problem, and it is what broke
   in July. Threshold recovery, or custody split across machines, with a
   recorded drill.
5. **Audit as a product surface.** One field per request, per identity, hash
   chained, is provenance a consumer manager structurally cannot offer, because
   it hands over whole items and never learns which field was used. Make it
   queryable: what did this agent take, when, under which grant.

## Non-negotiables that the outage established

**Failure must be distinguishable.** A consumer has to tell "you are not
allowed" from "I am broken", or every outage looks like an authorization bug in
someone else's code. Reads that cannot decrypt answer with a status and an
`infra_down` code, never a dropped connection. The health probe opens real key
material rather than reporting that a process is alive. Both were added after the
July incident and both are product requirements, not niceties.

**Availability is the fleet's availability.** There is no fallback by design —
the cross-cloud fallback was deliberately removed after an earlier outage — so
the broker not answering is the fleet not booting. That is an acceptable trade
only while the broker is boring, durable and diagnosable.

**Metadata is the map.** Names of every secret, consumer and scope are
cleartext. For a product whose pitch is "we hold what nobody else should", the
confidentiality requirement on the document is much higher than "the values are
encrypted" suggests.

## The one-line pitch, and what has to be true for it

*Your agents never hold a credential. They prove who they are and borrow one
field for one call, and you can see every borrow.*

For that sentence to be honest: no standing secret at the edge, a write path
that cannot lose the vault, recovery that survives one machine, and failures a
caller can read. Three of the four are not true yet.

## Examples are a product requirement

Every shipped feature, command and integration carries examples of real use.
A user who reads only the examples must be able to perform the task. No
feature is "done" without them.

What every example set contains:

- **A practical task**, not a flag demo: "publish a release", "let the
  pipeline read one field", "recover after a lost laptop" — never
  "run `set` with these flags".
- **The full arc in order**: preconditions (env vars, keyring state, vault
  path), the commands, and the verification step that proves it worked —
  with the expected output shape, not just "it should succeed".
- **Copy-paste runnable commands**: exact paths as deployed today, no
  ellipses in command position, no invented URLs.
- **The secret-safe pattern demonstrated, never violated**: values enter via
  `skarbiec://` refs, stdin, files or env vars — never inline, and never a
  fake-but-realistic token (those get pasted into real vaults).
- **The failure case**: what the user actually sees when it breaks and the
  next diagnostic step. An example without the failure path teaches half
  the task.

How to write a good example:

1. Start from the user's goal in one sentence; everything after it must
   serve that sentence.
2. One example, one outcome. Two outcomes = two examples.
3. Run it yourself before committing. An untested example is a bug report
   waiting to be filed; paste the real observed output (redacted, never a
   secret) not the imagined one.
4. Keep the reader's machine in view: state which host, which vault file,
   which key must exist first.
5. End with where to go next: the exact command or doc for the adjacent
   task.

Style — examples are plain command sequences:

- The example IS the commands a user would type, in order, nothing else.
  No helper functions, no jq/awk plumbing, no loops, no traps.
- Shell is for framing only: `set -eu`, a usage comment, env exports,
  `${SKARBIEC_BIN:-skarbiec}` for the binary. If a line is not a command
  the user could run verbatim, it does not belong.
- Verification is a command too (`get`, `status`, `health`), printed,
  not asserted in shell logic.
- A reader must be able to copy any line into their terminal and get the
  same result.

Template:

    ## <Task name, as the user phrases it>
    Goal: <one sentence>. Requires: <env/host/key preconditions>.
    1. <command>            # what this does
    2. <command>            # what this does
    Verify: <command whose output proves success> → <expected output>
    If it fails: <the error you will actually see> → <diagnostic step>

Examples live next to their feature: per command in `CLI.md`, per flow in
the feature's own doc. This section applies to every Wisent vault consumer
(Brama, game_asset_creator, Weles, jeden releases).

## Simple status commands are a product requirement

Every Wisent product exposes a small, stable set of simple commands for
the questions an operator asks daily. Nobody composes raw API calls, env
var juggling or multi-step pipelines to answer them. The bar: one command,
one JSON answer, no prerequisites beyond the product's own config.

Required surface per product:

- **`<product> status`** — the whole operator picture in one shot: what
  runs, where the data lives, how much of it, is recovery possible.
  (`skarbiec status` answers: vault path, item/recipient/token/bond
  counts, recovery fingerprint and whether its secret half is present.)
- **`<product> health`** — a liveness probe safe for load balancers and
  launchd (`/health` on serves; exit code carries the verdict).
- **`<product> doctor`** — diagnosis that works when the product is
  broken: reads state directly, never through the API it is diagnosing
  (pattern: `key-doctor`, `stado secrets doctor`).

Rules:

- Status output is JSON by default, stable field names, never a secret
  value (counts, fingerprints, booleans — no material).
- Composite status commands compose the reads of the granular ones
  (`status` = what `recovery-status` + `list` + `tokens` + `bonds` would
  say), so the answer can never drift between surfaces.
- If answering requires a flag, the command is wrong: defaults must be
  the deployed paths.

## CLI design contract

How commands in this repo are shaped. Applies to every Wisent CLI; the
reference implementation is `skarbiec`.

### Command shape

- **Core actions are single verbs**: `init`, `set`, `get`, `list`,
  `delete`, `restore`, `status`. Short, memorizable, no hierarchy for
  the things used daily.
- **Families use `<noun>-<verb>`**: `token-mint`, `sync-status`,
  `donation-accept`, `bond-add`. The noun is the object family, the verb
  is the action on it. Never deeper than two words.
- **The family noun alone is the read path**: `donations` lists pending,
  `tokens` lists grants, `bonds` lists bonds. A plural noun is always
  safe to run and always read-only.
- **`help` lists every command** as machine-readable JSON. If a command
  is not in `help`, it does not exist.

### Arguments

- **The object acted upon is positional, first**: `skarbiec get <id>`,
  `skarbiec delete <id>`, `skarbiec share <id> <uid>`. At most two
  positionals; a third means the flags are wrong.
- **Modifiers are flags**: `--key value` pairs or bare `--flag`
  (`--field value`, `--type login`, `--force`, `--dry-run`). No
  single-letter flags, no `--key=value` requirement (both accepted,
  space preferred in docs).
- **Secrets never go positional**: values arrive via stdin, env vars, or
  files — never as `argv` (argv leaks into ps, history and transcripts).
- **Every command documents itself**: wrong usage prints `usage: ...`
  and exits non-zero. No interactive prompts; non-interactive by
  default.

### Output and errors

- **One JSON object to stdout, always.** No tables, no prose on the
  success path. Lists are JSON arrays; absence is `[]` or `{}`, never
  silence.
- **Errors are JSON on stderr with a non-zero exit**: `1` for
  operational failure, `2` for usage error. The error object names the
  failure point (`{"error": "...", "retryable": false}` style), never a
  bare panic.
- **Soft by default**: `delete` soft-deletes (recoverable via
  `restore`); destruction has a distinct name (`purge`). Refusal beats
  pretending everywhere (missing item → error, not empty).

### Navigation for an operator

Daily loop needs four commands, no more: `status`, `list`, `get`,
`set`. Everything beyond that is administration: recipients (`users`,
`add-user`, `share`, `revoke`, `rotate-owner`), access (`token-*`,
acquisition), sync (`pull`, `sync-*`, `bond-*`, `donate`), serving
(`serve`, `mcp`). Docs and examples must keep that split visible.
