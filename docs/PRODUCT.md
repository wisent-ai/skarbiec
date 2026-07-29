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
