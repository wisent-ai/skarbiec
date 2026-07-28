# Lineage

Skarbiec existed as two diverged code bases. This document records what they
were and what this branch is for, so the next person does not repeat the
mistake of fixing one copy and shipping the other.

## The two lineages

**`main` — the deployed lineage.** The binary that serves the fleet on
loopback is built from this tree. It carries the `/v1/items/*` HTTP surface,
the one-time field acquisition flow (`acquisition-request`,
`acquisition-read`), and the honest failure reporting added after the July
credential outage.

**`vendored-superset` — this branch.** Skarbiec was also vendored inside
`lbartoszcze/entitlements-rotator` under `src/skarbiec/`, built there as a
second binary named `skarbiec-entitlements-router`, and published from that
repository as its own rolling release. That copy was never a mirror: it grew
sixteen commands the deployed lineage does not have, seven modules
(`access/capability.rs`, `access/reauth.rs`, `core/chrome_cards.rs`,
`credential.rs`, `release.rs`, `runtime/mailbox.rs`, `secure_input.rs`), and a
much wider dependency set — SQLite, AES-CBC, ed25519, PBKDF2 and an HTTP
client. Of the files present in both, most differed.

Its extra surface: Apple challenge and credential storage
(`apple-challenge-put`, `apple-credential-put`, `credential-put`), delegated
capabilities (`capability-serve`, `capability-issue`, `capability-status`,
`capability-cancel`, `capability-delegate`), Chrome card import (`card-set`,
`card-import-chrome`), mailbox brokering (`mailbox-broker`, `mailbox-probe`,
`seed-resend`), credential request/return, and release publishing.

## Why this branch exists

Both lineages now live in this one repository. Nothing about the vendored copy
is lost, and no second repository builds or publishes a credential broker any
more. This branch is the working-tree state of that copy at the moment of
consolidation, including work that had never been committed anywhere.

It compiles standalone. It is **not** deployed, and it is not merged: merging
it means deciding, feature by feature, what belongs in a broker the whole
fleet depends on. The dependency surface is the reason to be deliberate —
`main` states "no hosted dependency" and delegates cryptography to `gpg`,
`openssl` and `shasum`, while this branch links a database engine, a block
cipher and a network client into the process that holds every secret.

## What must not happen again

A credential broker with two sources and two publish paths cannot be reasoned
about. One of them was reached by production; the other accumulated features
and a release nobody consumed. During the outage that followed, the wrong copy
was read as the source of truth for hours, and a command found only in the
unreachable copy was cited as the recovery procedure.

One repository. One publish path. If a feature is worth having, it lands on
`main`.
