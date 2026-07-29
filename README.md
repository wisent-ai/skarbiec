# skarbiec

A password manager for the agent era, and the thing that ends `.env`.

One Rust binary, no hosted dependency, no external service. All cryptography is
delegated to vetted local tools (`gpg`, `openssl`, `shasum`, and optional
`oathtool`); none is hand-rolled.

## Why this is not a password manager with an API

The comparison to a consumer manager is exact on primitives — one vault, one
owner, per-recipient sharing, recovery material, an audit trail — and misleading
on clients.

A consumer manager's client is a human at a keyboard who unlocks with a master
secret and then holds the item. Skarbiec's clients are processes:
non-interactive, numerous, short-lived, spawned by schedulers and by other
processes, often on machines nobody is sitting at. There is no human to prompt,
no session to unlock, and **no reason a client should ever hold an item**.

Everything below follows from that.

## The end of `.env`, in three steps

**A file of values.** `.env` is a copy of every secret a process might need,
plaintext, duplicated into every checkout, image and CI runner. It cannot be
rotated, because nobody knows where the copies are.

**A vault with standing grants.** Values live in one place, access is scoped,
every request is recorded. Better — but the consumer still holds a long-lived
bearer, and that bearer is the new `.env`: smaller, still copied, still
effectively unrotatable.

**A capability requested per use.** The consumer holds no secret. It proves what
it *is* — a workload identity, an executable path, a host, a signed attestation —
and receives one field, once, bound to that identity and that field, expiring in
seconds. Rotation works for the first time, because nothing holds a copy to
invalidate.

The pitch, and the bar to clear: *your agents never hold a credential — they
prove who they are and borrow one field for one call, and you can see every
borrow.*

Where the implementation actually stands against that sentence is written down,
not glossed: see [docs/PRODUCT.md](docs/PRODUCT.md).

## Features

- **Encryption at rest.** Every item is armored ciphertext, sealed to the public
  keys of its recipients. The on-disk file is safe at rest; its metadata is not
  secret and is documented as such.
- **Multi-recipient sharing.** Register a user, share an item (re-encrypt to
  include them), revoke (re-encrypt to the remaining recipients).
- **Scoped service-account grants.** Read, write and delete scopes are checked
  independently. Request-only grants issue instead a short-lived, field-bound
  bearer that its first successful read atomically consumes.
- **Real owner rotation.** `rotate-owner` rewraps every current and historical
  ciphertext onto a new owner, drops the previous one per item, and keeps the
  recovery recipient. Nothing is written until all of it succeeds, so a
  half-finished rotation cannot leave the vault readable by neither owner.
- **Recovery and emergency access.** A recovery recipient is on every item;
  time-delayed emergency grants share the vault after an operator-chosen moment.
- **Diagnosis that does not need the patient healthy.** `key-doctor` reports
  which keys can still open the vault and, when none can, the exact
  `private-keys-v1.d/<KEYGRIP>.key` files a restore has to produce. It reads the
  document and the keyring directly, never the API.
- **Honest failure.** `GET /health` opens real key material rather than reporting
  that a process is alive. A read of an item that exists but will not decrypt
  answers `503` with `infra_down`, never a dropped connection. A consumer can
  tell "you are not allowed" from "I am broken".
- **Tamper-evident audit.** Append-only journal, each line carrying the prior
  line's hash; `verify-chain` detects any retroactive edit.
- **Runtime injection.** `resolve` emits an owner-only env file and returns its
  path; `expand` fills reference lines in a template. Values land in files, never
  on stdout.
- **Generator, one-time codes, breach health.** Login strings and passphrases
  from operating-system entropy; a current one-time code from a saved seed; a
  breach check under k-anonymity (only a hash prefix leaves the host).
- **Sync.** Git-backed transfer of the encrypted file across devices — only
  ciphertext crosses the wire.
- **Local HTTP API and MCP server.** A loopback API for GUI and CLI clients, and
  a stdio Model Context Protocol server for agents, sharing one policy and audit
  core.

## Install

```sh
sh scripts/install.sh
```

Builds a release binary and installs it into `$HOME/.stado/bin` — the prefix the
fleet's launchers look in — by rename, so a concurrent process never sees a
half-written file. Override the destination with `SKARBIEC_INSTALL_DIR`. The
script runs the installed binary afterwards and prints what it reports for
`skarbiec version`, so a stale install does not look exactly like a fresh one.

Runtime dependencies are invoked as subprocesses and must be on `PATH`: `gpg`,
`openssl`, `shasum` (`oathtool` is optional, for one-time codes).

Releases are published to the channel, immutable and retrievable without
credentials. There is deliberately no `latest` pointer — an install that discovers
its own version cannot be reproduced — so ask the channel which versions exist and
name the one you want:

```sh
stado storage objects releases skarbiec/
stado storage get stado://releases/skarbiec/<version>/darwin-arm64/skarbiec ./skarbiec
```

`skarbiec version` then reports the coordinate and the source commit that copy was
built from, so a build is never identified by guesswork.

Publishing is `sh scripts/publish.sh`, and a dry run prints the plan without
touching the channel. The script keeps the guards this product needs: a refused
dirty tree, a refused `HEAD` that is not an ancestor of `origin/main`, the release
coordinate and the source commit baked into the binary, a `SHA256SUMS` manifest, a
create-only upload, and confirmation read back from the channel listing.

The version number is not chosen by hand, and the rule that decides it is not
copied into this repository. It lives once for the whole fleet, in
[AutoVersion](https://github.com/lbartoszcze/AutoVersion), and is called as
`autoversion decide` on two command surfaces: the one the published build
advertises and the one this checkout advertises. Anything removed is `breaking`,
anything added is `additive`, an identical surface is `internal`. `--bump` writes
the derived number into `Cargo.toml`. `released-surface.json` records the surface
of the version currently on the channel, recovered by downloading that artifact
and asking it for its own command list. That rule, the channel, and what
durability it still lacks are in [docs/INSTALL.md](docs/INSTALL.md).

## Quickstart

```sh
# Create the vault, sealed to a fresh gpg owner key (plus a recovery key)
skarbiec init alice

# Add a login item; fields are free-form key=value pairs
skarbiec set github --type login --field login_email=alice@example.com

# Inspect — metadata only, never values
skarbiec list

# Read one item back
skarbiec get github

# Prove the vault can still be opened, and by which key
skarbiec key-doctor
```

The vault lives at `SKARBIEC_VAULT_FILE` (default
`~/.stado/skarbiec.vault.json`): armored ciphertext, safe at rest.

**Move the recovery material off this machine before you store anything real.**
`init` generates the owner and recovery keys into the same local keyring, so
until you export the recovery secret and remove it from that keyring, one
directory holds both halves of the failure domain. `recovery-status` tells you
whether that is still the case, and treats a local recovery secret as a fault.
This is not a hypothetical: it is the failure that produced
[docs/ARCHITECTURE-REVIEW.md](docs/ARCHITECTURE-REVIEW.md).

## Documentation

- [docs/PRODUCT.md](docs/PRODUCT.md) — what this is for, the three generations of
  secret handling, and where the implementation honestly stands.
- [docs/CLI.md](docs/CLI.md) — every command, grouped, with examples.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design, client boundary, HTTP and
  MCP surface, and the cryptographic model.
- [docs/SECURITY.md](docs/SECURITY.md) — trust boundaries, threat model, and the
  invariants the vault upholds.
- [docs/ARCHITECTURE-REVIEW.md](docs/ARCHITECTURE-REVIEW.md) — defects ranked by
  what can destroy or leak the vault, written from the shipped source.
- [docs/LINEAGE.md](docs/LINEAGE.md) — the two code bases this once had, and why
  there is now one.

## License

MIT — see [LICENSE](LICENSE).
