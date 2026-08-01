# skarbiec

[![CI](https://github.com/wisent-ai/skarbiec/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/wisent-ai/skarbiec/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wisent-ai/skarbiec?display_name=tag&sort=semver)](https://github.com/wisent-ai/skarbiec/releases)
[![Downloads](https://img.shields.io/github/downloads/wisent-ai/skarbiec/total)](https://github.com/wisent-ai/skarbiec/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Community](https://img.shields.io/badge/community-GitHub%20Discussions-8250df.svg)](https://github.com/wisent-ai/skarbiec/discussions)

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

The Release and Downloads badges above report GitHub's public state, not merely
the version written in `Cargo.toml`. A version is published only when its signed
tag and release assets are visible without authorization. Each published version
has immutable, bearer-free assets for `linux-amd64` and `darwin-arm64`, with a
sibling SHA-256 file. There is deliberately no mutable `latest` binary:
deployments pin an exact tag, platform, archive URL, and digest. See [the install
and release contract](docs/INSTALL.md) for the download and atomic rollout
procedure.

`skarbiec version` reports the immutable GitHub asset URL and source commit baked
into a tagged binary. A source build reports that it is a source build instead of
claiming a published coordinate.

Publishing is tag-driven. The version is not chosen by hand, and the rule that
decides it is not copied into this repository. It lives once for the whole fleet
in [AutoVersion](https://github.com/lbartoszcze/AutoVersion), and compares two
advertised command surfaces: the published predecessor and this checkout.
Anything removed is `breaking`, anything added is `additive`, and an identical
surface is `internal`. `scripts/publish.sh --against <version> --bump` writes the
derived version into both Cargo manifests and stops before upload; after that
commit passes branch CI, its signed tag drives the public release matrix.

`released-surface.json` records the predecessor recovered from the historical
Stado artifact. Stado may receive an exact mirror, but GitHub Releases is the
designated durable public distribution channel.

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

## Support and community

- Ask usage and design questions in [GitHub Discussions](https://github.com/wisent-ai/skarbiec/discussions).
- Report reproducible bugs and request features in [GitHub Issues](https://github.com/wisent-ai/skarbiec/issues).
- Report a vulnerability privately through [GitHub Security Advisories](https://github.com/wisent-ai/skarbiec/security/advisories/new). Do not put credentials, vault material, or exploit details in a public issue.

## License

Apache License, Version Two — see [LICENSE](LICENSE). Existing copies previously received under MIT remain under that grant.

The software licence grants no trademark rights. See [TRADEMARKS.md](TRADEMARKS.md).
