# skarbiec

Self-contained vault for sensitive values — a single Rust binary, with no
dependency on any hosted manager or external service. All cryptography is
delegated to vetted local tools (`gpg`, `openssl`, `shasum`, and optional
`oathtool`); none is hand-rolled.

## Features

- **Encryption at rest.** Every item is armored ciphertext, sealed to the public
  keys of its recipients. The on-disk file is safe at rest.
- **Multi-recipient sharing.** Register a user, share an item (re-encrypt to
  include them), revoke (re-encrypt to the remaining recipients).
- **Scoped service-account grants.** Existing read, write, and delete scopes are
  checked independently. Request-only grants can instead issue a short-lived,
  field-bound bearer that is atomically consumed by its first successful read.
- **Recovery and emergency access.** A recovery recipient is on every item, so
  losing the daily identity never loses data; time-delayed emergency grants share
  the vault after an operator-chosen moment.
- **Tamper-evident audit.** An append-only journal where each line carries the
  prior line's hash; `verify-chain` detects any retroactive edit.
- **Runtime injection.** `resolve` emits an owner-only env file and returns its
  path; `expand` fills reference lines in a template. Values land in files, never
  on stdout.
- **Generator, one-time codes, breach health.** Login strings and passphrases
  from operating-system entropy; a current one-time code from a saved seed; a
  breach check under k-anonymity (only a hash prefix leaves the host).
- **Sync.** Git-backed transfer of the encrypted file across many devices — only
  ciphertext crosses the wire.
- **Local HTTP API and MCP server.** A loopback API for GUI/CLI clients and a
  stdio Model Context Protocol server for agents, sharing one policy and audit
  core.

## Install

```sh
cargo build --release
```

The binary is `target/release/skarbiec`. It shells out to `gpg`, `openssl`, and
`shasum` at runtime, so those must be on `PATH` (`oathtool` is optional, for
one-time codes).

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
```

The vault lives at `SKARBIEC_VAULT_FILE` (default
`~/.stado/skarbiec.vault.json`): armored ciphertext, safe at rest.

## Documentation

- [docs/CLI.md](docs/CLI.md) — every command, grouped, with examples.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design, client boundary, HTTP and
  MCP surface, and the cryptographic model.
- [docs/SECURITY.md](docs/SECURITY.md) — trust boundaries, threat model, and the
  invariants the vault upholds.

## License

MIT — see [LICENSE](LICENSE).
