# Quick start

How do you go from nothing to one field, borrowed once, with the replay
refused? This page is the one happy path: install, create a vault, store an
item, and run the product's defining acquisition flow. Everything here runs
locally — no account, no network licence check.

## Install

Use an exact, checksum-verified tagged archive for deployment; the release
procedure is in [INSTALL.md](INSTALL.md). Contributors build and atomically
install from source:

```sh
git clone https://github.com/wisent-ai/skarbiec
cd skarbiec
sh scripts/install.sh
```

`SKARBIEC_INSTALL_DIR` overrides the default `$HOME/.stado/bin`. Skarbiec
delegates cryptography to local tools, so `gpg`, `openssl`, and `shasum` must
be on the PATH (`oathtool` only for `totp`).

## Create a vault

```sh
skarbiec init 'Your Name <you@example.com>'
```

`init` creates the vault at `SKARBIEC_VAULT_FILE` (default
`~/.local/share/skarbiec/skarbiec.vault.json`), sealed to a fresh `gpg` owner
key and a `skarbiec-recovery` key. Every command prints one JSON value to
stdout.

## Store and inspect an item

```sh
skarbiec set github --type login \
  username=alice@example.com password=correct-horse-battery-staple \
  --tags dev,ci
skarbiec list
skarbiec status
```

`set` writes a schema-validated typed item; fields are positional
`name=value` arguments. `list` returns metadata only — id, type, revision
count, recipients, tags — never a value. For real values, prefer `set-json`,
which reads the payload from stdin so the secret never reaches argv or shell
history:

```sh
printf '%s\n' '{"kind":"token","token":"value-from-stdin"}' |
  skarbiec set-json deployment-token
```

## Borrow one field once

The canonical acquisition quick start is executable rather than a transcript
that can drift. From a source checkout with `skarbiec` installed, it creates
a disposable vault, an isolated GPG keyring, and an Ed25519 workload
identity, and stores only the literal non-secret value `not-a-secret`:

```sh
SKARBIEC_EXAMPLE_DIR="${TMPDIR:-/tmp}/skarbiec-acquisition-quickstart" \
  sh docs/examples/acquire-one-field.sh
```

The script performs the product's defining path:

1. create a vault and item;
2. register `demo-workload` for exactly `demo-note#value`, with no standing
   bearer;
3. sign a timestamped, nonced acquisition request with the workload key;
4. consume the issued capability once;
5. retry the same capability and receive `unauthorized`;
6. print the matching `acquisition-issued` and `acquisition-consumed` audit
   records.

The script refuses to overwrite an existing demo directory; remove the
isolated state with `rm -rf` when finished.

## Verify the record

```sh
skarbiec audit --limit 10
skarbiec verify-chain
```

`audit` prints the append-only journal; `verify-chain` recomputes the hash
chain and names the journal it read.

## Before a real vault

Move the recovery key's private half off this machine and prove it works —
an untested recovery key is a hypothesis:

```sh
skarbiec recovery-status
skarbiec recovery-drill recovery
```

That is the whole path. The mental model is
[what-is-skarbiec](what-is-skarbiec.md); the full command surface is
[the CLI reference](CLI.md); machine access is
[grants and consumers](grants-and-consumers.md); the loopback broker is
[the HTTP API](http-api.md).
