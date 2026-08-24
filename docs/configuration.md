# Configuration

Skarbiec has no configuration file of its own. Everything is an environment
variable read by the process that needs it, plus a handful of owner-only
state files that default to paths derived from the vault. Every variable
below is read in `src/`; defaults are stated where the code has one.

## Vault and state

| Variable | Meaning |
| --- | --- |
| `SKARBIEC_VAULT_FILE` | Path of the encrypted vault. Default `~/.local/share/skarbiec/skarbiec.vault.json`. An operator-route request may override it per request through its body's `vault` member. |
| `SKARBIEC_AUDIT_FILE` | Path of the append-only, hash-chained audit journal. Default `~/.local/state/skarbiec/audit.jsonl`. `verify-chain` always names the journal it read, because the default and an override are different files. |
| `SKARBIEC_ACQUISITION_FILE` | Owner-only acquisition state file (issued bearer hashes, bindings, expiry). Default `<vault>.acquisitions.json` beside the vault. |
| `SKARBIEC_CAPABILITY_FILE` | Capability broker state file. Default `<vault>.capabilities.json` beside the vault. |
| `SKARBIEC_CAPABILITY_ROUTES_FILE` | The capability routes table. Default `capability-routes.json` beside the capability state file; `routes help` prints the path that resolves. |
| `SKARBIEC_SYNC_DIR` | Git synchronization working directory. Default `~/.skarbiec-sync`. |

## Unlocking a protected key

| Variable | Meaning |
| --- | --- |
| `SKARBIEC_UNLOCK` | Unlock phrase for a passphrase-protected recipient key, for a single invocation. Handed to `gpg` over stdin, never argv. |
| `SKARBIEC_UNLOCK_FILE` | Owner-only file holding the phrase, for a persistent service. With neither source, an unprotected key decrypts normally and a protected key fails closed without an interactive prompt. |

## Acquisition

| Variable | Meaning |
| --- | --- |
| `SKARBIEC_ACQUISITION_TTL_SECONDS` | One-time bearer TTL, an integer from 1 through 300. Default 30. The TTL is not secret. |

## MCP server

`skarbiec mcp` keeps `skarbiec_resolve` disabled until all three are set in
the server's own environment — never as tool arguments, so no bearer lands
in a transcript, log, or child argv
([SECURITY.md](SECURITY.md#the-mcp-boundary-is-tighter-than-the-cli)):

| Variable | Meaning |
| --- | --- |
| `SKARBIEC_MCP_CONSUMER` | Consumer identity to gate by. |
| `SKARBIEC_MCP_TOKEN` / `SKARBIEC_MCP_TOKEN_FILE` | The consumer's scoped grant, inline or from a file. |
| `SKARBIEC_MCP_OUT_DIR` | Required absolute directory for emitted mode-0600 env files; a relative path is refused. |

## Browser native host

| Variable | Meaning |
| --- | --- |
| `SKARBIEC_URL` | Loopback API base the native host calls. Default `http://127.0.0.1:8787`. |
| `SKARBIEC_BROWSER_TOKEN_FILE` | Owner-private token file of the browser consumer. Default `~/.local/state/skarbiec/browser-host-token`. |
| `SKARBIEC_BROWSER_CONSUMER` | Consumer name the host presents. Default `skarbiec-browser-host`. |

## Credential lifecycle

| Variable | Meaning |
| --- | --- |
| `STADO_FORWARDS_DIR` | Directory of forward files. Remote `credential` calls resolve their endpoint from `<dir>/skarbiec.local`; the bridge resolves Weles admission from `<dir>/weles-admission.local`. Default `~/.stado/forwards`. |
| `SKARBIEC_CREDENTIAL_TOKEN_FILE` | Owner-only file holding the bearer for remote `credential` calls, the alternative to `--token-file`. |
| `SKARBIEC_WELES_CREDENTIAL_COMMAND` | Absolute, owner-controlled, non-symlink executable implementing the `skarbiec.credential-operation.v3` bridge to Weles. |

## Diagnostics and receipts

| Variable | Meaning |
| --- | --- |
| `SKARBIEC_WORM_RECEIPT_DIR`, `SKARBIEC_WORM_CHECKPOINT` | Enable write-once receipt checking in `doctor`; with either unset, `doctor` reports `not_configured`, which is deliberately not a failure. |
| `SKARBIEC_OPENSSL` | Path of the `openssl` binary when the preferred OpenSSL 3 build lives somewhere unusual. |

## Install and build stamps

| Variable | Meaning |
| --- | --- |
| `SKARBIEC_INSTALL_DIR` | Where `scripts/install.sh` places the binary. Default `$HOME/.stado/bin`. |
| `SKARBIEC_RELEASE_URI`, `SKARBIEC_RELEASE_COMMIT` | Build-time stamps reported by `skarbiec version`; a source build reports them as null instead of guessing. |

## External tools

Skarbiec performs no cryptography of its own. It requires `gpg`, `openssl`,
and `shasum` on the PATH, and `oathtool` only for `totp`
([SECURITY.md](SECURITY.md#cryptography-is-delegated)).
