# Contributing to Skarbiec

Skarbiec treats its command surface, vault format, trust boundaries, and release artifacts as product contracts. A change is complete only when code, documentation, and an executable example describe the same behavior.

## Before writing code

Use the route that matches the change:

- **Usage or design question:** start in [GitHub Discussions](https://github.com/wisent-ai/skarbiec/discussions).
- **Bug or feature:** open a [GitHub Issue](https://github.com/wisent-ai/skarbiec/issues) with the observable current and expected behavior.
- **Security vulnerability:** do not open a public issue. Use [GitHub Security Advisories](https://github.com/wisent-ai/skarbiec/security/advisories/new).
- **Small documentation correction:** a focused pull request can start directly.

Discuss the contract first when a proposal changes any of these:

- a public command, flag, JSON field, HTTP route, or MCP tool;
- the vault, audit, acquisition-state, token, or release format;
- recipient, workload-identity, recovery, or authorization behavior;
- supported platforms, runtime dependencies, or release provenance.

## Development setup

Required locally:

- a stable Rust toolchain with `rustfmt` and Clippy;
- `gpg`, `openssl`, and `shasum`;
- `oathtool` only for TOTP behavior.

Build from the repository root:

```sh
cargo build
```

Use a disposable vault and isolated GPG home for manual work. Never point development commands at a production vault, keyring, audit journal, token file, or recovery custodian.

## Make one coherent change

- Fix the source of the behavior; do not add a compatibility alias unless the product contract requires one.
- Keep secret values out of source, shell history, command arguments, fixtures, logs, issue text, and screenshots.
- Preserve the distinction between operator commands, one-use acquisition, and legacy direct grants.
- Update `docs/CLI.md` when a public command or output changes.
- Update `docs/SECURITY.md` when a trust or failure boundary changes.
- Add or update one runnable script under `docs/examples/` for every new user-visible flow.
- Include the real redacted output shape and the failure path. Do not invent successful output.

## Local checks

Run the checks that cover the changed contract. The baseline used by CI is:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Run focused tests for changed behavior and the affected executable example before opening a pull request. A test should defend an observable contract and fail for a plausible regression; do not test source text or incidental implementation details.

## Pull requests

A pull request should contain:

- one problem and one coherent solution;
- the user-visible before and after behavior;
- the exact verification commands and redacted observed results;
- documentation and executable examples changed with the implementation;
- an explicit note for any public contract, migration, recovery, or release impact.

Keep unrelated cleanup out of the change. Reviewers should be able to connect every changed line to the stated outcome.

## Compatibility and versioning

`Cargo.toml` is the package-version source. `released-surface.json` records the command surface of the published predecessor. Do not edit either version manually as part of an ordinary feature pull request.

Maintainers classify the final release surface with `scripts/publish.sh`: additions require an additive bump, while removals or changed command contracts require a compatibility-breaking bump. Tags are signed, never moved or reused, and existing release assets are not replaced by the publication workflow.

## License

By contributing, you agree that your contribution is licensed under the repository's [Apache License, Version 2.0](LICENSE). The software license grants no trademark rights; see [TRADEMARKS.md](TRADEMARKS.md).
