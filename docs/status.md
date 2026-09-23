# Project status and support

What this release is, what it is not, and which boundary answers a question
about it. The [README](../README.md) links here from its status section.

## Project status and support

Skarbiec is an **early public `0.2.x` release**, not a hosted secrets service.
Deploy an exact release tag and checksum; do not infer readiness from
`Cargo.toml` or a mutable `latest` pointer.

| Boundary | Current contract |
| --- | --- |
| Maturity | Early public `0.2.x`. The local broker, acquisition flow, sharing, recovery, audit, sync, MCP boundary, and managed browser extension are shipped; the fleet-level Hosted Hub is planned commercial work and is not part of this repository |
| Latest complete release | [`v0.2.37`](https://github.com/wisent-ai/skarbiec/releases/tag/v0.2.37) |
| Supported release targets | `darwin-arm64` and `linux-amd64` |
| Runtime dependencies | `gpg` and `openssl`; `shasum` only for breach checking. TOTP is computed in process |
| Storage | One local JSON vault; values are per-recipient GPG ciphertext |
| Metadata | Item ids, types, tags, recipients, and revision counts are cleartext |
| Default machine access | Ed25519 workload proof → one short-lived, one-use, field-bound capability |
| Compatibility access | Direct scoped bearers and owner-only emitted env files remain for existing consumers |
| Network | Local CLI, MCP, native messaging, or the HTTP broker; no hosted control plane is required |
| Availability | No cloud fallback by design; if the local broker cannot decrypt, the integration is unavailable |
| Versioning | Additions require an additive bump; removals or changed command contracts require a compatibility-breaking bump |
| Distribution | Canonical Stado releases for both supported platforms, plus the signed `skarbiec-autofill.crx` and its update manifest on the Linux recipe. Contributors can build and install from source with `sh scripts/install.sh`. There is no package-registry distribution |
| License | [Apache License, Version 2.0](LICENSE); copies previously received under MIT remain under that grant. The license grants no trademark rights |

Not supported or promised:

- no published Windows target;
- no protection from a host already compromised while an owner key is
  available;
- no encryption of item names or other vault metadata;
- no automatic cloud fallback, secret replication in plaintext, or mutable
  release channel;
- no claim that legacy direct grants provide the acquisition model's one-use
  identity guarantee.

The local core, acquisition flow, sharing, recovery, audit, sync, MCP boundary,
and managed browser extension exist today. The fleet-level **Hosted Hub**
described in [the product contract](https://skarbiec.wisent.com/docs/product-contract#monetization-assessment)
is planned commercial control-plane work, not a dependency or capability of the
current core.

### Compatibility, releases, and support

`Cargo.toml` is the package-version source. Stado resolves
`.wisent-release.json`, runs the repository-owned quality and build entrypoints,
and stores immutable signed receipts for both supported platforms. The Linux
recipe receives the browser signing key only as the file-backed
`browser-extension-key#private_key` Skarbiec grant; the key is never stored in
source or a release asset. Promotion reconciles the same immutable receipts from
`candidate` to `stable`.

Release `0.2.37` is rollback-compatible with exact release `0.2.36`. This
declaration lets Stado atomically restore `0.2.36` after a `0.2.37` rollout
because both releases use runtime configuration schema 1 and state schema 1;
it is not a compatibility promise for every `0.2.x` release. Retain the exact
`0.2.36` receipt and checksum, and do not select a rollback target that is not
listed in `runtime.rollback_compatible_with`.

- Resolve downloadable assets from the canonical Stado release receipt.
- Commercial or account support is not applicable to the local core; Hosted Hub
  is planned and has no published paid contract.
- Ask design and usage questions in
  [GitHub Discussions](https://github.com/wisent-ai/skarbiec/discussions).
- Report reproducible bugs and request features in
  [GitHub Issues](https://github.com/wisent-ai/skarbiec/issues).
- Join the [Wisent Discord](https://discord.gg/qRjpkthq54) for community chat.
- Report vulnerabilities privately through
  [GitHub Security Advisories](https://github.com/wisent-ai/skarbiec/security/advisories/new).

### Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing a command contract,
vault format, trust boundary, or release surface. It defines the issue and
security-reporting routes, development prerequisites, required documentation
and examples, local checks, pull-request evidence, compatibility classification,
and maintainer-only release process.

### License

Apache License, Version 2.0 — see [LICENSE](LICENSE). Existing copies previously
received under MIT remain under that grant.

The software license grants no trademark rights.
