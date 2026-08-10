# Install and updates

## The release channel

The source may be mirrored publicly at
<https://github.com/wisent-ai/skarbiec>, but the canonical release is built,
stored, signed, promoted, and delivered by Stado. Supported coordinates are
`linux-amd64` and `darwin-arm64`. A version in `Cargo.toml` or a source tag does
not by itself constitute a release; the canonical signed Stado receipt must name
every expected platform artifact.

There is no mutable `latest` binary artifact. A deployment pins an exact
version, platform, Stado archive URI, and SHA-256, while the `candidate` and
`stable` labels only select immutable receipts.

## Install

Resolve the exact version and platform from the canonical Stado release receipt.
The receipt supplies the immutable `release.tar.gz` URI and SHA-256. Stado
verifies the digest, stages the archive under an immutable versioned directory,
and reconciles the selected channel; do not overwrite the running broker in
place.

Contributors may build from source:

```sh
git clone https://github.com/wisent-ai/skarbiec
cd skarbiec
sh scripts/install.sh
```

`scripts/install.sh` builds a release binary, stages it inside the destination
directory, and moves it into place atomically. It then prints the installed
binary's version and provenance. `SKARBIEC_INSTALL_DIR` overrides the default
`$HOME/.local/bin`.

Runtime requirements: `gpg`, `openssl`, and `shasum`. `oathtool` is optional
and needed only for one-time codes.

After installing:

```sh
skarbiec key-doctor
skarbiec recovery-status
```

`key-doctor` distinguishes a healthy binary from missing decryption material and
names the exact private-key files a restore needs.

## Artifact contract

Stado reads `.wisent-release.json` and invokes the checked-in
`scripts/release/quality.sh` and `scripts/release/build.sh` entrypoints on native
builders. Each platform receipt contains the staged binary, runtime launcher,
Apache License, Unicode notice, and trademark policy. The Linux recipe also
stages:

```text
share/skarbiec/browser/skarbiec-autofill.crx
share/skarbiec/browser/skarbiec-autofill.xml
```

The recipe checks the builder architecture, so a mislabeled native artifact is
refused before Stado archives it.

## Managed browser installation and updates

The Linux release recipe publishes a signed Chrome extension and its Omaha
update manifest. Stado materializes the Skarbiec-owned
`browser-extension-key#private_key` grant as the
`SKARBIEC_EXTENSION_PRIVATE_KEY_FILE` path only for that build. The key is never
stored in this repository, its manifest, or a release asset. The pinned key
determines the extension id, so every update remains authorized for the
native-messaging host. Packaging refuses an id that differs from
`deploy/chrome-extension-id`, which the native host embeds.

`deploy/chrome-managed-policy.json` is the Chrome managed-policy payload for
MDM or the fleet configuration system. Its `ExtensionInstallForcelist` entry
installs the signed extension without developer mode, CUA, or per-machine
unpacked-extension steps. Chrome consumes it through normal managed-policy
refresh; this mechanism never closes or restarts the browser. Chrome follows
the stable `skarbiec-autofill.xml` URL and fetches the CRX selected by the
canonical Stado `stable` receipt.

The build derives both embedded-manifest and Omaha versions from
`WISENT_VERSION`; an invalid Chrome version is refused before staging.

After the vault exists, the product activation path runs:

```sh
skarbiec browser-host-install
```

That command mints or rotates only the `read:login-*` browser grant and
atomically writes owner-private Chrome and Firefox native-messaging manifests.
It resolves the installed binary path itself; `--binary <absolute-path>` is for
packagers whose activation process runs a different Skarbiec binary. There are
no browser installation helper scripts and no local CRX artifacts in the
repository.

## Updates

The supervisor owns updates: stop the service, fetch and verify the exact pinned
asset, atomically replace the binary, restart, then run `key-doctor`. Skarbiec
does not swap its own executable while serving a credential request.

Do not discover a version at runtime. Changing the configured tag is the
operator's rollout decision and the rollback coordinate remains explicit.

## Publish

Publishing is source-submit driven. Update the version in `Cargo.toml`,
regenerate `Cargo.lock`, and commit both manifests. Submit that exact immutable
source snapshot to Stado. Stado extracts the version with
`.wisent-release.json`, runs both platform recipes, stores signed receipts, and
promotes those receipts through `candidate` and `stable` without rebuilding.

`released-surface.json` records the command surface recovered from the last
canonical release. Update it only from the published Stado archive, never from
a mutable checkout.

## Versioning

`Cargo.toml` is the source of the package version. Before tagging, the advertised
command surface is compared with `released-surface.json`: removals or changed
contracts require a compatibility-breaking bump; additions require an additive
bump. The workload-proof acquisition cutover removes the bootstrap-bearer
contract, so this release uses the next compatibility boundary rather than a
patch.

The Git tag is the versioned distribution coordinate and the workflow never
moves or reuses it. GitHub administrators can still delete or recreate tags and
releases; protect those permissions separately. The binary reports its source
revision, and no mutable channel pointer participates in binary deployment.

## No credential bootstrapping loop

For a completed release, the release metadata, archives, and checksums are all
readable without authorization. A new machine can therefore install the
credential broker before it possesses any Skarbiec identity. Publication uses
GitHub's ephemeral workflow token, not a credential stored inside the vault
being published.

## Remaining operational step

The workflow and documentation define the public two-platform channel. A release
exists only after the signed version tag is pushed and both matrix jobs upload
their assets. Operators must not point a deployment at the new coordinate until
those public assets and checksums are visible.

