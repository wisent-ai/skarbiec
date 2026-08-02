# Install and updates

## The release channel

The source is public at <https://github.com/wisent-ai/skarbiec>. For every
completed tagged release, GitHub Actions builds on independent Linux and macOS
runners and publishes bearer-free GitHub Release assets. The supported
coordinates are `linux-amd64` and `darwin-arm64`; each archive has a sibling
`.sha256` file. A version in `Cargo.toml`, or a tag without all of those assets,
is not a published release. The publication workflow refuses to replace an
existing asset; changed bytes require a new tag. This does not prevent a GitHub
administrator from deleting or recreating a tag or release, so repository
administration remains a separate trust boundary.

There is no mutable `latest` binary artifact. A deployment pins an exact tag,
platform, archive URL, and checksum. The older Stado object lineage remains
historical; GitHub Releases is the designated durable public distribution
channel.

## Install

From a public tagged release, set the exact version and platform:

```sh
version=vX.Y.Z
platform=darwin-arm64
archive="skarbiec-${version}-${platform}.tar.gz"
origin="https://github.com/wisent-ai/skarbiec/releases/download/${version}"

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$archive" "$origin/$archive"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$archive.sha256" "$origin/$archive.sha256"
openssl dgst -sha256 -r "$archive"
cat "$archive.sha256"
```

The two digest lines must match before extraction. Install into a staging
directory, then rename the binary into `$HOME/.stado/bin`; never overwrite the
running broker in place.

Contributors may build from source:

```sh
git clone https://github.com/wisent-ai/skarbiec
cd skarbiec
sh scripts/install.sh
```

`scripts/install.sh` builds a release binary, stages it inside the destination
directory, and moves it into place atomically. It then prints the installed
binary's version and provenance. `SKARBIEC_INSTALL_DIR` overrides the default
`$HOME/.stado/bin`.

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

Every tag matching `v*` runs the release matrix in
`.github/workflows/ci.yml`. Each runner formats, lints, and builds the exact
source revision before packaging:

```text
skarbiec-<tag>-linux-amd64.tar.gz
skarbiec-<tag>-linux-amd64.tar.gz.sha256
skarbiec-<tag>-darwin-arm64.tar.gz
skarbiec-<tag>-darwin-arm64.tar.gz.sha256
skarbiec-autofill.crx
skarbiec-autofill.crx.sha256
skarbiec-autofill.xml
```

Archives contain the binary, Apache License, Unicode notice, and trademark
policy. The workflow checks the runner architecture, so a mislabeled native
artifact fails instead of being published under the wrong coordinate. GitHub
Release assets are publicly downloadable without a token.

## Managed browser installation and updates

Tagged releases also publish a signed Chrome extension and its Omaha update
manifest. The signing key is supplied only to the release job through the
`SKARBIEC_EXTENSION_PRIVATE_KEY_B64` repository secret; the key is never stored
in this repository or a release asset. The pinned key determines the extension
id, so every update remains authorized for the native-messaging host.
The release job derives the id from the public key and refuses publication if
it differs from `deploy/chrome-extension-id`, which the native host embeds.

`deploy/chrome-managed-policy.json` is the Chrome managed-policy payload for
MDM or the fleet configuration system. Its `ExtensionInstallForcelist` entry
installs the signed extension without developer mode, CUA, or per-machine
unpacked-extension steps. Chrome consumes it through normal managed-policy
refresh; this mechanism never closes or restarts the browser. Chrome follows
the stable `skarbiec-autofill.xml` URL and fetches the CRX published by the
newest signed tag.

The build derives both embedded-manifest and Omaha versions from the release
tag; a tag that is not a valid Chrome version fails before publication.

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

Publishing is tag-driven. First derive the version from the advertised command
surface and commit both package manifests:

```sh
previous="$(jq -r .version released-surface.json)"
STADO_RELEASE_PLATFORM=darwin-arm64 \
  sh scripts/publish.sh --against "$previous" --bump
git add Cargo.toml Cargo.lock
git commit -m 'Prepare Skarbiec release'
git push origin main
```

After the branch CI succeeds, tag that exact pushed commit:

```sh
version="v$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)"
git tag -s "$version" -m "Skarbiec $version"
git push origin "$version"
```

The tag must match the version reported by `Cargo.toml`. GitHub Actions creates
the versioned release and uploads both platform archives plus checksums without
replacement. A tag is never moved or reused; changed bytes require a new version.

The `--bump` invocation uses the historical Stado artifact as its comparison
baseline and exits before upload. A later invocation without `--bump` may mirror
the exact build into Stado object storage, but Stado is no longer the public
distribution channel.

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

