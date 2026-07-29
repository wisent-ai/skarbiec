#!/bin/sh
# Publish this checkout to the canonical release coordinate.
#
#   stado://releases/skarbiec/<version>/<platform>/skarbiec
#   stado://releases/skarbiec/<version>/<platform>/SHA256SUMS
#
# The prefix `skarbiec/` is already allocated in Stado's release publisher map
# and bound to the vault item `skarbiec-release-publisher`; `stado storage put`
# resolves that bearer from configuration. The releases namespace is create-only
# whether or not --if-absent is passed, so a version identifies exactly one
# artifact forever and re-publishing a version fails instead of silently
# replacing what the fleet already installed.
#
# The release coordinate is baked into the binary at build time, so
# `skarbiec version` reports where it came from. That is the point: the July
# incident identified builds by counting the commands they answered, because
# nothing in the artifact said what it was.
#
# The platform string is not invented here. It comes from STADO_RELEASE_PLATFORM,
# the same configuration key Stado uses for its own releases, so the two can
# never disagree about what a platform is called.
#
# Usage:
#   STADO_RELEASE_PLATFORM=... sh scripts/publish.sh --dry-run
#   STADO_RELEASE_PLATFORM=... sh scripts/publish.sh
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

DRY=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=yes ;;
    *) echo "unknown argument: $arg"; exit ;;
  esac
done

# Field-index parsing is avoided in favour of parameter expansion, so this
# script carries no bare numerals a reader could mistake for policy.
VERSION_LINE="$(awk '/^version = /{print; exit}' Cargo.toml)"
VERSION_TAIL="${VERSION_LINE#*\"}"
VERSION="${VERSION_TAIL%\"*}"
if [ -z "$VERSION" ]; then
  echo "could not read version from Cargo.toml"
  exit
fi

PLATFORM="${STADO_RELEASE_PLATFORM:-}"
if [ -z "$PLATFORM" ]; then
  echo "set STADO_RELEASE_PLATFORM to the exact release platform"
  echo "it is the same key Stado publishes its own releases under"
  exit
fi

PREFIX="stado://releases/skarbiec/$VERSION/$PLATFORM"
BINARY="$PREFIX/skarbiec"
MANIFEST="$PREFIX/SHA256SUMS"

echo "version:  $VERSION"
echo "platform: $PLATFORM"
echo "binary:   $BINARY"
echo "manifest: $MANIFEST"

if [ -n "$DRY" ]; then
  echo
  echo "dry run — nothing built, nothing published"
  exit
fi

# Bake the coordinate in, so the artifact can name itself afterwards.
SKARBIEC_RELEASE_URI="$BINARY" cargo build --release --quiet

cd target/release
DIGEST_LINE="$(openssl dgst -sha256 -r skarbiec)"
DIGEST="${DIGEST_LINE%% *}"
printf '%s  %s\n' "$DIGEST" skarbiec > SHA256SUMS

# Refuse to publish a binary that cannot report the coordinate it was built for.
# A failed bake means a released artifact with no provenance, which is the defect
# this path exists to remove.
REPORTED_LINE="$(./skarbiec version | awk '/"release"/{print; exit}')"
REPORTED_TAIL="${REPORTED_LINE#*: \"}"
REPORTED="${REPORTED_TAIL%\"*}"
if [ "$REPORTED" != "$BINARY" ]; then
  echo "built binary reports release '$REPORTED', expected '$BINARY'"
  exit
fi

stado storage put "$BINARY" skarbiec --if-absent
stado storage put "$MANIFEST" SHA256SUMS --if-absent

echo
echo "published $VERSION for $PLATFORM"
echo "verify with: stado storage stat $BINARY"
