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

# An immutable coordinate that nobody can rebuild identifies bytes, not software.
# A dirty tree is therefore refused outright: the published artifact must resolve
# to a revision that still exists after this shell exits.
if [ -n "$(git status --porcelain)" ]; then
  echo "refusing to publish: the tree has uncommitted changes"
  echo "commit them first, so $VERSION resolves to a revision that can be rebuilt"
  exit
fi
COMMIT="$(git rev-parse HEAD)"

# And a revision only on this laptop is the same fragility under a better name.
if ! git merge-base --is-ancestor HEAD origin/main; then
  echo "refusing to publish: HEAD is not on origin/main"
  echo "push it first, or fetch if this ref is stale"
  exit
fi

echo "version:  $VERSION"
echo "platform: $PLATFORM"
echo "commit:   $COMMIT"
echo "binary:   $BINARY"
echo "manifest: $MANIFEST"

if [ -n "$DRY" ]; then
  echo
  echo "dry run — nothing built, nothing published"
  exit
fi

# Bake both in, so the artifact can name itself and its source afterwards.
SKARBIEC_RELEASE_URI="$BINARY" SKARBIEC_RELEASE_COMMIT="$COMMIT" \
  cargo build --release --quiet

cd target/release
DIGEST_LINE="$(openssl dgst -sha256 -r skarbiec)"
DIGEST="${DIGEST_LINE%% *}"
printf '%s  %s\n' "$DIGEST" skarbiec > SHA256SUMS

# Refuse to publish a binary that cannot report the coordinate and the revision it
# was built from. A failed bake means a released artifact whose provenance stops at
# "some tree on some machine", which is the defect this path exists to remove.
REPORTED_LINE="$(./skarbiec version | awk '/"release"/{print; exit}')"
REPORTED_TAIL="${REPORTED_LINE#*: \"}"
REPORTED="${REPORTED_TAIL%\"*}"
if [ "$REPORTED" != "$BINARY" ]; then
  echo "built binary reports release '$REPORTED', expected '$BINARY'"
  exit
fi
STAMPED_LINE="$(./skarbiec version | awk '/"commit"/{print; exit}')"
STAMPED_TAIL="${STAMPED_LINE#*: \"}"
STAMPED="${STAMPED_TAIL%\"*}"
if [ "$STAMPED" != "$COMMIT" ]; then
  echo "built binary reports commit '$STAMPED', expected '$COMMIT'"
  exit
fi

stado storage put "$BINARY" skarbiec --if-absent
stado storage put "$MANIFEST" SHA256SUMS --if-absent

# Confirm through the channel, not from the fact that the uploads returned. The
# listing is used rather than `stat` on purpose: `stat` skipped the object-path
# mapping until recently and answered "absent" about objects it had just stored,
# so a script that trusted it would report a healthy publish as a failed one.
# Confirmation is a substring test on the listing rather than a regex, because a
# version string contains dots and a regex would accept coordinates that only
# resemble the one just published.
echo
LISTING="$(stado storage objects releases skarbiec/)"
case "$LISTING" in
  *"$VERSION/$PLATFORM/skarbiec"*)
    echo "published $VERSION for $PLATFORM, and the channel lists it" ;;
  *)
    echo "uploads returned but the channel does not list $VERSION/$PLATFORM"
    exit ;;
esac
echo "install with: stado storage get $BINARY <destination>"
