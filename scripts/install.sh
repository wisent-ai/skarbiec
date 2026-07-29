#!/bin/sh
# Build Skarbiec from this checkout and install it where the fleet looks for it.
#
# This is the source install. It is the only install that exists today: there is
# no published release channel for Skarbiec yet, so nothing can be fetched and
# checksum-verified the way `stado` itself is. See docs/INSTALL.md for the
# channel this should become and what blocks it.
#
# The replacement is done by rename inside the destination directory, so a
# concurrent process either sees the old binary or the new one and never a
# half-written file. The installed binary is then exercised before the script
# reports success — an install that cannot run is not an install.
set -eu

DEST="${SKARBIEC_INSTALL_DIR:-$HOME/.stado/bin}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

cd "$HERE"
cargo build --release --quiet

mkdir -p "$DEST"
STAGE="$DEST/.skarbiec.incoming"
cp target/release/skarbiec "$STAGE"
chmod +x "$STAGE"
mv "$STAGE" "$DEST/skarbiec"

# Prove the thing runs where it now lives, and make it say what it is, so a stale
# install cannot masquerade as a fresh one. Asking the binary for its identity
# replaces counting the commands it answers, which is how builds were told apart
# during the July incident because nothing in the artifact named itself.
VERSION_LINE="$("$DEST/skarbiec" version | awk '/"version"/{print; exit}')"
VERSION_TAIL="${VERSION_LINE#*: \"}"
PROVENANCE_LINE="$("$DEST/skarbiec" version | awk '/"provenance"/{print; exit}')"
PROVENANCE_TAIL="${PROVENANCE_LINE#*: \"}"
echo "installed: $DEST/skarbiec"
echo "version:   ${VERSION_TAIL%\"*} (${PROVENANCE_TAIL%\"*})"
echo
echo "next: run '$DEST/skarbiec key-doctor' to confirm the vault opens,"
echo "and move the recovery secret off this machine before storing anything real."
