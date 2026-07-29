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
# THE VERSION RULE LIVES ELSEWHERE AND IS CALLED, NOT COPIED.
#
# One rule decides versions for every product on this channel, and it is a
# separate package on purpose — a second copy is a second policy:
#
#   pip install "git+https://github.com/lbartoszcze/AutoVersion@v0.1.0"
#
# This script supplies only the two things this repository alone knows: the
# surface of the build already on the channel, and the surface of the candidate.
# `autoversion decide` classifies the difference and names the only version this
# release may carry.
#
# A surface is the command list the binary ADVERTISES — exactly what `help`
# prints, reshaped from {"commands": [...]} into {"surface": [...]}. A command
# that dispatches but is unlisted is private, and nothing may be told to depend
# on it: `version` shipped dispatchable but unadvertised, the docs pointed at it
# anyway, and this comparison is what noticed.
#
# Usage:
#   STADO_RELEASE_PLATFORM=... sh scripts/publish.sh --dry-run
#   STADO_RELEASE_PLATFORM=... sh scripts/publish.sh --against <version> --bump
#   STADO_RELEASE_PLATFORM=... sh scripts/publish.sh --against <version>
#
# --against names the version already on the channel; released-surface.json
# records which one that is. Given it, the predecessor is fetched off the channel
# and asked for its own command list, so the baseline is what was really shipped
# rather than what anyone remembers shipping. Without --against the
# classification is skipped and says so out loud, because a check that quietly
# does not run is worse than one that is absent.
#
# --bump writes the derived number into Cargo.toml and stops, so nobody has to
# type a version or remember which slot moves. The commit is left to the operator
# on purpose: a published coordinate must resolve to a revision that is pushed.
#
# --dry-run publishes nothing. It prints the plan and reports every guard that
# would refuse a real run, rather than stopping at the first one — the point of a
# dry run is to learn what blocks the publish, not to discover the blockers one
# invocation at a time.
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

DRY=""
BUMP=""
AGAINST=""
while [ -n "${1:-}" ]; do
  case "$1" in
    --dry-run) DRY=yes ;;
    --bump) BUMP=yes ;;
    --against)
      shift
      if [ -z "${1:-}" ]; then
        echo "--against needs the version already published"
        false
      fi
      AGAINST="$1"
      ;;
    *) echo "unknown argument: $1"; false ;;
  esac
  shift
done

if [ -n "$BUMP" ] && [ -z "$AGAINST" ]; then
  echo "--bump needs --against <published-version>: the number is derived from a"
  echo "comparison, so there is nothing to derive it from without a predecessor"
  false
fi

# Reshape the binary's advertised command list into a surface document the shared
# rule accepts. `unique` sorts and de-duplicates, which is the document's whole
# contract. An empty surface is refused rather than written: a binary that
# advertises nothing has an unknown surface, not an empty one, and the rule would
# read the difference as every command having been removed.
surface_of() {
  "$1" help | jq '{surface: (.commands // [] | unique)}' > "$2"
  if ! jq -e '.surface | any' "$2" > /dev/null; then
    echo "$1 advertised no commands; its surface is unknown, not empty"
    false
  fi
}

# Field-index parsing is avoided in favour of parameter expansion, so this
# script carries no bare numerals a reader could mistake for policy.
VERSION_LINE="$(awk '/^version = /{print; exit}' Cargo.toml)"
VERSION_TAIL="${VERSION_LINE#*\"}"
VERSION="${VERSION_TAIL%\"*}"
if [ -z "$VERSION" ]; then
  echo "could not read version from Cargo.toml"
  false
fi

# A dry run reports a missing platform instead of stopping on it, so the plan is
# still printed; a real publish refuses, because a coordinate needs an exact
# platform and guessing one is how two names for the same platform get published.
PLATFORM="${STADO_RELEASE_PLATFORM:-}"
BLOCKED=""
if [ -z "$PLATFORM" ]; then
  if [ -z "$DRY" ]; then
    echo "set STADO_RELEASE_PLATFORM to the exact release platform"
    echo "it is the same key Stado publishes its own releases under"
    false
  fi
  BLOCKED=yes
  PLATFORM="<platform>"
fi

PREFIX="stado://releases/skarbiec/$VERSION/$PLATFORM"
BINARY="$PREFIX/skarbiec"
MANIFEST="$PREFIX/SHA256SUMS"
COMMIT="$(git rev-parse HEAD)"

echo "version:  $VERSION"
echo "platform: $PLATFORM"
echo "commit:   $COMMIT"
echo "binary:   $BINARY"
echo "manifest: $MANIFEST"

# An immutable coordinate that nobody can rebuild identifies bytes, not software.
# A dirty tree is therefore refused outright: the published artifact must resolve
# to a revision that still exists after this shell exits. And a revision only on
# this laptop is the same fragility under a better name, so HEAD must already be
# an ancestor of origin/main.
DIRTY="$(git status --porcelain)"
if [ -n "$DIRTY" ] && [ -z "$DRY" ]; then
  echo "refusing to publish: the tree has uncommitted changes"
  echo "commit them first, so $VERSION resolves to a revision that can be rebuilt"
  false
fi
if ! git merge-base --is-ancestor HEAD origin/main && [ -z "$DRY" ]; then
  echo "refusing to publish: HEAD is not on origin/main"
  echo "push it first, or fetch if this ref is stale"
  false
fi

if [ -n "$DRY" ]; then
  echo
  echo "dry run — nothing built, nothing published"
  if [ -n "$BLOCKED" ]; then
    echo "would refuse: STADO_RELEASE_PLATFORM is unset, so there is no coordinate"
  fi
  if [ -n "$DIRTY" ]; then
    echo "would refuse: the tree has uncommitted changes"
    BLOCKED=yes
  fi
  if ! git merge-base --is-ancestor HEAD origin/main; then
    echo "would refuse: HEAD is not an ancestor of origin/main"
    BLOCKED=yes
  fi
  # The classification needs a built candidate to interrogate, so it cannot run
  # here. Saying so beats letting --against look honoured when it was not.
  if [ -n "$AGAINST" ]; then
    echo "classification against $AGAINST needs a build; run without --dry-run"
  fi
  if [ -z "$BLOCKED" ]; then
    echo "no guard would refuse this publish"
  fi
  exit
fi

# Bake both in, so the artifact can name itself and its source afterwards.
SKARBIEC_RELEASE_URI="$BINARY" SKARBIEC_RELEASE_COMMIT="$COMMIT" \
  cargo build --release --quiet

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd target/release
DIGEST_LINE="$(openssl dgst -sha256 -r skarbiec)"
DIGEST="${DIGEST_LINE%% *}"
printf '%s  %s\n' "$DIGEST" skarbiec > SHA256SUMS

# Refuse to publish a binary that cannot report the coordinate and the revision it
# was built from. A failed bake means a released artifact whose provenance stops at
# "some tree on some machine", which is the defect this path exists to remove.
REPORTED="$(./skarbiec version | jq -r .release)"
if [ "$REPORTED" != "$BINARY" ]; then
  echo "built binary reports release '$REPORTED', expected '$BINARY'"
  false
fi
STAMPED="$(./skarbiec version | jq -r .commit)"
if [ "$STAMPED" != "$COMMIT" ]; then
  echo "built binary reports commit '$STAMPED', expected '$COMMIT'"
  false
fi

# The number itself is checked against the evidence. The predecessor comes off the
# channel — possible precisely because release downloads need no credentials — and
# is asked for its own command list, so the baseline is the surface that was really
# published. `autoversion decide` then derives the only version this release may
# carry, and publishing under any other is refused.
if [ -n "$AGAINST" ]; then
  PREVIOUS="$WORK/skarbiec-$AGAINST"
  stado storage get "stado://releases/skarbiec/$AGAINST/$PLATFORM/skarbiec" "$PREVIOUS"
  chmod +x "$PREVIOUS"
  surface_of "$PREVIOUS" "$WORK/published.json"
  surface_of ./skarbiec "$WORK/candidate.json"

  # released-surface.json is this repository's record of what the channel serves,
  # and it is checked mechanically rather than trusted. Every baseline document in
  # the fleet carries a named marker as the first whitespace-delimited token of
  # "source"; everything after it is prose for humans. Reading the marker is one
  # jq call, identical in every repository, so no step ever greps prose.
  BASELINE="$HERE/released-surface.json"
  BASELINE_MARKER_PREFIX="stado:"
  MARKER="$(jq -r '.source | split(" ") | first' "$BASELINE")"
  RECORDED="$(jq -r .version "$BASELINE")"

  # The assertion runs both ways, against the registry the marker family names.
  # Skarbiec IS published, to the Stado release channel, so its baseline must say
  # so and the object it names must really be served. A `head:`, `git-archive:` or
  # `pypi-` marker here would be a baseline dodging a release that exists.
  case "$MARKER" in
    "$BASELINE_MARKER_PREFIX"*) ;;
    pypi-*|git-archive:*|head:*)
      echo "released-surface.json carries the marker '$MARKER', which claims the"
      echo "baseline did not come from this channel. Skarbiec is published to"
      echo "stado://releases/skarbiec/, so its baseline has to be recovered from the"
      echo "published artifact and marked '$BASELINE_MARKER_PREFIX<object path>'."
      false ;;
    *)
      echo "unknown baseline marker: $MARKER"
      false ;;
  esac

  # Marker and coordinate are coupled by construction rather than by prose: the
  # object path the marker names must be the one this script itself would build
  # for the version the baseline records.
  RECORDED_OBJECT="${MARKER#"$BASELINE_MARKER_PREFIX"}"
  if [ "$RECORDED_OBJECT" != "releases/skarbiec/$RECORDED/$PLATFORM/skarbiec" ]; then
    echo "released-surface.json records version $RECORDED, but its marker names"
    echo "'$RECORDED_OBJECT', which is not that version's coordinate on $PLATFORM"
    false
  fi

  # Forward: what the baseline claims was published must be downloadable. A
  # baseline nobody can fetch measures nothing.
  CHANNEL="$(stado storage objects releases skarbiec/)"
  case "$CHANNEL" in
    *"$RECORDED_OBJECT"*) ;;
    *)
      echo "released-surface.json names $RECORDED_OBJECT, which the channel does"
      echo "not list. Recover the baseline from a published artifact instead."
      false ;;
  esac

  # And it must be the NEWEST published version, not merely a published one. If
  # the baseline lags the channel, every later comparison is measured against a
  # superseded artifact while still looking healthy. Versions are read by
  # trimming the coordinate rather than by field index, so this carries no bare
  # numeral a reader could mistake for policy.
  NEWEST="$(printf '%s\n' "$CHANNEL" | while read -r line; do
    URI="${line%% *}"
    case "$URI" in
      stado://releases/skarbiec/*/skarbiec)
        TRIMMED="${URI%/*}"
        TRIMMED="${TRIMMED%/*}"
        printf '%s\n' "${TRIMMED##*/}" ;;
    esac
  done | sort -V | awk 'END {print}')"
  if [ "$NEWEST" != "$RECORDED" ]; then
    echo "the channel serves $NEWEST, but released-surface.json records $RECORDED."
    echo "The baseline has to be the newest published version, or the comparison"
    echo "is made against an artifact the channel has already moved past."
    false
  fi
  if [ "$AGAINST" != "$NEWEST" ]; then
    echo "note:     --against $AGAINST is not the newest published ($NEWEST)"
  fi

  # When the baseline names the version being compared against, its recorded
  # surface must equal what that artifact actually advertises. A hand-edited
  # baseline is the one way this whole chain can still lie.
  if [ "$RECORDED" = "$AGAINST" ]; then
    if ! jq -e --slurpfile channel "$WORK/published.json" \
      '.surface == ($channel | first | .surface)' "$BASELINE" > /dev/null; then
      echo "released-surface.json claims to describe $AGAINST, but the artifact on"
      echo "the channel advertises a different surface. Regenerate the baseline from"
      echo "the published binary; do not edit it by hand."
      false
    fi
    echo "baseline: released-surface.json agrees with the published $AGAINST"
  fi

  DECISION="$(autoversion decide --current "$AGAINST" \
    --published-surface "$WORK/published.json" \
    --candidate-surface "$WORK/candidate.json" --json)"
  EXPECTED="$(printf '%s' "$DECISION" | jq -r .next)"
  CHANGE="$(printf '%s' "$DECISION" | jq -r .change)"
  echo "change:   $CHANGE against $AGAINST"
  if [ -n "$BUMP" ]; then
    if [ "$EXPECTED" = "$VERSION" ]; then
      echo "Cargo.toml already says $EXPECTED; nothing to bump"
      exit
    fi
    # Only the first `version = ` line is the package's own. Rewritten with awk
    # rather than sed so no capture group is needed, and the number itself never
    # appears in this script - it arrives from the classifier at run time.
    awk -v want="$EXPECTED" '
      /^version = / && !done { print "version = \"" want "\""; done = "yes"; next }
      { print }
    ' "$HERE/Cargo.toml" > "$HERE/Cargo.toml.next"
    mv "$HERE/Cargo.toml.next" "$HERE/Cargo.toml"
    echo
    echo "Cargo.toml: $VERSION -> $EXPECTED"
    echo "commit and push that, then: sh scripts/publish.sh --against $AGAINST"
    echo
    echo "The bump is a source change and is committed like any other, because a"
    echo "published coordinate has to resolve to a revision that is already pushed."
    exit
  fi
  if [ "$EXPECTED" != "$VERSION" ]; then
    echo "refusing to publish: the surface change against $AGAINST requires $EXPECTED"
    echo "Cargo.toml says $VERSION. Write it mechanically with --bump, or declare"
    echo "breakage the command list cannot show:"
    echo "  autoversion decide --current $AGAINST --published-surface <published>" \
      "--candidate-surface <candidate> --breaking"
    false
  fi
else
  echo "change:   not classified, no --against given"
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
    false ;;
esac
echo "install with: stado storage get $BINARY <destination>"
