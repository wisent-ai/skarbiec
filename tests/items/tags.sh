#!/usr/bin/env bash
# Real test of acting on every item one tag names, `skarbiec retag --rename
# <tag> --to <tag>`, `skarbiec delete --tag <tag> [--yes]` and `skarbiec
# restore --tag <tag> [--yes]`, through the built binary on a vault of its
# own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into this
# checkout's target directory, so the operator's vault and keyring are never
# read or written.
#
# Two notes carry one tag and a third does not. Renaming the tag moves it on
# both and leaves the third alone; delete --tag without --yes lists both and
# trashes nothing; with --yes both leave the live list and the third stays;
# restore brings one back, and restore --tag lists the other and with --yes
# brings it back too. A tag no item carries, and renaming a tag to itself,
# are refused naming why.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/items/tags.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/items/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all || true; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\noutput: %s\n\n' "$*" "$got" "$out" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
note() {
  printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$1-value" >"$ROOT/stdin"
  WANT=ok run set "$1" --type note --tags "$2"
  : >"$ROOT/stdin"
}
live() {
  WANT=ok run list
  printf '%s' "$out" | jq -e --arg id "$1" 'map(.id) | index($id) != null' >/dev/null
}
tags_of() {
  WANT=ok run list
  printf '%s' "$out" | jq -c --arg id "$1" '.[] | select(.id == $id) | .tags'
}

: >"$ROOT/stdin"
WANT=ok run init "tags-owner-$RUN"
OLD="project-$RUN"
NEW="ended-$RUN"
ONE="tags-one-$RUN"
TWO="tags-two-$RUN"
OTHER="tags-other-$RUN"
note "$ONE" "$OLD"
note "$TWO" "$OLD"
note "$OTHER" "keep-$RUN"

WANT=ok run retag --rename "$OLD" --to "$NEW"
[ "$(tags_of "$ONE")" = "[\"$NEW\"]" ] || fail "--rename did not move the tag on the first item"
[ "$(tags_of "$TWO")" = "[\"$NEW\"]" ] || fail "--rename did not move the tag on the second item"
[ "$(tags_of "$OTHER")" = "[\"keep-$RUN\"]" ] || fail "--rename touched an item without the tag"
echo "ok: --rename moved the tag on every item carrying it and on no other" >>"$REPORT"

WANT=ok run delete --tag "$NEW"
[ "$(printf '%s' "$out" | jq -r .confirmed)" = false ] || fail "delete --tag without --yes trashed something"
live "$ONE" || fail "delete --tag without --yes took an item out of the live list"
WANT=ok run delete --tag "$NEW" --yes
if live "$ONE"; then fail "delete --tag --yes left the first item live"; fi
if live "$TWO"; then fail "delete --tag --yes left the second item live"; fi
live "$OTHER" || fail "delete --tag --yes trashed an item without the tag"
WANT=ok run restore "$ONE"
live "$ONE" || fail "restore did not bring back an item delete --tag trashed"
echo "ok: delete --tag lists first, trashes only the tagged items with --yes, and restore undoes one" >>"$REPORT"

WANT=ok run restore --tag "$NEW"
[ "$(printf '%s' "$out" | jq -c .would_restore)" = "[\"$TWO\"]" ] || fail "restore --tag without --yes did not list exactly the item still trashed"
if live "$TWO"; then fail "restore --tag without --yes brought an item back"; fi
WANT=ok run restore --tag "$NEW" --yes
live "$TWO" || fail "restore --tag --yes did not bring back the trashed item"
echo "ok: restore --tag lists the trashed items first and brings them all back with --yes" >>"$REPORT"
WANT=refused run restore --tag "$NEW" --yes
names "no trashed item carries the tag $NEW"

SET="set-$RUN"
WANT=ok run retag --add "$SET" "$ONE" "$OTHER"
[ "$(tags_of "$ONE")" = "[\"$NEW\",\"$SET\"]" ] || fail "retag --add did not keep the first item's tag beside the new one"
[ "$(tags_of "$OTHER")" = "[\"keep-$RUN\",\"$SET\"]" ] || fail "retag --add did not keep the other item's tag beside the new one"
WANT=ok run retag --add "$SET" "$ONE"
[ "$(printf '%s' "$out" | jq -c .unchanged)" = "[\"$ONE\"]" ] || fail "retag --add of a tag already carried was not reported unchanged"
WANT=ok run retag --remove "$SET" "$OTHER"
[ "$(tags_of "$OTHER")" = "[\"keep-$RUN\"]" ] || fail "retag --remove did not take only that tag off"
echo "ok: retag --add and --remove change one tag on several items and keep the rest" >>"$REPORT"
WANT=refused run retag --add "$SET"
names "usage: retag --add <tag> <id>"

WANT=refused run delete --tag "nobody-$RUN" --yes
names "no live item carries the tag nobody-$RUN"
WANT=refused run retag --rename "keep-$RUN" --to "keep-$RUN"
names "nothing to rename"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
