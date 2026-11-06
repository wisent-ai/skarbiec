#!/usr/bin/env bash
# Real test of `skarbiec copy` and `skarbiec merge`, through the built binary
# on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME
# point into this checkout's target directory, so the operator's vault and
# keyring are never read or written.
#
# copy --without makes a new item with the original's shape but not the left
# out field, and leaves the original as it was; copying onto an id that exists,
# onto the same id, or leaving out a field the item lacks is refused. merge
# keeps one item and trashes the others, so the live list no longer holds them;
# naming the kept item among the dropped is refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/items/copy_merge.sh
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  if [ "$got" = ok ]; then
    printf '$ skarbiec %s\nresult: ok\n\n' "$*" >>"$REPORT"
  else
    printf '$ skarbiec %s\nresult: refused\noutput: %s\nstderr: %s\n\n' "$*" "$out" "$said" >>"$REPORT"
  fi
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said" ;;
  esac
}
live() {
  WANT=ok run list
  printf '%s' "$out" | jq -e --arg id "$1" 'map(.id) | index($id) != null' >/dev/null
}

: >"$ROOT/stdin"
WANT=ok run init "copy-merge-owner-$RUN"
ORIGINAL="copy-original-$RUN"
COPY="copy-shape-$RUN"
SECRET="copy-secret-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"copy-user-%s","password":"%s"},"context":{"domains":["copy.test"]}}' \
  "$RUN" "$SECRET" >"$ROOT/stdin"
WANT=ok run set "$ORIGINAL" --type login
: >"$ROOT/stdin"

WANT=ok run copy "$ORIGINAL" "$COPY" --without password
WANT=ok run get "$COPY" --field username
[ "$out" = "copy-user-$RUN" ] || fail "the copy does not hold the original's username"
WANT=refused run get "$COPY" --field password
names "password"
WANT=ok run get "$ORIGINAL" --field password
[ "$out" = "$SECRET" ] || fail "copying changed the original's password"
echo "ok: copy --without kept the shape, left out the password and left the original as it was" >>"$REPORT"

WANT=refused run copy "$ORIGINAL" "$COPY"
names "already exists"
WANT=refused run copy "$ORIGINAL" "$ORIGINAL"
names "same id"
WANT=refused run copy "$ORIGINAL" "copy-other-$RUN" --without "missing_$RUN"
names "has no field missing_$RUN"

WANT=refused run merge "$ORIGINAL" "$ORIGINAL"
names "both kept and dropped"
WANT=ok run merge "$ORIGINAL" "$COPY"
live "$ORIGINAL" || fail "merge trashed the item it was told to keep"
if live "$COPY"; then fail "merge left the dropped item live"; fi
echo "ok: merge kept the one item and trashed the other" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
