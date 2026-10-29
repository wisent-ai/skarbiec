#!/usr/bin/env bash
# Real test of reading an item as it was, `skarbiec get <id> --at <stamp>`, and
# of finding it by its notes, `skarbiec find <text> --notes`, through the built
# binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written.
#
# A login's password is changed once; get --at the first stamp history lists
# reads the old password and a plain get the new one, and --revision together
# with --at is refused. Notes are set on stdin; find does not look in them
# unless --notes asks it to, and then names notes as where the item matched.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/history/find_and_versions.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/history/$RUN"
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
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out; stderr: $said" ;;
  esac
}
login() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"history-user","password":"%s"},"context":{"domains":["history.test"]}}' \
    "$1" >"$ROOT/stdin"
  WANT=ok run set "$ITEM" --type login
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "history-owner-$RUN"
ITEM="history-login-$RUN"
OLD="history-old-$RUN"
NEW="history-new-$RUN"
login "$OLD"
login "$NEW"

WANT=ok run history "$ITEM"
FIRST=$(printf '%s' "$out" | jq -r '.versions | first | .at')
WANT=ok run get "$ITEM" --field password --at "$FIRST"
[ "$out" = "$OLD" ] || fail "get --at the first stamp did not read the password as it was"
WANT=ok run get "$ITEM" --field password
[ "$out" = "$NEW" ] || fail "a plain get did not read the current password"
WANT=refused run get "$ITEM" --revision --at "$FIRST"
names "--at"
echo "ok: get --at reads the saved version, a plain get the current one" >>"$REPORT"

NOTE="rotate on the first quarter day $RUN"
printf '%s' "$NOTE" >"$ROOT/stdin"
WANT=ok run notes "$ITEM" --set
: >"$ROOT/stdin"
WANT=ok run find "first quarter day $RUN"
printf '%s' "$out" | jq -e '.items | length == 0' >/dev/null || fail "find looked in notes without --notes"
WANT=ok run find "first quarter day $RUN" --notes
printf '%s' "$out" | jq -e --arg id "$ITEM" '.items | any(.item == $id and (.matched | index("notes") != null))' >/dev/null \
  || fail "find --notes did not name the item as matched in its notes"
echo "ok: find looks in notes only with --notes, and says it matched there" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
