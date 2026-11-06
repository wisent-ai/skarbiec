#!/usr/bin/env bash
# Real test of running a program with vault values in its environment,
# `skarbiec exec --env NAME=<id>:<field> -- <program>`, through the built
# binary on a vault of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and
# GNUPGHOME point into this checkout's target directory, so the operator's
# vault and keyring are never read or written.
#
# The program writes the variable it was given into a file: the file holds
# the stored password, while skarbiec's own output and the journal do not.
# The program's exit status is skarbiec's: `false` run through exec ends as
# `false` ends. A --help after -- reaches the program. A missing field, a
# variable name a shell cannot read, a variable named twice and no -- are
# refused, and the program is then never started.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/exec/exec.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/exec/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out; stderr: $said" ;;
  esac
}

SECRET="exec-secret-$RUN"
ITEM="exec-db-$RUN"
SEEN="$ROOT/seen"
: >"$ROOT/stdin"
WANT=ok run init "exec-owner-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"app","password":"%s"},"context":{}}' "$SECRET" >"$ROOT/stdin"
WANT=ok run set "$ITEM" --type login
: >"$ROOT/stdin"

WANT=ok run exec --env "DB_PASSWORD=$ITEM:password" -- sh -c 'printf %s "$DB_PASSWORD" >"$1"' exec-test "$SEEN"
[ "$(cat "$SEEN")" = "$SECRET" ] || fail "the program was not given the stored password"
# The value must be in neither stream, so both are searched.
case "$out$said" in *"$SECRET"*) fail "skarbiec exec printed the value" ;; esac
grep -q '"exec"' "$SKARBIEC_AUDIT_FILE" || fail "exec appended no journal record"
if grep -q "$SECRET" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds the value"; fi
echo "ok: the program reads the value from its environment; output and journal hold none" >>"$REPORT"

# The status `false` ends with, measured here, is the one exec must end with.
if false; then direct=ok; else direct=$?; fi
if "$BIN" exec --env "DB_PASSWORD=$ITEM:password" -- false </dev/null; then through=ok; else through=$?; fi
[ "$through" = "$direct" ] || fail "exec ended with $through where the program ended with $direct"
echo "ok: the program's exit status ($direct) is exec's" >>"$REPORT"

WANT=ok run exec --env "DB_PASSWORD=$ITEM:password" -- sh -c 'printf %s "$2" >"$1"' exec-test "$SEEN" --help
[ "$(cat "$SEEN")" = "--help" ] || fail "a --help after -- did not reach the program"
echo "ok: words after -- reach the program untouched" >>"$REPORT"

rm -f "$SEEN"
WANT=refused run exec --env "DB_PASSWORD=$ITEM:pin" -- sh -c ': >"$1"' exec-test "$SEEN"
names "$ITEM has no text field pin for DB_PASSWORD"
[ ! -e "$SEEN" ] || fail "the program was started although a field was missing"
WANT=refused run exec --env "DB-PASSWORD=$ITEM:password" -- true
names "is not a variable name"
WANT=refused run exec --env "A=$ITEM:password" --env "A=$ITEM:username" -- true
names "A is bound twice"
WANT=refused run exec --env "A=$ITEM:password" true
names "name the program after --"

# A committed bindings file: comments and blank lines skipped, every line
# bound; a line that is not a binding is quoted in the refusal.
printf '# what the job reads\n\nDB_USER=%s:username\nDB_PASSWORD=%s:password\n' "$ITEM" "$ITEM" >"$ROOT/bindings"
WANT=ok run exec --env-from "$ROOT/bindings" -- sh -c 'printf %s "$DB_USER:$DB_PASSWORD" >"$1"' exec-test "$SEEN"
[ "$(cat "$SEEN")" = "app:$SECRET" ] || fail "--env-from did not bind every line of the file"
echo "ok: --env-from binds every line of a bindings file" >>"$REPORT"
printf 'NOT A BINDING\n' >"$ROOT/broken"
WANT=refused run exec --env-from "$ROOT/broken" -- true
names "the line \`NOT A BINDING\`"

# --env-item puts every text field of the login in as DB_<FIELD>.
WANT=ok run exec --env-item "DB=$ITEM" -- sh -c 'printf %s "$DB_USERNAME:$DB_PASSWORD" >"$1"' exec-test "$SEEN"
[ "$(cat "$SEEN")" = "app:$SECRET" ] || fail "--env-item did not put the login's fields in as DB_USERNAME and DB_PASSWORD"
echo "ok: --env-item binds every text field of one item under its prefix" >>"$REPORT"
WANT=refused run exec --env-item "DB=$ITEM" --env "DB_PASSWORD=$ITEM:password" -- true
names "DB_PASSWORD is bound twice"

# --env-tag binds every item carrying the tag under its id in upper case.
TAGGED="jobdb-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"tagged-%s"},"context":{}}' "$RUN" >"$ROOT/stdin"
WANT=ok run set "$TAGGED" --type note --tags "job-$RUN"
: >"$ROOT/stdin"
NAME="$(printf '%s' "$TAGGED" | tr '[:lower:]' '[:upper:]' | tr -c '[:alnum:]' '_')_VALUE"
WANT=ok run exec --env-tag "job-$RUN" -- sh -c 'env >"$1"' exec-test "$SEEN"
grep -qx "$NAME=tagged-$RUN" "$SEEN" || fail "--env-tag did not bind $NAME to the tagged note's value"
echo "ok: --env-tag binds every tagged item under its id" >>"$REPORT"
WANT=refused run exec --env-tag "none-$RUN" -- true
names "no live item carries the tag none-$RUN"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
