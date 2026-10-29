#!/usr/bin/env bash
# Real test of `skarbiec env import`, through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault and keyring are
# never read or written.
#
# A .env sets three variables: one exported, one double-quoted with an
# escaped quote, one unquoted with a trailing comment. Without --yes nothing
# is stored. With --yes each is a token item holding exactly the value, the
# bindings file lists NAME=<id>:token, and `exec --env-from` hands the program
# the values. Running it again, an existing bindings file without --replace,
# a line that is not NAME=value and a variable set twice are refused naming
# why, and none of the answers carries a value.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/exec/env_import.sh
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
# A value must be in neither stream, so both are searched.
secretless() {
  case "$out$said" in *"secret-$RUN"*) fail "an answer carried a value: $out; stderr: $said" ;; esac
}

: >"$ROOT/stdin"
WANT=ok run init "env-owner-$RUN"

PREFIX="envtest-$$"
DOTENV="$ROOT/app.env"
BINDINGS="$ROOT/app.env.skarbiec"
DATABASE="postgres://app:secret-$RUN-db@db.example.com/app"
cat >"$DOTENV" <<EOF
# the app's settings
export DATABASE_URL=$DATABASE

API_TOKEN="secret-$RUN-\"api\""
PLAIN_KEY=secret-$RUN-plain # rotated by hand
EOF

WANT=ok run env import "$DOTENV" --prefix "$PREFIX" --bindings "$BINDINGS"
secretless
printf '%s' "$out" | jq -e '.applied == false and (.items | length == 3)' >/dev/null || fail "the preview did not list three variables unapplied"
[ ! -e "$BINDINGS" ] || fail "the preview wrote the bindings file"
WANT=refused run get "$PREFIX-database-url" --field token
echo "ok: without --yes nothing is stored and no bindings are written" >>"$REPORT"

WANT=ok run env import "$DOTENV" --prefix "$PREFIX" --bindings "$BINDINGS" --tags "$PREFIX" --yes
secretless
WANT=ok run get "$PREFIX-database-url" --field token
[ "$out" = "$DATABASE" ] || fail "DATABASE_URL was stored as: $out"
WANT=ok run get "$PREFIX-api-token" --field token
[ "$out" = "secret-$RUN-\"api\"" ] || fail "the double-quoted API_TOKEN was stored as: $out"
WANT=ok run get "$PREFIX-plain-key" --field token
[ "$out" = "secret-$RUN-plain" ] || fail "the unquoted PLAIN_KEY kept its comment or lost text: $out"
grep -qx "DATABASE_URL=$PREFIX-database-url:token" "$BINDINGS" || fail "the bindings file does not bind DATABASE_URL"
grep -qx "PLAIN_KEY=$PREFIX-plain-key:token" "$BINDINGS" || fail "the bindings file does not bind PLAIN_KEY"
echo "ok: --yes stores every value exactly and writes the bindings" >>"$REPORT"

WANT=ok run exec --env-from "$BINDINGS" -- sh -c 'printf "%s|%s" "$DATABASE_URL" "$PLAIN_KEY"'
[ "$out" = "$DATABASE|secret-$RUN-plain" ] || fail "exec --env-from did not hand the program the values: $out"
echo "ok: exec --env-from runs the program with the imported values" >>"$REPORT"

WANT=refused run env import "$DOTENV" --prefix "$PREFIX" --yes
names "already exist"
WANT=refused run env import "$DOTENV" --prefix "other-$$" --bindings "$BINDINGS" --yes
names "add --replace"
printf 'GOOD=one\nnot a setting\n' >"$ROOT/broken.env"
WANT=refused run env import "$ROOT/broken.env" --prefix "broken-$$" --yes
names "line 2 is not NAME=value"
printf 'TWICE=one\nTWICE=two\n' >"$ROOT/twice.env"
WANT=refused run env import "$ROOT/twice.env" --prefix "twice-$$" --yes
names "line 2 sets TWICE again, first set on line 1"
WANT=refused run get "twice-$$-twice" --field token
WANT=refused run env import "$DOTENV"
names "usage: env import"
WANT=refused run env "$DOTENV" --prefix "$PREFIX"
names "is not a form of env"
WANT=refused run env-import "$DOTENV" --prefix "$PREFIX"
names "unknown command: env-import"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
