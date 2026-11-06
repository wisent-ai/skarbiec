#!/usr/bin/env bash
# Real test of `skarbiec rotate --with database`, through the built binary on a vault of
# its own and a real database server: SKARBIEC_TEST_DB_URL names the database
# as postgresql://host[:port]/dbname or mysql://host[:port]/dbname, and
# SKARBIEC_TEST_DB_ADMIN an account there that may create and drop accounts,
# whose password the client reads from its own configuration (~/.pgpass,
# ~/.my.cnf) or the server's trust. The test makes an account of its own,
# carrying this run's id, and drops it at the end. SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE and GNUPGHOME point into this checkout's target
# directory, so the operator's vault and keyring are never read or written.
#
# After rotate --with database the account signs in with the item's new password and not
# with the old one, and the old one is the item's saved version. Rotating
# with a wrong stored password fails, leaves the server alone, and the item
# holds the password it held before. No password is printed.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_DB_URL=postgresql://localhost/postgres SKARBIEC_TEST_DB_ADMIN=postgres tests/rotation/db_rotate.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
URL=${SKARBIEC_TEST_DB_URL:?set SKARBIEC_TEST_DB_URL to postgresql://host[:port]/dbname or mysql://host[:port]/dbname of a server this test may make and drop an account on}
ADMIN=${SKARBIEC_TEST_DB_ADMIN:?set SKARBIEC_TEST_DB_ADMIN to an account there that may create and drop accounts}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/rotation/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "database: $URL" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
ACCOUNT="skarbiec_test_$$"
FIRST="first$$Secret"

case "$URL" in
  postgresql://* | postgres://*)
    admin() { psql -X -q -v ON_ERROR_STOP=on -U "$ADMIN" -d "$URL" -c "$*" &>>"$REPORT"; }
    signs_in() { PGPASSWORD="$*" psql -X -q -U "$ACCOUNT" -d "$URL" -c "SELECT current_user" &>>"$REPORT"; }
    CREATE="CREATE ROLE $ACCOUNT LOGIN PASSWORD '$FIRST'"
    DROP="DROP ROLE IF EXISTS $ACCOUNT"
    ;;
  mysql://*)
    IFS=/ read -r ADDRESS DATABASE <<<"${URL#mysql://}"
    IFS=: read -r HOST PORT <<<"$ADDRESS"
    PORT_ARGS=()
    if [ -n "$PORT" ]; then PORT_ARGS=(-P "$PORT"); fi
    admin() { mysql --batch -h "$HOST" "${PORT_ARGS[@]}" -u "$ADMIN" -D "$DATABASE" -e "$*" &>>"$REPORT"; }
    signs_in() { MYSQL_PWD="$*" mysql --batch --no-defaults -h "$HOST" "${PORT_ARGS[@]}" -u "$ACCOUNT" -D "$DATABASE" -e "SELECT CURRENT_USER()" &>>"$REPORT"; }
    CREATE="CREATE USER '$ACCOUNT'@'%' IDENTIFIED BY '$FIRST'; GRANT USAGE ON \`$DATABASE\`.* TO '$ACCOUNT'@'%'; GRANT SELECT ON \`$DATABASE\`.* TO '$ACCOUNT'@'%'"
    DROP="DROP USER IF EXISTS '$ACCOUNT'@'%'"
    ;;
  *)
    echo "SKARBIEC_TEST_DB_URL $URL is neither postgresql:// nor mysql://" >/dev/stderr
    false
    ;;
esac
cleanup() {
  admin "$DROP" || echo "cleanup: could not drop $ACCOUNT" >>"$REPORT"
  gpgconf --homedir "$GNUPGHOME" --kill all
  rm -rf "$KEYRING"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
item() {
  jq -n --arg user "$ACCOUNT" --arg password "$*" '{schema:"skarbiec.item.v2",kind:"login",fields:{username:$user,password:$password},context:{}}' >"$ROOT/stdin"
  WANT=ok run set "$ITEM" --type login
  : >"$ROOT/stdin"
}

admin "$CREATE" || fail "could not create the test account"
: >"$ROOT/stdin"
WANT=ok run init "db-owner-$RUN"
ITEM="db-$RUN"
LENGTH="$(printf '%s' "$FIRST$FIRST" | wc -c | tr -d ' ')"
item "$FIRST"

WANT=ok run rotate "$ITEM" --with database --url "$URL" --length "$LENGTH"
# Neither stream may carry the old password.
case "$out$said" in *"$FIRST"*) fail "rotate printed the old password" ;; esac
WANT=ok run get "$ITEM" --field password
NEW="$out"
[ "$NEW" != "$FIRST" ] || fail "the item still holds the old password"
signs_in "$NEW" || fail "the account does not sign in with the item's new password"
if signs_in "$FIRST"; then fail "the account still signs in with the old password"; fi
STAMP="$("$BIN" history "$ITEM" </dev/null | jq -r '[.versions[] | select(.current | not)] | last | .at')"
WANT=ok run get "$ITEM" --at "$STAMP" --field password
[ "$out" = "$FIRST" ] || fail "the old password is not the item's saved version"
echo "ok: the server and the item hold the new password, the old one is a saved version" >>"$REPORT"

item "wrong$$"
WANT=refused run rotate "$ITEM" --with database --url "$URL" --length "$LENGTH"
case "$said" in *"the server holds the old password, and so does $ITEM again"*) ;; *) fail "the refusal does not say the item holds the old password again: $said; output: $out" ;; esac
WANT=ok run get "$ITEM" --field password
[ "$out" = "wrong$$" ] || fail "a failed rotation did not put the item's password back"
signs_in "$NEW" || fail "a failed rotation changed the server's password"
echo "ok: a refused rotation leaves the server alone and the item as it was" >>"$REPORT"

WANT=refused run rotate "$ITEM" --with database --url "postgresql://$ACCOUNT@localhost/db" --length "$LENGTH"
case "$said" in *"never the address"*) ;; *) fail "an address naming a user was not refused: $said; output: $out" ;; esac
WANT=refused run rotate "$ITEM" --with database --url "redis://localhost/db" --length "$LENGTH"
case "$said" in *"neither postgresql:// nor mysql://"*) ;; *) fail "an unknown scheme was not refused: $said; output: $out" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
