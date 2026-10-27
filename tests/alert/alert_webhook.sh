#!/usr/bin/env bash
# Real test of `skarbiec alert`, through the built binary on a vault of its
# own and a real chat webhook: SKARBIEC_TEST_WEBHOOK_URL is an https incoming
# webhook of a channel kept for this test (Slack, Mattermost, Teams or
# Discord), which this test posts to. SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE
# and GNUPGHOME point into this checkout's target directory, so the
# operator's vault and keyring are never read or written.
#
# set writes the item and field beside the vault file and never the address;
# test posts through the webhook and journals alert-sent without the address;
# a rotation run whose policy fails posts the failure and says so; unset
# removes the setting, after which test is refused. An address that is not
# https and a set without --field are refused with nothing written.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_WEBHOOK_URL=<webhook> tests/alert/alert_webhook.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
URL=${SKARBIEC_TEST_WEBHOOK_URL:?set SKARBIEC_TEST_WEBHOOK_URL to an https webhook of a channel this test may post to}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/alert/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}
note() {
  jq -n --arg value "$2" '{schema:"skarbiec.item.v2",kind:"note",fields:{value:$value},context:{}}' >"$ROOT/stdin"
  WANT=ok run set "$1" --type note
  : >"$ROOT/stdin"
}

: >"$ROOT/stdin"
WANT=ok run init "alert-owner-$RUN"
note "hook-$RUN" "$URL"
note "plain-$RUN" "http://hooks.example.com/not-secure"

WANT=refused run alert set "hook-$RUN"
WANT=refused run alert set "plain-$RUN" --field value
names "is not an https:// address"
[ ! -e "$SKARBIEC_VAULT_FILE.alert" ] || fail "a refused set wrote the setting"
WANT=refused run alert test
names "no alert is set on this host"

WANT=ok run alert set "hook-$RUN" --field value
if grep -qF "$URL" "$SKARBIEC_VAULT_FILE.alert"; then fail "the setting holds the webhook address"; fi
WANT=ok run alert status
[ "$(printf '%s' "$out" | jq -r .item)" = "hook-$RUN" ] || fail "status does not name the item: $out"
WANT=ok run alert test
[ "$(printf '%s' "$out" | jq -r .sent)" = "true" ] || fail "test did not post: $out"
grep -q '"alert-sent"' "$SKARBIEC_AUDIT_FILE" || fail "the post was not journalled"
if grep -qF "$URL" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds the webhook address"; fi
echo "ok: set keeps no address, test posts and the journal holds no address" >>"$REPORT"

# A policy whose command is refused fails the rotation run, which posts it;
# --now runs it before it falls due.
note "rotated-$RUN" "not a database password"
WANT=ok run rotation set "rotated-$RUN" --every-days "$(printf 'd' | wc -c | tr -d ' ')" --with database --url postgresql://db.example.com/app --length "$(printf 'dddddddddddddddd' | wc -c | tr -d ' ')"
WANT=refused run rotation run --now
names "needs --item"
WANT=refused run rotation run --item "rotated-$RUN" --now
names "the alert was posted"
echo "ok: a failed rotation run posts the failure" >>"$REPORT"

# The failed rotation leaves the rotations check failing; doctor --alert
# posts it, whatever doctor's other checks say on this host.
out=$("$BIN" doctor --alert </dev/null 2>>"$REPORT")
printf '$ skarbiec doctor --alert\n%s\n\n' "$out" >>"$REPORT"
[ "$(printf '%s' "$out" | jq -r '.alert.posted')" = "true" ] || fail "doctor --alert did not post the failing rotations check: $out"
echo "ok: doctor --alert posts the failed checks" >>"$REPORT"

# The policy is due and failing, so the review's rotations_due section holds
# a row; review --alert posts it, naming counts and never the note's text.
WANT=ok run review --before "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --alert
[ "$(printf '%s' "$out" | jq -r '.alert.posted')" = "true" ] || fail "review --alert did not post its findings: $out"
echo "ok: review --alert posts the sections holding rows" >>"$REPORT"

WANT=ok run alert unset
[ ! -e "$SKARBIEC_VAULT_FILE.alert" ] || fail "unset left the setting"
WANT=refused run alert test
names "no alert is set on this host"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
