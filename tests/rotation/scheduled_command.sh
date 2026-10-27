#!/usr/bin/env bash
# Real test of `rotation set --with`, through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault and keyring are
# never read or written. The ssh provider is the one the policy rotates
# through, because it needs nothing outside this machine.
#
# A key-pair item gets a policy rotating with ssh; rotation list names the
# provider; removing a person who could read the key marks it due; rotation
# run then rotates it through ssh — the item holds a new public key, the
# policy records rotated and is no longer due. A provider that does not
# exist, and a flag the provider does not take, are refused before any
# policy is kept. A rename carries the policy to the new id, and a purge
# forgets it.
#
# Usage: declare ROTATION_DAYS and ROTATION_PASSWORD_LENGTH, then run:
# SKARBIEC=target/debug/skarbiec bash tests/rotation/scheduled_command.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
DAYS=${ROTATION_DAYS:?set ROTATION_DAYS to the fixture interval in whole days}
PASSWORD_LENGTH=${ROTATION_PASSWORD_LENGTH:?set ROTATION_PASSWORD_LENGTH to the database password length under test}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/rotation/$RUN"
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
  if out=$("$BIN" "$@" </dev/null &>/dev/stdout); then got=ok; else got=refused; fi
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out"
}
names() {
  case "$out" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $out" ;;
  esac
}

WANT=ok run init "rotation-owner-$RUN"
KEY="deploy-$RUN"
PERSON="leaver-$RUN@example.com"
WANT=ok run ssh new "$KEY"
BEFORE="$(printf '%s' "$out" | jq -r .public_key)"

WANT=refused run rotation set "$KEY" --every-days "$DAYS" --with owner
names "--with owner"
WANT=refused run rotation set "$KEY" --every-days "$DAYS" --with ssh --url postgresql://db.example.com/app
names "--url"
WANT=ok run rotation list
printf '%s' "$out" | jq -e '.policies == []' >/dev/null || fail "a refused rotation set kept a policy"

WANT=ok run rotation set "$KEY" --every-days "$DAYS" --with ssh --comment "scheduled-$RUN"
WANT=ok run rotation list
POLICY="$(printf '%s' "$out" | jq --arg key "$KEY" '.policies[] | select(.item == $key)')"
[ "$(printf '%s' "$POLICY" | jq -r .with)" = "ssh" ] || fail "rotation list does not name ssh: $POLICY"
[ "$(printf '%s' "$POLICY" | jq -r '.with_flags.comment')" = "scheduled-$RUN" ] || fail "rotation list does not keep --comment: $POLICY"
[ "$(printf '%s' "$POLICY" | jq -r .due)" = "false" ] || fail "a new policy is due already: $POLICY"
echo "ok: the policy keeps the ssh provider and its flags and is not due yet" >>"$REPORT"

WANT=ok run recipient add "$PERSON"
WANT=ok run share "$KEY" "$PERSON"
WANT=ok run recipient remove "$PERSON" --yes
printf '%s' "$out" | jq -e --arg key "$KEY" '.rotation_marked_due | index($key)' &>/dev/null || fail "removing a reader did not mark $KEY due: $out"
WANT=ok run rotation run --item "$KEY"
printf '%s' "$out" | jq -e --arg key "$KEY" '(.ran | map(.item)) == [$key] and (.ran | all(.status == "rotated"))' >/dev/null \
  || fail "rotation run did not rotate exactly the requested SSH policy: $out"
WANT=ok run get "$KEY" --field public_key
[ "$out" != "$BEFORE" ] || fail "the item still holds the old public key"
case "$out" in *"scheduled-$RUN"*) ;; *) fail "the new key does not carry the policy's --comment: $out" ;; esac
WANT=ok run rotation list
POLICY="$(printf '%s' "$out" | jq --arg key "$KEY" '.policies[] | select(.item == $key)')"
[ "$(printf '%s' "$POLICY" | jq -r .last_status)" = "rotated" ] || fail "the policy does not record rotated: $POLICY"
[ "$(printf '%s' "$POLICY" | jq -r .due)" = "false" ] || fail "the policy is still due after its rotation: $POLICY"
echo "ok: a removed reader makes the key due and rotation run replaces it through ssh" >>"$REPORT"
rotations_check() {
  "$BIN" doctor </dev/null >"$ROOT/doctor.json" || echo "doctor exited non-zero; its checks follow" >>"$REPORT"
  jq -r '.checks[] | select(.check == "rotations") | "\(.status) \(.detail)"' "$ROOT/doctor.json"
}
CHECK="$(rotations_check)"
[ "${CHECK%% *}" = "pass" ] || fail "doctor's rotations check does not pass after a rotation: $CHECK"
echo "ok: doctor's rotations check passes once the policy rotated" >>"$REPORT"

# A policy whose provider refuses — database with no address to reach —
# fails its run, and doctor names it with the provider's words.
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"app","password":"before-%s"},"context":{}}' "$RUN" >"$ROOT/login.json"
"$BIN" set "db-$RUN" --type login <"$ROOT/login.json" &>>"$REPORT"
WANT=ok run rotation set "db-$RUN" --every-days "$DAYS" --with database --length "$PASSWORD_LENGTH"
WANT=ok run recipient add "second-$PERSON"
WANT=ok run share "db-$RUN" "second-$PERSON"
WANT=ok run recipient remove "second-$PERSON" --yes
WANT=refused run rotation run --item "db-$RUN"
CHECK="$(rotations_check)"
[ "${CHECK%% *}" = "fail" ] || fail "doctor's rotations check does not fail on the failing policy: $CHECK"
printf '%s' "$CHECK" | grep -q "db-$RUN" || fail "doctor's rotations check does not name the failing policy: $CHECK"
printf '%s' "$CHECK" | grep -q -- "--url" || fail "doctor's rotations check does not carry the database provider's words: $CHECK"
echo "ok: doctor's rotations check names the failing policy with the database provider's words" >>"$REPORT"
WANT=ok run rotation remove "db-$RUN"

RENAMED="renamed-$RUN"
WANT=ok run rename "$KEY" "$RENAMED"
[ "$(printf '%s' "$out" | jq -r .rotation_policy_moved)" = "true" ] || fail "rename did not say it moved the policy: $out"
WANT=ok run rotation list
printf '%s' "$out" | jq -e --arg old "$KEY" --arg new "$RENAMED" '(.policies | any(.item == $new and .with == "ssh")) and (.policies | any(.item == $old) | not)' &>/dev/null \
  || fail "the policy did not follow the rename: $out"
WANT=ok run delete "$RENAMED"
WANT=ok run purge "$RENAMED" --yes
WANT=ok run rotation list
if printf '%s' "$out" | jq -e --arg new "$RENAMED" '.policies | any(.item == $new)' &>/dev/null; then fail "purge left the policy behind: $out"; fi
echo "ok: a rename carries the policy and a purge forgets it" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
