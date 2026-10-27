#!/usr/bin/env bash
# Reusable real-vault journey; its final scheduled SSH rotation replaces a key.
# SKARBIEC=target/debug/skarbiec ROTATION_DAYS=<positive days> \
#   bash tests/rotation/provider_upgrade.sh
set -euo pipefail
cd -P "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the actual skarbiec executable}
DAYS=${ROTATION_DAYS:?set ROTATION_DAYS to the fixture policy interval}
mkdir -p .build
# Standard descriptor values: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/unistd.h.html
[ "$(cd .build && pwd -P)" = "$PWD/.build" ] || { echo '.build redirects outside the checkout' >&2; false; }
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p .build/rotation-provider-upgrade
[ "$(cd .build/rotation-provider-upgrade && pwd -P)" = "$PWD/.build/rotation-provider-upgrade" ] \
  || { echo 'the report directory redirects outside the checkout' >/dev/stderr; false; }
ROOT="$PWD/.build/rotation-provider-upgrade/$RUN"
KEYRING="$PWD/.build/g$$"
mkdir "$ROOT" "$KEYRING"
chmod go-rwx "$ROOT" "$KEYRING"
REPORT="$ROOT/report.txt"
COMPLETED=no
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/vault/audit.jsonl"
mkdir -p "$ROOT/home" "$ROOT/tmp" "$ROOT/vault" "$ROOT/source" \
  "$ROOT/calls" "$ROOT/fixtures" "$ROOT/assertions/apply" "$ROOT/assertions/repeat"
COMMAND=(
  env -i "PATH=$PATH" "HOME=$ROOT/home" "TMPDIR=$ROOT/tmp"
  "GNUPGHOME=$GNUPGHOME" "SKARBIEC_VAULT_FILE=$SKARBIEC_VAULT_FILE"
  "SKARBIEC_AUDIT_FILE=$SKARBIEC_AUDIT_FILE" "$BIN"
)

finish() {
  original=$?
  trap - EXIT
  # Standard descriptor values: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/unistd.h.html
  if gpgconf --homedir "$KEYRING" --kill all >>"$REPORT" 2>&1; then
    if rm -rf "$KEYRING"; then
      # Success exit status: https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html
      if [ "$COMPLETED" = yes ] && [ "$original" -eq 0 ]; then
        printf 'passed\n' >"$ROOT/state"
        printf 'PASS: %s\n' "$REPORT" >>"$REPORT"
      else
        printf 'failed\n' >"$ROOT/state"
      fi
      printf 'journey exit: %s\n' "$original" >>"$REPORT"
      exit "$original"
    else
      cleanup=$?
    fi
  else
    cleanup=$?
  fi
  printf 'failed\n' >"$ROOT/state"
  printf 'isolated keyring cleanup failed: %s\n' "$cleanup" >>"$REPORT"
  exit "$cleanup"
}
trap finish EXIT
printf 'running\n' >"$ROOT/state"
git rev-parse HEAD >"$ROOT/source/revision.txt"
tar -cf "$ROOT/source/snapshot.tar" Cargo.toml Cargo.lock src tests/rotation/provider_upgrade.sh
openssl dgst -sha256 "$BIN" "$ROOT/source/snapshot.tar" >"$ROOT/source/digests.txt"
printf 'binary: %s\nsource: %s\ninterval: %s days\n' "$BIN" "$ROOT/source/revision.txt" "$DAYS" >"$REPORT"

fail() {
  # Standard error: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/unistd.h.html
  printf 'FAIL: %s\n' "$*" | tee -a "$REPORT" >&2
  false
}
run() {
  label=$1
  shift
  expected=$1
  shift
  mkdir "$ROOT/calls/$label"
  OUT_FILE="$ROOT/calls/$label/stdout"
  ERR_FILE="$ROOT/calls/$label/stderr"
  printf '$' >>"$REPORT"
  printf ' %q' "${COMMAND[@]}" "$@" >>"$REPORT"
  printf '\n' >>"$REPORT"
  # Standard error: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/unistd.h.html
  if "${COMMAND[@]}" "$@" </dev/null >"$OUT_FILE" 2>"$ERR_FILE"; then
    CODE=$?
    got=ok
  else
    CODE=$?
    got=refused
  fi
  printf 'exit: %s\nstdout: %s\nstderr: %s\n' "$CODE" "$OUT_FILE" "$ERR_FILE" >>"$REPORT"
  case "$expected" in
    ok) [ "$got" = ok ] || fail "$label refused; inspect $ERR_FILE" ;;
    usage)
      # Usage refusal: https://skarbiec.wisent.com/docs/cli
      [ "$CODE" -eq 2 ] || fail "$label did not return a usage refusal; inspect $ERR_FILE"
      ;;
    refused) [ "$got" = refused ] || fail "$label accepted damaged persisted state" ;;
    *) fail "unknown journey expectation: $expected" ;;
  esac
}

KEY="migrated-$RUN"
UNKNOWN="unknown-$RUN"
run init ok init "policy-upgrade-owner-$RUN"
run key ok ssh new "$KEY"
run unknown-key ok ssh new "$UNKNOWN"
run policy ok rotation set "$KEY" --every-days "$DAYS" --with ssh --comment "policy-$RUN"
run unknown-policy ok rotation set "$UNKNOWN" --every-days "$DAYS" --with ssh
run baseline ok upgrade --apply
run before-key ok get "$KEY" --field public_key
BEFORE_KEY="$(cat "$OUT_FILE")"
cp "$SKARBIEC_VAULT_FILE" "$ROOT/fixtures/canonical.vault.json"

# Older metadata over the actual encrypted vault: no fabricated provider response.
jq --arg key "$KEY" --arg unknown "$UNKNOWN" \
  '.rotation[$key].submission.with = "ssh-rotate" | .rotation[$unknown].submission.with = "unregistered-source"' \
  "$ROOT/fixtures/canonical.vault.json" >"$ROOT/fixtures/legacy.vault.json"
chmod go-rwx "$ROOT/fixtures/legacy.vault.json"
cp "$ROOT/fixtures/legacy.vault.json" "$SKARBIEC_VAULT_FILE"

run rotate-alias usage rotate "$KEY" --with ssh-rotate
cmp "$ROOT/fixtures/legacy.vault.json" "$SKARBIEC_VAULT_FILE" || fail 'refused rotate changed the vault'
run policy-alias usage rotation set "$KEY" --every-days "$DAYS" --with ssh-rotate
cmp "$ROOT/fixtures/legacy.vault.json" "$SKARBIEC_VAULT_FILE" || fail 'refused policy alias changed the vault'
run policy-view ok rotation list
jq -e --arg key "$KEY" \
  '.policies | any(.item == $key and .with == "ssh-rotate" and (.with_error | contains("skarbiec upgrade --apply")))' \
  "$OUT_FILE" >/dev/null || fail 'legacy policy was hidden or omitted its upgrade route'

run preview ok upgrade
jq -e --arg key "$KEY" --arg unknown "$UNKNOWN" \
  '(.rotation_policies.applied == false) and
   (.rotation_policies.changes | any(.item == $key and .from == "ssh-rotate" and .to == "ssh")) and
   (.rotation_policies.unrecognized | any(.item == $unknown and .provider == "unregistered-source"))' \
  "$OUT_FILE" >/dev/null || fail 'preview did not distinguish known conversion from unknown provider'
cmp "$ROOT/fixtures/legacy.vault.json" "$SKARBIEC_VAULT_FILE" || fail 'preview wrote the vault'

# Without policy validation, the missing identifier would make upgrade write.
# The damaged policy must refuse before that backfill can happen.
jq --arg key "$KEY" \
  '.rotation[$key].submission.with = {unexpected: true} | del(.items[$key].item_uid)' \
  "$SKARBIEC_VAULT_FILE" >"$ROOT/fixtures/damaged.vault.json"
chmod go-rwx "$ROOT/fixtures/damaged.vault.json"
cp "$ROOT/fixtures/damaged.vault.json" "$SKARBIEC_VAULT_FILE"
run malformed-view ok rotation list
jq -e --arg key "$KEY" \
  '.policies | any(.item == $key and .with == null and (.with_error | contains("submission.with")))' \
  "$OUT_FILE" >/dev/null || fail 'damaged provider metadata made the list unreadable or hid its field diagnostic'
run malformed refused upgrade --apply
case "$(cat "$ERR_FILE")" in
  *"$KEY"*"submission.with"*) ;;
  *) fail 'malformed provider refusal omitted the affected item or field' ;;
esac
cmp "$ROOT/fixtures/damaged.vault.json" "$SKARBIEC_VAULT_FILE" || fail 'malformed policy was partly upgraded'
cp "$ROOT/fixtures/legacy.vault.json" "$SKARBIEC_VAULT_FILE"

jq -S --arg key "$KEY" '.rotation[$key].submission.with = "ssh" | del(.generation)' \
  "$SKARBIEC_VAULT_FILE" >"$ROOT/assertions/apply/expected.json"
run apply ok upgrade --apply
jq -e --arg key "$KEY" --arg unknown "$UNKNOWN" \
  '(.rotation_policies.applied == true) and
   (.rotation_policies.changes | any(.item == $key and .from == "ssh-rotate" and .to == "ssh")) and
   (.rotation_policies.unrecognized | any(.item == $unknown and .provider == "unregistered-source"))' \
  "$OUT_FILE" >/dev/null || fail 'apply omitted its changes or unrecognized-state diagnostics'
jq -S 'del(.generation)' "$SKARBIEC_VAULT_FILE" >"$ROOT/assertions/apply/observed.json"
cmp "$ROOT/assertions/apply/expected.json" "$ROOT/assertions/apply/observed.json" \
  || fail 'upgrade changed cadence, flags, history, payloads or unrelated vault metadata'
jq -se --arg key "$KEY" --arg unknown "$UNKNOWN" \
  'any(.op == "rotation-policies-upgraded" and .extra.applied == true and
       (.extra.changes | any(.item == $key and .from == "ssh-rotate" and .to == "ssh")) and
       (.extra.unrecognized | any(.item == $unknown and .provider == "unregistered-source")))' \
  "$SKARBIEC_AUDIT_FILE" >/dev/null || fail 'the applied metadata conversion was not durably audited'
cp "$SKARBIEC_VAULT_FILE" "$ROOT/assertions/repeat/before.vault.json"
run repeat ok upgrade --apply
jq -e --arg unknown "$UNKNOWN" \
  '.rotation_policies.applied == true and .rotation_policies.changes == [] and
   (.rotation_policies.unrecognized | any(.item == $unknown and .provider == "unregistered-source"))' \
  "$OUT_FILE" >/dev/null || fail 'repeated upgrade changed its plan or lost the unknown-provider diagnostic'
cmp "$ROOT/assertions/repeat/before.vault.json" "$SKARBIEC_VAULT_FILE" || fail 'repeated upgrade rewrote the vault'

# Exercise the actual scheduled consumer, not just its declaration.
run rotation ok rotation run --item "$KEY" --now
jq -e --arg key "$KEY" '(.ran | map(.item)) == [$key] and (.ran | all(.status == "rotated"))' "$OUT_FILE" >/dev/null \
  || fail 'the migrated policy did not complete its actual SSH rotation'
run after-key ok get "$KEY" --field public_key
[ "$(cat "$OUT_FILE")" != "$BEFORE_KEY" ] || fail 'the consumer left the original public key in place'
run final-policy ok rotation list
jq -e --arg key "$KEY" \
  '.policies | any(.item == $key and .with == "ssh" and .last_status == "rotated" and .due == false)' \
  "$OUT_FILE" >/dev/null || fail 'the rotated policy did not retain canonical and completed state'
COMPLETED=yes
