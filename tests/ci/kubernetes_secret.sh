#!/usr/bin/env bash
# Real test of `skarbiec ci set kubernetes`, through the built binary on a
# vault of its own and a real cluster: SKARBIEC_TEST_KUBE_CONTEXT names the
# kubectl context and SKARBIEC_TEST_KUBE_NAMESPACE a namespace there where
# Secrets may be made and deleted. SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE
# and GNUPGHOME point into this checkout's target directory, so the
# operator's vault and keyring are never read or written; the Secret carries
# this run's id and is deleted at the end.
#
# Without --yes no Secret exists afterwards. With --yes the Secret holds
# both values under their names, as kubectl reads them back, and carries no
# last-applied annotation holding them again; no answer carries a value. A
# place that is not namespace/name is refused.
#
# Usage: SKARBIEC=target/debug/skarbiec SKARBIEC_TEST_KUBE_CONTEXT=kind-test SKARBIEC_TEST_KUBE_NAMESPACE=default tests/ci/kubernetes_secret.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
CONTEXT=${SKARBIEC_TEST_KUBE_CONTEXT:?set SKARBIEC_TEST_KUBE_CONTEXT to a kubectl context of a cluster where this test may make and delete a Secret}
NAMESPACE=${SKARBIEC_TEST_KUBE_NAMESPACE:?set SKARBIEC_TEST_KUBE_NAMESPACE to a namespace of that cluster}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/ci/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "cluster: $CONTEXT, namespace $NAMESPACE" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
SECRET="skarbiec-test-$$"
kube() {
  kubectl --context "$CONTEXT" --namespace "$NAMESPACE" "$@"
}
cleanup() {
  kube delete secret "$SECRET" --ignore-not-found &>>"$REPORT"
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
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: output: $out stderr: $said" ;;
  esac
}
held() {
  kube get secret "$SECRET" -o "jsonpath={.data.$1}" | base64 --decode
}

: >"$ROOT/stdin"
WANT=ok run init "kube-owner-$RUN"
TOKEN="kube-token-$RUN"
PASSWORD="kube-password-$RUN"
jq -n --arg token "$TOKEN" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "kube-token-item-$RUN" --type token
jq -n --arg password "$PASSWORD" '{schema:"skarbiec.item.v2",kind:"login",fields:{username:"app",password:$password},context:{}}' >"$ROOT/stdin"
WANT=ok run set "kube-login-item-$RUN" --type login
: >"$ROOT/stdin"
printf 'API_TOKEN=kube-token-item-%s:token\nDB_PASSWORD=kube-login-item-%s:password\n' "$RUN" "$RUN" >"$ROOT/bindings"

WANT=ok run ci set kubernetes "$NAMESPACE/$SECRET" --env-from "$ROOT/bindings" --context "$CONTEXT"
printf '%s' "$out" | jq -e '.applied == false and (.secrets | length == 2)' >/dev/null || fail "the preview did not name two values unapplied"
if kube get secret "$SECRET" &>>"$REPORT"; then fail "the preview made the Secret"; fi
echo "ok: without --yes no Secret is made" >>"$REPORT"

WANT=ok run ci set kubernetes "$NAMESPACE/$SECRET" --env-from "$ROOT/bindings" --context "$CONTEXT" --yes
# A value must be in neither stream, so both are searched.
case "$out$said" in *"$TOKEN"*|*"$PASSWORD"*) fail "the answer carried a value" ;; esac
[ "$(held API_TOKEN)" = "$TOKEN" ] || fail "the Secret does not hold API_TOKEN as the vault does"
[ "$(held DB_PASSWORD)" = "$PASSWORD" ] || fail "the Secret does not hold DB_PASSWORD as the vault does"
if kube get secret "$SECRET" -o json | jq -e '.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]' >/dev/null; then
  fail "the Secret carries a last-applied annotation holding the values again"
fi
echo "ok: --yes applies one Secret holding every value, with no plain-text annotation" >>"$REPORT"

# Kept: a new revision of the token item is set again by maintain, and
# kept says which item changed before the pass and nothing after it.
PLACE="$NAMESPACE/$SECRET"
WANT=ok run ci keep kubernetes "$PLACE" --env-from "$ROOT/bindings" --context "$CONTEXT"
WANT=ok run ci kept
printf '%s' "$out" | jq -e --arg place "$PLACE" '.kept | any(.place == $place and .changed_since == [])' >/dev/null \
  || fail "kept does not list the kept Secret as up to date"
ROTATED="kube-token-rotated-$RUN"
jq -n --arg token "$ROTATED" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
WANT=ok run set "kube-token-item-$RUN" --type token
: >"$ROOT/stdin"
WANT=ok run ci kept
printf '%s' "$out" | jq -e --arg place "$PLACE" --arg item "kube-token-item-$RUN" '.kept | any(.place == $place and .changed_since == [$item])' >/dev/null \
  || fail "kept does not name the token item as changed"
# doctor exits non-zero while any check fails; its status goes to the report
# and its answer is read either way.
ci_check() {
  if doctor=$("$BIN" doctor </dev/null 2>>"$REPORT"); then echo "doctor: ok" >>"$REPORT"; else echo "doctor: a check failed" >>"$REPORT"; fi
  printf '%s' "$doctor" | jq -r '.checks[] | select(.check == "ci_secrets") | "\(.status) \(.detail)"'
}
case "$(ci_check)" in
  fail*"kube-token-item-$RUN"*) echo "ok: doctor's ci_secrets check fails naming the item the Secret is behind" >>"$REPORT" ;;
  *) fail "doctor's ci_secrets check does not fail naming the changed item: $(ci_check)" ;;
esac
WANT=ok run maintain
[ "$(held API_TOKEN)" = "$ROTATED" ] || fail "maintain did not set the rotated token again"
WANT=ok run ci kept
printf '%s' "$out" | jq -e --arg place "$PLACE" '.kept | any(.place == $place and .changed_since == [])' >/dev/null \
  || fail "kept still names a change maintain has set"
case "$(ci_check)" in
  pass*) echo "ok: doctor's ci_secrets check passes once maintain set the Secret again" >>"$REPORT" ;;
  *) fail "doctor's ci_secrets check does not pass after maintain: $(ci_check)" ;;
esac
echo "ok: a kept Secret is set again by maintain after its item changes" >>"$REPORT"

# A rename rebinds the kept bindings file, so the Secret stays set and doctor
# passes; a trashed item it binds makes doctor name the line.
RENAMED="kube-token-renamed-$RUN"
WANT=ok run rename "kube-token-item-$RUN" "$RENAMED"
printf '%s' "$out" | jq -e --arg file "$ROOT/bindings" '.ci_bindings.moved | index($file) != null' >/dev/null \
  || fail "rename did not rebind the kept bindings file: $out"
grep -qxF "API_TOKEN=$RENAMED:token" "$ROOT/bindings" || fail "the bindings file does not bind API_TOKEN to the new id"
case "$(ci_check)" in
  pass*) echo "ok: after a rename the kept bindings bind the new id and doctor passes" >>"$REPORT" ;;
  *) fail "doctor's ci_secrets check does not pass after a rename: $(ci_check)" ;;
esac
WANT=ok run delete "$RENAMED"
case "$(ci_check)" in
  fail*API_TOKEN*"in the trash"*) echo "ok: doctor names the binding whose item is in the trash" >>"$REPORT" ;;
  *) fail "doctor's ci_secrets check does not name the trashed binding: $(ci_check)" ;;
esac
WANT=ok run restore "$RENAMED"
WANT=ok run ci forget kubernetes "$PLACE"
WANT=ok run ci kept
printf '%s' "$out" | jq -e --arg place "$PLACE" '.kept | all(.place != $place)' >/dev/null || fail "forget left the Secret kept"
WANT=refused run ci forget kubernetes "$PLACE"
names "is not kept here"

WANT=refused run ci set kubernetes "$SECRET" --env-from "$ROOT/bindings"
names "is not <namespace>/<name>"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
