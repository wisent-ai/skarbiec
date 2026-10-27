#!/usr/bin/env bash
# Real test of the bindings files a host knows of, through the built binary
# on a vault and a home of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE,
# GNUPGHOME and HOME point into this checkout's target directory, so the
# operator's vault, keyring and files are never read or written.
#
# env import --bindings remembers the file it writes; bindings remember adds
# another; bindings list names both as giving every value; rename rebinds
# each line naming the old id in both files and answers them under
# bindings_files; exec --env-from still gives the program its value; a
# trashed item makes doctor's bindings_files check fail naming the line;
# forget drops a file. A file that binds nothing and forgetting a file the
# host does not know are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/bindings/known_bindings.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/bindings/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
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
bindings_check() {
  if doctor=$("$BIN" doctor </dev/null); then echo "doctor: ok" >>"$REPORT"; else echo "doctor: a check failed" >>"$REPORT"; fi
  printf '%s' "$doctor" | jq -r '.checks[] | select(.check == "bindings_files") | "\(.status) \(.detail)"'
}

: >"$ROOT/stdin"
WANT=ok run init "bindings-owner-$RUN"
case "$(bindings_check)" in
  not_configured*) echo "ok: with no known file doctor's bindings_files check is not configured" >>"$REPORT" ;;
  *) fail "bindings_files is not not_configured before any file is known: $(bindings_check)" ;;
esac

VALUE="api-value-$RUN"
printf 'API_TOKEN=%s\n' "$VALUE" >"$ROOT/app.env"
WANT=ok run env import "$ROOT/app.env" --prefix "app-$RUN" --bindings "$ROOT/app.bindings" --yes
ITEM="app-$RUN-api-token"
printf 'DEPLOY_TOKEN=%s:token\n' "$ITEM" >"$ROOT/deploy.bindings"
WANT=ok run bindings remember "$ROOT/deploy.bindings"
[ "$(printf '%s' "$out" | jq -r .added)" = true ] || fail "remember did not add the file: $out"
WANT=ok run bindings remember "$ROOT/deploy.bindings"
[ "$(printf '%s' "$out" | jq -r .added)" = false ] || fail "remembering the same file twice added it again: $out"

WANT=ok run bindings list
printf '%s' "$out" | jq -e --arg app "$ROOT/app.bindings" --arg deploy "$ROOT/deploy.bindings" \
  '.ok and ([.files[].file] | (index($app) != null) and (index($deploy) != null))' >/dev/null \
  || fail "list does not name the env import file and the remembered one as giving every value: $out"
case "$out" in *"$VALUE"*) fail "list printed a value" ;; esac
echo "ok: env import and remember make both files known, and list finds every line giving a value" >>"$REPORT"

RENAMED="api-renamed-$RUN"
WANT=ok run rename "$ITEM" "$RENAMED"
printf '%s' "$out" | jq -e --arg app "$ROOT/app.bindings" --arg deploy "$ROOT/deploy.bindings" \
  '.bindings_files.moved | (index($app) != null) and (index($deploy) != null)' >/dev/null \
  || fail "rename did not rebind both known files: $out"
grep -qxF "API_TOKEN=$RENAMED:token" "$ROOT/app.bindings" || fail "the env import file does not bind the new id"
grep -qxF "DEPLOY_TOKEN=$RENAMED:token" "$ROOT/deploy.bindings" || fail "the remembered file does not bind the new id"
seen="$("$BIN" exec --env-from "$ROOT/deploy.bindings" -- sh -c 'printf "%s" "$DEPLOY_TOKEN"' </dev/null)"
[ "$seen" = "$VALUE" ] || fail "exec --env-from does not give the value after the rename"
case "$(bindings_check)" in
  pass*) echo "ok: rename rebinds every known file, exec still gets the value and doctor passes" >>"$REPORT" ;;
  *) fail "bindings_files does not pass after the rename: $(bindings_check)" ;;
esac

WANT=ok run delete "$RENAMED"
case "$(bindings_check)" in
  fail*DEPLOY_TOKEN*"in the trash"*) echo "ok: doctor names the line whose item is in the trash" >>"$REPORT" ;;
  *) fail "bindings_files does not fail naming the trashed binding: $(bindings_check)" ;;
esac
WANT=ok run restore "$RENAMED"

printf '# nothing bound here\n' >"$ROOT/empty.bindings"
WANT=refused run bindings remember "$ROOT/empty.bindings"
WANT=ok run bindings forget "$ROOT/deploy.bindings"
WANT=ok run bindings list
printf '%s' "$out" | jq -e --arg deploy "$ROOT/deploy.bindings" '[.files[].file] | index($deploy) == null' >/dev/null \
  || fail "forget left the file known: $out"
WANT=refused run bindings forget "$ROOT/deploy.bindings"
case "$out" in *"not a bindings file this host knows of"*) ;; *) fail "forgetting an unknown file was not refused: $out" ;; esac
echo "ok: a file binding nothing and an unknown file to forget are refused; forget drops a file" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
