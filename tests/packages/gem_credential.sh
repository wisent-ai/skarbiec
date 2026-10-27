#!/usr/bin/env bash
# Real test of `skarbiec tool` with the gem adapter, through the built binary on a vault
# and a home of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE, GNUPGHOME
# and HOME point into this checkout's target directory, so the operator's
# vault, keyring and gem credentials are never read or written.
#
# A ~/.gem/credentials holding rubygems.org's key and a gem server's key:
# status names both as plain text, never a key; import moves rubygems.org's
# key into a token item, binds GEM_HOST_API_KEY and removes its line,
# keeping the other; exec --env-from gives a program GEM_HOST_API_KEY. A key
# the file does not hold and a variable the bindings file binds elsewhere
# are refused with the file unchanged.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/packages/gem_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/packages/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home/.gem" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
CREDENTIALS="$HOME/.gem/credentials"
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

: >"$ROOT/stdin"
WANT=ok run init "gem-owner-$RUN"
PUBLIC="rubygems_public_$RUN"
SERVER="gems_server_$RUN"
cat >"$CREDENTIALS" <<EOF
---
:rubygems_api_key: $PUBLIC
https://gems.example.com: $SERVER
EOF
chmod go-rwx "$CREDENTIALS"
BINDINGS="$ROOT/bindings"

WANT=ok run tool status gem
printf '%s' "$out" | jq -e '[.entries[] | select(.kept == "plain text") | .entry] | (index("rubygems_api_key") != null) and (index("https://gems.example.com") != null)' >/dev/null \
  || fail "status did not name both keys as plain text: $out"
case "$out" in *"$PUBLIC"*|*"$SERVER"*) fail "status printed a key" ;; esac
echo "ok: status names both keys, never a value" >>"$REPORT"

# doctor exits non-zero while any check fails; its status goes to the report
# and the developer_tokens check is read either way.
tokens_check() {
  if doctor=$("$BIN" doctor </dev/null); then echo "doctor: ok" >>"$REPORT"; else echo "doctor: a check failed" >>"$REPORT"; fi
  printf '%s' "$doctor" | jq -r '.checks[] | select(.check == "developer_tokens") | "\(.status) \(.detail)"'
}
before="$(tokens_check)"
case "$before" in
  fail*"--select rubygems_api_key"*"--select https://gems.example.com"*) ;;
  *) fail "doctor's developer_tokens check does not fail naming both imports: $before" ;;
esac
case "$before" in *"$PUBLIC"*|*"$SERVER"*) fail "doctor printed a key" ;; esac
echo "ok: doctor names each plain-text gem key with its import, never a value" >>"$REPORT"

ITEM="gem-$RUN"
WANT=ok run tool import gem "$ITEM" --select rubygems_api_key --bindings "$BINDINGS"
[ "$(printf '%s' "$out" | jq -r '.variables[]')" = GEM_HOST_API_KEY ] || fail "the key was not bound as GEM_HOST_API_KEY: $out"
case "$out" in *"$PUBLIC"*) fail "import printed the key" ;; esac
if grep -q "$PUBLIC" "$CREDENTIALS"; then fail "the credentials file still holds rubygems.org's key"; fi
grep -qF "https://gems.example.com: $SERVER" "$CREDENTIALS" || fail "import removed the other key"
grep -qxF -- "---" "$CREDENTIALS" || fail "import dropped the document marker"
grep -qxF "GEM_HOST_API_KEY=$ITEM:token" "$BINDINGS" || fail "the bindings file does not bind GEM_HOST_API_KEY"
WANT=ok run get "$ITEM" --field token
[ "$out" = "$PUBLIC" ] || fail "the item does not hold the moved key"
echo "ok: import moves the key, binds GEM_HOST_API_KEY and removes only its line" >>"$REPORT"
after="$(tokens_check)"
case "$after" in
  *"--select rubygems_api_key"*) fail "doctor still names the moved key: $after" ;;
  fail*"--select https://gems.example.com"*) echo "ok: after import doctor names only the key still in plain text" >>"$REPORT" ;;
  *) fail "doctor no longer names the key still in plain text: $after" ;;
esac

seen="$("$BIN" exec --env-from "$BINDINGS" -- sh -c 'printf "%s" "$GEM_HOST_API_KEY"' </dev/null)"
[ "$seen" = "$PUBLIC" ] || fail "exec --env-from did not give the program GEM_HOST_API_KEY"
echo "ok: exec --env-from gives gem push its key" >>"$REPORT"

cp "$CREDENTIALS" "$ROOT/credentials-before-refusals"
WANT=refused run tool import gem "none-$RUN" --select rubygems_api_key --bindings "$BINDINGS"
case "$out" in *"keeps no rubygems_api_key"*"https://gems.example.com"*) ;; *) fail "a key the file does not hold was not refused naming those it does: $out" ;; esac
WANT=refused run tool import gem "clash-$RUN" --select https://gems.example.com --bindings "$BINDINGS"
case "$out" in *"already binds GEM_HOST_API_KEY"*) ;; *) fail "a variable bound elsewhere was not refused: $out" ;; esac
WANT=refused run tool import gem "bare-$RUN" --select rubygems_api_key
cmp -s "$CREDENTIALS" "$ROOT/credentials-before-refusals" || fail "a refused import changed the credentials file"
echo "ok: an unknown key, a clashing binding and a missing --bindings are refused, the file unchanged" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
