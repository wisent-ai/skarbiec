#!/usr/bin/env bash
# Real test of `skarbiec tool` with the huggingface adapter, through the built binary on a vault
# and a Hugging Face home of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, GNUPGHOME, HOME and HF_HOME point into this checkout's
# target directory, so the operator's vault, keyring and Hugging Face sign-in
# are never read or written.
#
# A token file holding the active token, and stored_tokens holding it under
# one name and another token under a second: status names all three as
# plain text, never a token; import of the active token moves it into a
# token item, binds HF_TOKEN, deletes the token file and the stored section
# holding it, and keeps the other section; doctor's developer_tokens check
# then names only the other stored token. Imports consume the backend's
# required Boolean selection decision, not its human command suggestion.
# No active token, an unknown stored name and a clashing binding refuse
# without changing the source files or vault. This is local migration
# qualification, not proof of a Hugging Face sign-in.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/huggingface/hf_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/huggingface/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home" "$ROOT/hf" "$KEYRING"
chmod go-rwx "$KEYRING"
git rev-parse HEAD >"$ROOT/source-revision.txt"
tar -cf "$ROOT/source.tar" Cargo.toml Cargo.lock src tests/huggingface/hf_credential.sh
openssl dgst -sha256 "$BIN" "$ROOT/source.tar" >"$ROOT/digests.txt"
printf 'revision: %s\nbinary: %s\nsource and artifact digests: %s\n' \
  "$(cat "$ROOT/source-revision.txt")" "$BIN" "$ROOT/digests.txt" >"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
export HF_HOME="$ROOT/hf"
TOKEN_FILE="$HF_HOME/token"
STORED="$HF_HOME/stored_tokens"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then code=$?; got=ok; else code=$?; got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nexit: %s\nresult: %s\n\n' "$*" "$code" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
tokens_check() {
  if doctor=$("$BIN" doctor </dev/null); then echo "doctor: ok" >>"$REPORT"; else echo "doctor: a check failed" >>"$REPORT"; fi
  printf '%s' "$doctor" | jq -r '.checks[] | select(.check == "developer_tokens") | "\(.status) \(.detail)"'
}
import_entry() {
  local tool="$1" item="$2" entry="$3" bindings="$4" selected
  local selection=()
  WANT=ok run tool status "$tool"
  printf '%s\n' "$out" >"$ROOT/status-$entry.json"
  selected="$(printf '%s' "$out" | jq -er --arg entry "$entry" \
    '.entries[] | select(.entry == $entry) | .requires_select | if type == "boolean" then tostring else error("missing Boolean requires_select") end')" \
    || fail "status omitted its selection decision for $tool/$entry"
  case "$selected" in
    true) selection=(--select "$entry") ;;
    false) ;;
    *) fail "status gave an invalid selection decision for $tool/$entry: $selected" ;;
  esac
  WANT=ok run tool import "$tool" "$item" "${selection[@]}" --bindings "$bindings"
}

: >"$ROOT/stdin"
WANT=ok run init "hf-owner-$RUN"
READ="hf_read_$RUN"
WRITE="hf_write_$RUN"
printf '%s' "$READ" >"$TOKEN_FILE"
cat >"$STORED" <<EOF
[read]
hf_token = $READ

[write]
hf_token = $WRITE
EOF
BINDINGS="$ROOT/bindings"

WANT=ok run tool status huggingface
printf '%s' "$out" | jq -e '[.entries[] | select(.kept == "plain text") | .entry] | (index("active") != null) and (index("read") != null) and (index("write") != null)' >/dev/null \
  || fail "status did not name the active and both stored tokens: $out"
# A token must appear on neither stream.
case "$out$said" in *"$READ"*|*"$WRITE"*) fail "status printed a token" ;; esac
echo "ok: status names the active and both stored tokens, never a token" >>"$REPORT"

ITEM="hf-$RUN"
import_entry huggingface "$ITEM" active "$BINDINGS"
case "$out$said" in *"$READ"*) fail "import printed the token" ;; esac
[ ! -e "$TOKEN_FILE" ] || fail "the active token file is still there"
if grep -q "$READ" "$STORED"; then fail "stored_tokens still holds the moved token"; fi
grep -qxF "[write]" "$STORED" || fail "import removed the other stored token's section"
grep -qF "hf_token = $WRITE" "$STORED" || fail "import removed the other stored token"
grep -qxF "HF_TOKEN=$ITEM:token" "$BINDINGS" || fail "the bindings file does not bind HF_TOKEN"
WANT=ok run get "$ITEM" --field token
[ "$out" = "$READ" ] || fail "the item does not hold the moved token"
echo "ok: import moves the active token, binds HF_TOKEN and removes both of its plain copies" >>"$REPORT"

after="$(tokens_check)"
case "$after" in
  *"--select read"*|*"$WRITE"*) fail "doctor names the moved token or prints a token: $after" ;;
  fail*"--select write"*) echo "ok: doctor names only the stored token still in plain text" >>"$REPORT" ;;
  *) fail "doctor's developer_tokens check does not name the stored token left: $after" ;;
esac


cp "$STORED" "$ROOT/stored-before-refusals"
cp "$SKARBIEC_VAULT_FILE" "$ROOT/vault-before-refusals"
WANT=refused run tool import huggingface "none-$RUN" --bindings "$BINDINGS"
WANT=refused run tool import huggingface "missing-$RUN" --select "nowhere-$RUN" --bindings "$BINDINGS"
WANT=refused run tool import huggingface "clash-$RUN" --select write --bindings "$BINDINGS"
cmp -s "$STORED" "$ROOT/stored-before-refusals" || fail "a refused import changed stored_tokens"
cmp -s "$SKARBIEC_VAULT_FILE" "$ROOT/vault-before-refusals" || fail "a refused import changed the vault"
echo "ok: no active token, an unknown name and a clashing binding are refused, the files unchanged" >>"$REPORT"

import_entry huggingface "hf-write-$RUN" write "$ROOT/write-bindings"
WANT=ok run get "hf-write-$RUN" --field token
[ "$out" = "$WRITE" ] || fail "the selected named entry was not retained in its actual vault item"
if grep -q "$WRITE" "$STORED"; then fail "stored_tokens still holds the write token"; fi
case "$(tokens_check)" in
  not_configured*) echo "ok: with every token moved doctor finds no Hugging Face token in plain text" >>"$REPORT" ;;
  *) fail "doctor's developer_tokens check is not not_configured once every token moved: $(tokens_check)" ;;
esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
