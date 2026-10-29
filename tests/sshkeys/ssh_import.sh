#!/usr/bin/env bash
# Real test of `skarbiec ssh import`, through the built binary on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault and keyring are
# never read or written; the keys imported are made here with ssh-keygen.
#
# A key file is imported: the item holds exactly the file's private key and
# the public key ssh-keygen derives, the file stays without --remove and is
# gone with it, and no private key is printed. A key under a passphrase is
# refused naming ssh-keygen -p, a file that is not a key is refused, and an
# id that exists is refused before the file is read.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/sshkeys/ssh_import.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/sshkeys/$RUN"
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
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: $said; output: $out" ;;
  esac
}
key() {
  ssh-keygen -q -t ed25519 -N "$2" -C "import-$RUN" -f "$1"
}

: >"$ROOT/stdin"
WANT=ok run init "import-owner-$RUN"

key "$ROOT/kept" ""
WANT=ok run ssh import "$ROOT/kept" "kept-$RUN" --tags "kept-$RUN"
# Neither stream may carry a private key.
case "$out$said" in *"PRIVATE KEY"*) fail "ssh import printed a private key" ;; esac
[ "$(printf '%s' "$out" | jq -r .public_key)" = "$(cat "$ROOT/kept.pub")" ] || fail "the public key printed is not the one the file pairs with"
WANT=ok run get "kept-$RUN" --field private_key
[ "$out" = "$(cat "$ROOT/kept")" ] || fail "the item does not hold the file's private key"
[ -e "$ROOT/kept" ] || fail "the file was removed without --remove"
echo "ok: the key is stored with its derived public key and the file stays" >>"$REPORT"

key "$ROOT/moved" ""
WANT=ok run ssh import "$ROOT/moved" "moved-$RUN" --remove
[ ! -e "$ROOT/moved" ] && [ ! -e "$ROOT/moved.pub" ] || fail "--remove left the key file or its .pub"
WANT=ok run get "moved-$RUN" --field public_key
[ -n "$out" ] || fail "the moved key's item holds no public key"
echo "ok: --remove deletes the file and its .pub once stored" >>"$REPORT"

key "$ROOT/locked" "passphrase-$RUN"
WANT=refused run ssh import "$ROOT/locked" "locked-$RUN"
names "ssh-keygen -p -f $ROOT/locked"
printf 'not a key\n' >"$ROOT/plain"
WANT=refused run ssh import "$ROOT/plain" "plain-$RUN"
names "ssh-keygen could not read $ROOT/plain"
WANT=refused run ssh import "$ROOT/no-such-file" "kept-$RUN"
names "kept-$RUN already exists"
WANT=refused run get "locked-$RUN" --field private_key

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
