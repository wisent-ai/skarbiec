#!/usr/bin/env bash
# Real test of the cutover from GnuPG to Skarbiec's own cryptography, through
# the built binary on a vault of its own under this checkout's target
# directory, so the operator's vault, keys and GnuPG home are never read or
# written.
#
# The fixture is a vault as the gpg-era product wrote it: SKARBIEC_LEGACY, a
# released Skarbiec that ran gpg (its write and recipient verbs are `set` and
# `recipient add`, or `set-json` and `add-user` before 0.4.16, read from its
# own help), makes the vault, an owner and recovery key,
# two items (one written twice, so it keeps a saved version) and a member
# whose key is protected by a passphrase, shared one item; every ciphertext
# is gpg's OpenPGP. gpg runs only there, in a GnuPG home of its own under the
# short root ~/.skarbiec/test-runs (gpg-agent's socket path is short), and
# for nothing else. The binary under test then runs with a PATH that holds no
# gpg and must:
#   - refuse a read before the keys are here, naming the key file and
#     `keys import`;
#   - refuse `keys import` of a protected key without an unlock phrase,
#     naming SKARBIEC_UNLOCK_FILE, and with the wrong one, writing nothing;
#   - import every key with the right one, into an owner-only key file whose
#     secret halves are sealed, beside the vault;
#   - refuse reads with no unlock phrase, the wrong one, an unlock file other
#     accounts could read, and a key file other accounts could read, each
#     naming the fix;
#   - read the gpg-written items (current and saved versions) and write a new
#     one in the sealed format;
#   - refuse an item no key here opens (another key file), and a damaged
#     sealed and a damaged OpenPGP item;
#   - refuse `reseal --apply` while the key file lacks a key items are sealed
#     to, leaving the vault byte for byte as it was;
#   - reseal every OpenPGP ciphertext with a kept copy, prove every one opens,
#     and still read every value, the member its shared item with its own key
#     alone and not the owner's;
#   - refuse a second `reseal --apply` while a run is recorded unproven,
#     naming the copy, and clear it with `reseal --verify`;
#   - never carry the key file with the vault: `backup`, `export`, the Git
#     mirror and a replica `pull` each leave no key file at the destination.
# Every command, its exit and its output go to the run's report.txt.
#
# Usage: SKARBIEC=<binary under test> SKARBIEC_LEGACY=<gpg-era release binary>
#        tests/keys/gpg_free.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test}
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
LEGACY=${SKARBIEC_LEGACY:?set SKARBIEC_LEGACY to a released gpg-era skarbiec, which writes the fixture vault}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/keys/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT/no-gpg" "$ROOT/backups" "$ROOT/replica"
chmod go-rwx "$ROOT"
mkdir -p "$HOME/.skarbiec/test-runs"
GHOME=$(mktemp -d "$HOME/.skarbiec/test-runs/k.XXXXXX")
chmod go-rwx "$GHOME"
SERVE=
cleanup() {
  [ -z "$SERVE" ] || kill "$SERVE" 2>/dev/null || true
  gpgconf --homedir "$GHOME" --kill all || true
  rm -rf "$GHOME"
}
trap cleanup EXIT
# A checkout states its revision; a delivered copy states it with
# SKARBIEC_TEST_SOURCE_REVISION.
echo "revision: ${SKARBIEC_TEST_SOURCE_REVISION:-$(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')}" >"$REPORT"
echo "binary: $BIN; sha256: $(openssl dgst -sha256 -r "$BIN" | cut -d' ' -f1)" >>"$REPORT"
echo "legacy: $LEGACY; $("$LEGACY" version | jq -c .)" >>"$REPORT"
if "$LEGACY" help | jq -e '.commands | index("set-json")' >/dev/null; then
  LEGACY_SET=set-json LEGACY_ADD=add-user
else
  LEGACY_SET=set LEGACY_ADD="recipient add"
fi
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export SKARBIEC_SYNC_DIR="$ROOT/sync"
KEYS="$ROOT/vault.keys.json"
# What the binary under test may run: the tools the mirror needs, and no gpg.
for tool in git; do ln -s "$(command -v "$tool")" "$ROOT/no-gpg/$tool"; done

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
# One command of the binary under test with $ROOT/stdin as its input; WANT
# says whether it had to succeed (ok) or be refused (refused).
run() {
  if out=$(PATH="$ROOT/no-gpg" "$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
says() {
  case "$said" in
    *"$1"*) echo "ok: $2" >>"$REPORT" ;;
    *) fail "$2: expected '$1' in: $said" ;;
  esac
}
legacy() {
  GNUPGHOME="$GHOME" "$LEGACY" "$@" <"$ROOT/stdin" >>"$REPORT" 2>&1 || fail "the legacy binary refused: $*"
}
item() {
  printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"%s","password":"%s"},"context":{}}' "$1" "$2" >"$ROOT/stdin"
}
password() {
  WANT=ok run get "$1" --field password "${@:3}"
  [ "$out" = "$2" ] || fail "$1 read back as '$out', not '$2'"
  echo "ok: $1 reads back" >>"$REPORT"
}

# --- the gpg-era fixture ---------------------------------------------------
OWNER="cutover-owner-$RUN"
MEMBER="cutover-member-$RUN"
PHRASE="member phrase $RUN"
: >"$ROOT/stdin"
legacy init "$OWNER"
item first-user "first-$RUN"; legacy $LEGACY_SET login-a --type login
item first-user "second-$RUN"; legacy $LEGACY_SET login-a --type login
item note-user "note-$RUN"; legacy $LEGACY_SET login-b --type login
gpg --homedir "$GHOME" --batch --pinentry-mode loopback --passphrase "$PHRASE" \
  --quick-generate-key "$MEMBER" default default never >>"$REPORT" 2>&1 || fail "gpg did not make the member key"
: >"$ROOT/stdin"
legacy $LEGACY_ADD "$MEMBER"
legacy share login-b "$MEMBER"
jq -e '[.items[] | .current.ciphertext, (.history[]?.ciphertext) | startswith("-----BEGIN PGP MESSAGE-----")] | all' \
  "$SKARBIEC_VAULT_FILE" >/dev/null || fail "the fixture vault holds a ciphertext gpg did not write"
OWNER_FPR=$(jq -r --arg o "$OWNER" '.recipients[$o].fingerprint' "$SKARBIEC_VAULT_FILE")
MEMBER_FPR=$(jq -r --arg m "$MEMBER" '.recipients[$m].fingerprint' "$SKARBIEC_VAULT_FILE")
OLD_STAMP=$(jq -r '.items["login-a"].history[0].created_at' "$SKARBIEC_VAULT_FILE")
echo "fixture: owner $OWNER_FPR, member $MEMBER_FPR, saved version $OLD_STAMP" >>"$REPORT"

# --- before the keys are here ------------------------------------------------
: >"$ROOT/stdin"
WANT=refused run get login-a --field password
says "$KEYS" "a read with no key file names the key file"
says "keys import" "a read with no key file names keys import"

WANT=refused run keys import --gnupg-home "$GHOME"
says "SKARBIEC_UNLOCK_FILE" "importing a protected key without a phrase names the unlock file"
[ ! -e "$KEYS" ] || fail "a refused import wrote $KEYS"
SKARBIEC_UNLOCK="not the phrase" WANT=refused run keys import --gnupg-home "$GHOME"
says "does not open" "importing a protected key with the wrong phrase says it does not open"
[ ! -e "$KEYS" ] || fail "a refused import wrote $KEYS"

SKARBIEC_UNLOCK="$PHRASE" WANT=ok run keys import --gnupg-home "$GHOME"
[ "$(printf '%s' "$out" | jq '.keys | length')" = 3 ] || fail "keys import did not bring the owner, recovery and member keys: $out"
[ -n "$(find "$KEYS" -perm 600)" ] || fail "the key file is not mode 0600: $(ls -l "$KEYS")"
jq -e '[.keys[].secret.sealed] | all' "$KEYS" >/dev/null || fail "a secret half was written unsealed under a configured phrase"
echo "ok: keys import wrote an owner-only key file with sealed secret halves" >>"$REPORT"

# --- unlock and key file refusals --------------------------------------------
WANT=refused run get login-a --field password
says "no unlock phrase is configured" "a sealed key with no phrase is refused naming the setting"
SKARBIEC_UNLOCK="not the phrase" WANT=refused run get login-a --field password
says "does not open the secret half" "a sealed key with the wrong phrase is refused"
printf '%s\n' "$PHRASE" >"$ROOT/unlock"
chmod 644 "$ROOT/unlock"
export SKARBIEC_UNLOCK_FILE="$ROOT/unlock"
WANT=refused run get login-a --field password
says "must be mode 0600" "an unlock file other accounts can read is refused"
chmod 600 "$ROOT/unlock"
chmod 644 "$KEYS"
WANT=refused run get login-a --field password
says "chmod 600 $KEYS" "a key file other accounts can read is refused naming the fix"
chmod 600 "$KEYS"

# --- reading what gpg wrote, writing the new format --------------------------
password login-a "second-$RUN"
password login-a "first-$RUN" --at "$OLD_STAMP"
password login-b "note-$RUN"
WANT=ok run readers login-a
[ "$(printf '%s' "$out" | jq -r .format)" = openpgp ] || fail "readers did not name the OpenPGP format: $out"
item new-user "new-$RUN"
WANT=ok run set login-c --type login
: >"$ROOT/stdin"
jq -e '.items["login-c"].current.ciphertext | startswith("-----BEGIN SKARBIEC SEALED-----")' "$SKARBIEC_VAULT_FILE" >/dev/null \
  || fail "a new item was not written in the sealed format"
password login-c "new-$RUN"

# --- items no key here opens -------------------------------------------------
SKARBIEC_KEYS_FILE="$ROOT/other.keys.json" WANT=ok run owner key mint "stranger-$RUN"
SKARBIEC_KEYS_FILE="$ROOT/other.keys.json" WANT=refused run get login-c --field password
says "no key held here is a recipient" "a sealed item no key here opens is refused"
SKARBIEC_KEYS_FILE="$ROOT/other.keys.json" WANT=refused run get login-a --field password
says "no secret key held here opens this message" "an OpenPGP item no key here opens is refused"
cp "$SKARBIEC_VAULT_FILE" "$ROOT/intact.vault.json"
for id in login-c login-a; do
  jq --arg id "$id" '.items[$id].current.ciphertext |= (.[0:120] + (if .[120:121] == "A" then "B" else "A" end) + .[121:])' \
    "$ROOT/intact.vault.json" >"$ROOT/damaged.vault.json"
  chmod 600 "$ROOT/damaged.vault.json"
  SKARBIEC_VAULT_FILE="$ROOT/damaged.vault.json" WANT=refused run get "$id" --field password
  says "changed" "a damaged $id is refused as changed"
done

# --- reseal --------------------------------------------------------------------
WANT=ok run reseal
LEGACY_COUNT=$(jq '[.items[] | .current.ciphertext, (.history[]?.ciphertext) | select(startswith("-----BEGIN PGP MESSAGE-----"))] | length' "$SKARBIEC_VAULT_FILE")
[ "$(printf '%s' "$out" | jq .openpgp_ciphertexts)" = "$LEGACY_COUNT" ] \
  || fail "reseal did not count the $LEGACY_COUNT OpenPGP ciphertexts the vault holds: $out"
SKARBIEC_UNLOCK="$PHRASE" SKARBIEC_KEYS_FILE="$ROOT/owner-only.keys.json" WANT=ok run keys import --gnupg-home "$GHOME" --keys "$OWNER_FPR"
SKARBIEC_KEYS_FILE="$ROOT/owner-only.keys.json" WANT=refused run reseal --apply
says "$MEMBER_FPR" "reseal names the key the key file lacks"
cmp "$ROOT/intact.vault.json" "$SKARBIEC_VAULT_FILE" || fail "a refused reseal changed the vault"
WANT=ok run reseal --apply
printf '%s' "$out" | jq -e '.proven == true' >/dev/null || fail "reseal did not prove every ciphertext opens: $out"
BACKUP=$(printf '%s' "$out" | jq -r .backup)
cmp "$ROOT/intact.vault.json" "$BACKUP" || fail "the copy kept before resealing is not the vault as it was"
jq -e '[.items[] | .current.ciphertext, (.history[]?.ciphertext) | startswith("-----BEGIN SKARBIEC SEALED-----")] | all' \
  "$SKARBIEC_VAULT_FILE" >/dev/null || fail "an OpenPGP ciphertext is left after reseal"
password login-a "second-$RUN"
password login-a "first-$RUN" --at "$OLD_STAMP"
password login-b "note-$RUN"
password login-c "new-$RUN"
SKARBIEC_UNLOCK="$PHRASE" SKARBIEC_KEYS_FILE="$ROOT/member.keys.json" WANT=ok run keys import --gnupg-home "$GHOME" --keys "$MEMBER_FPR"
SKARBIEC_KEYS_FILE="$ROOT/member.keys.json" WANT=ok run get login-b --field password
[ "$out" = "note-$RUN" ] || fail "the member could not read its shared item after reseal"
SKARBIEC_KEYS_FILE="$ROOT/member.keys.json" WANT=refused run get login-a --field password
says "no key held here is a recipient" "the member still cannot read what was not shared"

jq --arg b "$BACKUP" '.reseal = {"started_at": "an interrupted run", "backup": $b, "resealed": 3}' \
  "$SKARBIEC_VAULT_FILE" >"$ROOT/interrupted.json"
chmod 600 "$ROOT/interrupted.json"
mv "$ROOT/interrupted.json" "$SKARBIEC_VAULT_FILE"
WANT=refused run reseal --apply
says "$BACKUP" "a second reseal over an unproven run names the kept copy"
says "reseal --verify" "a second reseal over an unproven run names --verify"
WANT=ok run reseal --verify
jq -e 'has("reseal") | not' "$SKARBIEC_VAULT_FILE" >/dev/null || fail "reseal --verify left the run recorded"

# --- the key file never travels with the vault --------------------------------
no_keys_in() {
  if find "$1" -name '*keys*' | grep -q .; then fail "$2 carried a key file: $(find "$1" -name '*keys*')"; fi
  echo "ok: $2 carries no key file" >>"$REPORT"
}
WANT=ok run backup "$ROOT/backups"
no_keys_in "$ROOT/backups" "backup"
mkdir "$ROOT/exports"
(cd "$ROOT/exports" && WANT=ok run export plain.json && WANT=ok run export sealed.json --encrypt-to "$OWNER")
no_keys_in "$ROOT/exports" "export"
git init --bare --initial-branch=main "$ROOT/remote.git" >>"$REPORT"
WANT=ok run mirror init "$ROOT/remote.git"
WANT=ok run mirror push
no_keys_in "$SKARBIEC_SYNC_DIR" "the Git mirror"
git clone -q "$ROOT/remote.git" "$ROOT/remote-clone"
no_keys_in "$ROOT/remote-clone" "the mirror's remote"
printf 'pull-token-%s\n' "$RUN" >"$ROOT/pull.token"
chmod 600 "$ROOT/pull.token"
WANT=ok run grant issue replica --capabilities sync:pull --token-file "$ROOT/pull.token" --until-revoked
PATH="$ROOT/no-gpg" "$BIN" serve --port 0 >"$ROOT/serve.log" 2>&1 &
SERVE=$!
for _ in $(seq 1 100); do
  ADDRESS=$(sed -n 's/.*listening on \(http:[^ ]*\).*/\1/p' "$ROOT/serve.log")
  [ -z "$ADDRESS" ] || break
  sleep 0.1
done
[ -n "$ADDRESS" ] || fail "serve did not listen: $(cat "$ROOT/serve.log")"
SKARBIEC_VAULT_FILE="$ROOT/replica/vault.json" WANT=ok run pull --from "$ADDRESS" --token-file "$ROOT/pull.token"
no_keys_in "$ROOT/replica" "a replica pull"
kill "$SERVE"
SERVE=

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
