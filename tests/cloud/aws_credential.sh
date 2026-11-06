#!/usr/bin/env bash
# Real test of `skarbiec helper ... aws`, through the built binary on a vault
# of its own and the real AWS CLI (v2): SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, GNUPGHOME, AWS_CONFIG_FILE and
# AWS_SHARED_CREDENTIALS_FILE all point into this checkout's target
# directory, so the operator's vault, keyring and AWS files are never read or
# written. `aws configure export-credentials` runs the profile's
# credential_process exactly as every AWS call does, and prints what it got,
# without asking AWS anything.
#
# After setup the profile's AWS CLI reads the item's key from the vault, and
# a key changed in the vault is the one it reads next; other lines of the
# config file are kept; unset removes only this vault's line. import moves
# the key a profile keeps in the credentials file into a new item, takes it
# out of the file, and the profile then reads it from the vault. A profile
# that still keeps its own key, an item that is not an access key, an id
# that exists, and unset of a profile that runs someone else's process are
# refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/cloud/aws_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
command -v aws >/dev/null || { echo "the AWS CLI v2 must be on PATH: this test runs aws configure export-credentials" >/dev/stderr; false; }
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/cloud/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
aws --version &>>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export AWS_CONFIG_FILE="$ROOT/aws-config"
export AWS_SHARED_CREDENTIALS_FILE="$ROOT/aws-credentials"
unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\n\n' "$*" "$got" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
names() {
  case "$said" in
    *"$*"*) echo "ok: refused naming: $*" >>"$REPORT" ;;
    *) fail "expected a refusal naming '$*', got: output: $out stderr: $said" ;;
  esac
}
key() {
  jq -n --arg id "$1" --arg secret "$2" '{schema:"skarbiec.item.v2",kind:"access-key",fields:{access_key_id:$id,secret_access_key:$secret},context:{}}' >"$ROOT/stdin"
  WANT=ok run set "$ITEM" --type access-key
  : >"$ROOT/stdin"
}
exported() {
  aws configure export-credentials --profile "$PROFILE" --format process 2>>"$REPORT"
}

: >"$ROOT/stdin"
WANT=ok run init "aws-owner-$RUN"
ITEM="aws-$RUN"
PROFILE="vault-$$"
key "AKIAFIRST$$" "first-secret-$$"
printf '[profile other-%s]\nregion = eu-west-1\n' "$$" >"$AWS_CONFIG_FILE"

WANT=ok run helper setup aws "$ITEM" --profile "$PROFILE"
[ "$(exported | jq -r .AccessKeyId)" = "AKIAFIRST$$" ] || fail "the AWS CLI did not read the item's key through credential_process"
grep -q "region = eu-west-1" "$AWS_CONFIG_FILE" || fail "setup lost another profile's line"
key "AKIASECOND$$" "second-secret-$$"
[ "$(exported | jq -r .SecretAccessKey)" = "second-secret-$$" ] || fail "the AWS CLI did not read the key changed in the vault"
WANT=ok run audit list --op aws-credential
case "$out" in *"$ITEM"*) ;; *) fail "the read was not journalled: $out" ;; esac
echo "ok: the profile reads the vault's current key through the AWS CLI itself" >>"$REPORT"

printf '[%s]\naws_access_key_id = AKIASTATIC\naws_secret_access_key = static\n' "kept-$$" >"$AWS_SHARED_CREDENTIALS_FILE"
WANT=refused run helper setup aws "$ITEM" --profile "kept-$$"
names "profile kept-$$ keeps a key in $AWS_SHARED_CREDENTIALS_FILE"
jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{text:"not a key"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
: >"$ROOT/stdin"
WANT=refused run helper setup aws "note-$RUN" --profile "$PROFILE"
names "helper answer aws hands AWS the key an access-key item keeps"
printf '[profile foreign-%s]\ncredential_process = /usr/bin/true\n' "$$" >>"$AWS_CONFIG_FILE"
WANT=refused run helper unset aws --profile "foreign-$$"
names "is not this vault's, so it is left alone"

WANT=ok run helper unset aws --profile "$PROFILE"
if grep -q "helper answer aws $ITEM" "$AWS_CONFIG_FILE"; then fail "unset left this vault's line"; fi
grep -q "credential_process = /usr/bin/true" "$AWS_CONFIG_FILE" || fail "unset removed someone else's line"
echo "ok: unset removes only this vault's line" >>"$REPORT"

printf '[kept-%s]\naws_access_key_id = AKIAKEPT%s\naws_secret_access_key = kept-secret-%s\n' "$$" "$$" "$$" >"$AWS_SHARED_CREDENTIALS_FILE"
WANT=refused run helper import aws "$ITEM" --profile "kept-$$"
names "$ITEM already exists"
grep -q "kept-secret-$$" "$AWS_SHARED_CREDENTIALS_FILE" || fail "a refused import changed the credentials file"
WANT=ok run helper import aws "imported-$RUN" --profile "kept-$$"
if grep -q "kept-secret-$$" "$AWS_SHARED_CREDENTIALS_FILE"; then fail "import left the key in the credentials file"; fi
PROFILE="kept-$$"
[ "$(exported | jq -r .SecretAccessKey)" = "kept-secret-$$" ] || fail "the imported profile does not read its key from the vault"
WANT=ok run get "imported-$RUN" --field access_key_id
[ "$out" = "AKIAKEPT$$" ] || fail "the item does not hold the imported key id"
echo "ok: import moves the profile's key into the vault and the profile reads it there" >>"$REPORT"

WANT=ok run rename "imported-$RUN" "renamed-$RUN"
printf '%s' "$out" | jq -e --arg profile "kept-$$" '.aws_profiles.moved | index($profile) != null' &>/dev/null || fail "rename did not move the profile: $out"
[ "$(exported | jq -r .SecretAccessKey)" = "kept-secret-$$" ] || fail "the profile does not read the renamed item"
grep -q "helper answer aws renamed-$RUN" "$AWS_CONFIG_FILE" || fail "the profile still names the old id"
echo "ok: a rename points the profile at the new id" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
