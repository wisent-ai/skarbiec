#!/usr/bin/env bash
# Real test of Docker signing in with the vault, `skarbiec helper ... docker`,
# through the built binary run under the program name Docker uses, on a vault
# of its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, DOCKER_CONFIG names a Docker
# configuration directory there, and the helper is linked into a directory
# there, so the operator's vault, keyring and Docker setup are never touched.
#
# setup links docker-credential-skarbiec to the binary and names it for the
# registry in config.json, keeping a member already there; the linked
# program, as Docker runs it, answers get with the login's username and
# token, and the journal holds no value. A registry no login is offered on is
# answered with Docker's not-found sentence and fails. store is refused, and
# unset removes the registry's entry. import moves the sign-in docker login
# left base64-encoded under auths into a new login, names the helper for the
# registry and takes the sign-in out of auths; a registry auths keeps nothing
# for is refused with config.json unchanged.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/exec/docker_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/exec/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/docker" "$ROOT/bin" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export DOCKER_CONFIG="$ROOT/docker"
printf '{"auths":{"kept.example":{}}}' >"$DOCKER_CONFIG/config.json"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$("$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out; stderr: $said"
}

REGISTRY="registry-$RUN.example"
TOKEN="registry-token-$RUN"
: >"$ROOT/stdin"
WANT=ok run init "docker-owner-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"octo-%s","password":"%s"},"context":{"domains":["%s"]}}' "$RUN" "$TOKEN" "$REGISTRY" >"$ROOT/stdin"
WANT=ok run set "registry-$RUN" --type login
: >"$ROOT/stdin"

WANT=ok run helper setup docker "$REGISTRY" --link "$ROOT/bin"
HELPER="$ROOT/bin/docker-credential-skarbiec"
[ "$(readlink "$HELPER")" = "$BIN" ] || fail "the helper is not linked to the binary"
jq -e --arg r "$REGISTRY" '.credHelpers[$r] == "skarbiec" and (.auths | has("kept.example"))' "$DOCKER_CONFIG/config.json" >/dev/null \
  || fail "config.json does not name skarbiec for the registry, or lost a member: $(cat "$DOCKER_CONFIG/config.json")"
echo "ok: setup links the helper and names it for the registry, keeping config.json's other members" >>"$REPORT"

printf '%s' "$REGISTRY" | "$HELPER" get >"$ROOT/answer.json"
jq -e --arg u "octo-$RUN" --arg t "$TOKEN" '.Username == $u and .Secret == $t' "$ROOT/answer.json" >/dev/null \
  || fail "the helper did not answer the login's username and token"
if grep -q "$TOKEN" "$SKARBIEC_AUDIT_FILE"; then fail "the journal holds the token"; fi
echo "ok: the helper, run as Docker runs it, answers from the vault; the journal holds no value" >>"$REPORT"

if out=$(printf 'nothing-%s.example' "$RUN" | "$HELPER" get 2>/dev/null); then fail "a registry without a login was answered"; fi
[ "$out" = "credentials not found in native keychain" ] || fail "a registry without a login was not answered with Docker's not-found sentence: $out"
if printf '{}' | "$HELPER" store 2>/dev/null; then fail "store was not refused"; fi
echo "ok: an unknown registry gets Docker's not-found sentence, and store is refused" >>"$REPORT"

IMPORTED="imported-$RUN.example.com"
jq --arg r "$IMPORTED" --arg a "$(printf 'ci-%s:pushed-%s' "$RUN" "$RUN" | base64)" '.auths[$r] = {auth: $a}' "$DOCKER_CONFIG/config.json" >"$ROOT/config.next"
mv "$ROOT/config.next" "$DOCKER_CONFIG/config.json"
WANT=refused run helper import docker "nothing-$RUN" "absent-$RUN.example.com" --link "$ROOT/bin"
case "$said" in *"keeps no sign-in for absent-$RUN.example.com"*) ;; *) fail "a registry with no sign-in was not refused naming it: $out; stderr: $said" ;; esac
WANT=ok run helper import docker "imported-$RUN" "$IMPORTED" --link "$ROOT/bin"
jq -e --arg r "$IMPORTED" '(.auths | has($r) | not) and .credHelpers[$r] == "skarbiec" and (.auths | has("kept.example"))' "$DOCKER_CONFIG/config.json" >/dev/null \
  || fail "import did not move the sign-in out of auths and name the helper, keeping the rest: $(cat "$DOCKER_CONFIG/config.json")"
printf '%s' "$IMPORTED" | "$HELPER" get >"$ROOT/imported.json"
jq -e --arg u "ci-$RUN" --arg t "pushed-$RUN" '.Username == $u and .Secret == $t' "$ROOT/imported.json" >/dev/null \
  || fail "the imported sign-in is not answered from the vault"
# The password must be in neither stream, so both are searched.
case "$out$said" in *"pushed-$RUN"*) fail "import printed the password" ;; esac
echo "ok: import moves docker login's sign-in into the vault and Docker reads it from there" >>"$REPORT"
WANT=refused run helper unset docker "$REGISTRY" --link "$ROOT/bin"
case "$said" in *"helper unset docker takes no --link"*) ;; *) fail "a flag unset does not take was not refused naming it: $out; stderr: $said" ;; esac
WANT=ok run helper unset docker "$REGISTRY"
jq -e --arg r "$REGISTRY" '.credHelpers | has($r) | not' "$DOCKER_CONFIG/config.json" >/dev/null || fail "unset left the registry's entry"
WANT=refused run helper unset podman "$REGISTRY"
case "$said" in *"podman is not a tool skarbiec answers for"*) ;; *) fail "an unknown tool was not refused naming the tools: $out; stderr: $said" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
