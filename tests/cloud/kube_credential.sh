#!/usr/bin/env bash
# Real test of `skarbiec helper ... kube`, through the built binary on a vault
# of its own and the real kubectl: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE,
# GNUPGHOME and KUBECONFIG all point into this checkout's target directory,
# so the operator's vault, keyring and kubeconfig are never read or written.
#
# setup has kubectl write the user's exec; `kubectl config view` then names
# this binary with `helper answer kube` and the item, and running that exec as
# kubectl runs it — with KUBERNETES_EXEC_INFO set — answers an ExecCredential
# holding the item's token, the one changed in the vault included. unset has
# kubectl remove the exec. import moves a user's bearer token into a new
# item, gives the user the plugin and takes the token out of the kubeconfig.
# An item that is not a token, a user with no token to import and unset of a
# user that runs another plugin are refused.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/cloud/kube_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
command -v kubectl >/dev/null || { echo "kubectl must be on PATH: setup and unset are kubectl config" >/dev/stderr; false; }
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/cloud/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING" "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
kubectl version --client &>>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export KUBECONFIG="$ROOT/kubeconfig"
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
token() {
  jq -n --arg token "$*" '{schema:"skarbiec.item.v2",kind:"token",fields:{token:$token},context:{}}' >"$ROOT/stdin"
  WANT=ok run set "$ITEM" --type token
  : >"$ROOT/stdin"
}
exec_of() {
  kubectl config view --raw -o json | jq -c --arg user "$*" '.users[] | select(.name == $user) | .user.exec'
}
# The user's exec exactly as kubectl reads it, run as kubectl runs it.
plugin() {
  local exec command
  local -a args
  exec="$(exec_of "$USER_NAME")"
  command="$(printf '%s' "$exec" | jq -r .command)"
  read -r -a args <<<"$(printf '%s' "$exec" | jq -r '.args | join(" ")')"
  KUBERNETES_EXEC_INFO='{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"interactive":false}}' \
    "$command" "${args[@]}"
}

: >"$ROOT/stdin"
WANT=ok run init "kube-owner-$RUN"
ITEM="kube-$RUN"
USER_NAME="vault-user-$$"
token "first-token-$$"

WANT=ok run helper setup kube "$ITEM" --user "$USER_NAME"
[ "$(exec_of "$USER_NAME" | jq -r '.args | join(" ")')" = "helper answer kube $ITEM" ] || fail "the user's exec does not run helper answer kube for the item"
[ "$(plugin | jq -r .status.token)" = "first-token-$$" ] || fail "the user's exec does not answer the item's token"
[ "$(plugin | jq -r .kind)" = "ExecCredential" ] || fail "the user's exec does not answer an ExecCredential"
token "second-token-$$"
[ "$(plugin | jq -r .status.token)" = "second-token-$$" ] || fail "the user's exec does not answer the token changed in the vault"
echo "ok: kubectl's user runs this vault's plugin and gets the current token" >>"$REPORT"

kubectl config set-credentials "other-$$" --exec-api-version=client.authentication.k8s.io/v1 --exec-command=/usr/bin/true --exec-interactive-mode=Never &>>"$REPORT"
WANT=refused run helper unset kube --user "other-$$"
names "no kubeconfig user other-$$ runs this vault's helper answer kube"
jq -n '{schema:"skarbiec.item.v2",kind:"note",fields:{text:"not a token"},context:{}}' >"$ROOT/stdin"
WANT=ok run set "note-$RUN" --type note
: >"$ROOT/stdin"
WANT=refused run helper setup kube "note-$RUN" --user "$USER_NAME"
names "helper answer kube hands kubectl the token a token item keeps"

WANT=ok run helper unset kube --user "$USER_NAME"
[ "$(exec_of "$USER_NAME")" = "null" ] || fail "unset left the user's exec"
echo "ok: unset has kubectl remove the exec" >>"$REPORT"

# A test token, typed here only to give the user one to import.
kubectl config set-credentials "kept-$$" --token="kept-token-$$" &>>"$REPORT"
WANT=ok run helper import kube "imported-$RUN" --user "kept-$$"
[ "$(kubectl config view --raw -o json | jq -r --arg user "kept-$$" '.users[] | select(.name == $user) | .user.token')" = "null" ] || fail "import left the token in the kubeconfig"
USER_NAME="kept-$$"
[ "$(plugin | jq -r .status.token)" = "kept-token-$$" ] || fail "the imported user's exec does not answer its token from the vault"
WANT=refused run helper import kube "again-$RUN" --user "kept-$$"
names "kubeconfig user kept-$$ keeps neither a bearer token nor an inline client certificate"
echo "ok: import moves the user's token into the vault and the user reads it there" >>"$REPORT"

# A throwaway client certificate, embedded as kind and minikube embed theirs.
openssl req -x509 -newkey ed25519 -nodes -keyout "$ROOT/client.key" -out "$ROOT/client.crt" -subj "/CN=kube-test-$$" -days "$(printf 'd' | wc -c | tr -d ' ')" &>>"$REPORT"
kubectl config set-credentials "cert-$$" --client-certificate="$ROOT/client.crt" --client-key="$ROOT/client.key" --embed-certs &>>"$REPORT"
rm "$ROOT/client.key"
WANT=ok run helper import kube "cert-$RUN" --user "cert-$$"
[ "$(printf '%s' "$out" | jq -r .kind)" = "certificate" ] || fail "import did not keep the client certificate as a certificate item: $out"
[ "$(kubectl config view --raw -o json | jq -r --arg user "cert-$$" '.users[] | select(.name == $user) | .user["client-key-data"]')" = "null" ] || fail "import left the client key in the kubeconfig"
USER_NAME="cert-$$"
plugin >"$ROOT/cert-credential.json"
jq -e '.status.clientCertificateData | startswith("-----BEGIN CERTIFICATE-----")' "$ROOT/cert-credential.json" >/dev/null || fail "the exec does not answer the client certificate"
jq -e '.status.clientKeyData | contains("PRIVATE KEY")' "$ROOT/cert-credential.json" >/dev/null || fail "the exec does not answer the client key"
rm "$ROOT/cert-credential.json"
echo "ok: import moves an embedded client certificate into a certificate item the user reads" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
