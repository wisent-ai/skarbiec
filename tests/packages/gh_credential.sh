#!/usr/bin/env bash
# Real test of `skarbiec tool` with the gh adapter, through the built binary on a vault
# and a gh configuration directory of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, GNUPGHOME, HOME and GH_CONFIG_DIR point into this
# checkout's target directory, so the operator's vault, keyring and gh
# sign-in are never read or written.
#
# A hosts.yml holding github.com's token at host and user level and an
# enterprise host's token: status names both as plain text, never a token;
# import moves github.com's token into a token item, binds GH_TOKEN and
# removes both of its oauth_token lines, keeping every other line; exec
# --env-from gives a program GH_TOKEN; the enterprise host would bind
# GH_ENTERPRISE_TOKEN. A host hosts.yml does not hold, one keeping no token,
# and a variable the bindings file binds elsewhere are refused with
# hosts.yml unchanged.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/packages/gh_credential.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/packages/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home" "$ROOT/gh" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export HOME="$ROOT/home"
export GH_CONFIG_DIR="$ROOT/gh"
HOSTS="$GH_CONFIG_DIR/hosts.yml"
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
WANT=ok run init "gh-owner-$RUN"
PUBLIC="gho_public_$RUN"
ENTERPRISE="ghe_enterprise_$RUN"
cat >"$HOSTS" <<EOF
github.com:
    users:
        octo-$RUN:
            oauth_token: $PUBLIC
    git_protocol: https
    oauth_token: $PUBLIC
    user: octo-$RUN
git.example.com:
    oauth_token: $ENTERPRISE
    user: octo-$RUN
EOF
BINDINGS="$ROOT/bindings"

WANT=ok run tool status gh
printf '%s' "$out" | jq -e '[.entries[] | select(.kept == "plain text") | .entry] | (index("github.com") != null) and (index("git.example.com") != null)' >/dev/null \
  || fail "status did not name both hosts as plain text: $out"
case "$out" in *"$PUBLIC"*|*"$ENTERPRISE"*) fail "status printed a token" ;; esac
echo "ok: status names both hosts keeping a token, never the token" >>"$REPORT"

ITEM="gh-$RUN"
WANT=ok run tool import gh "$ITEM" --select github.com --bindings "$BINDINGS"
[ "$(printf '%s' "$out" | jq -r '.variables[]')" = GH_TOKEN ] || fail "github.com's token was not bound as GH_TOKEN: $out"
case "$out" in *"$PUBLIC"*) fail "import printed the token" ;; esac
if grep -q "$PUBLIC" "$HOSTS"; then fail "hosts.yml still holds github.com's token"; fi
grep -qF "oauth_token: $ENTERPRISE" "$HOSTS" || fail "import removed the other host's token"
grep -qF "git_protocol: https" "$HOSTS" || fail "import dropped an unrelated line"
grep -qxF "GH_TOKEN=$ITEM:token" "$BINDINGS" || fail "the bindings file does not bind GH_TOKEN"
WANT=ok run get "$ITEM" --field token
[ "$out" = "$PUBLIC" ] || fail "the item does not hold the moved token"
echo "ok: import moves the token, binds GH_TOKEN and removes both of the host's token lines" >>"$REPORT"

seen="$("$BIN" exec --env-from "$BINDINGS" -- sh -c 'printf "%s" "$GH_TOKEN"' </dev/null)"
[ "$seen" = "$PUBLIC" ] || fail "exec --env-from did not give the program GH_TOKEN"
echo "ok: exec --env-from gives gh its token" >>"$REPORT"

cp "$HOSTS" "$ROOT/hosts-before-refusals"
WANT=refused run tool import gh "none-$RUN" --select "nowhere-$RUN.example.com" --bindings "$BINDINGS"
case "$out" in *"keeps no nowhere-$RUN.example.com"*) ;; *) fail "a host hosts.yml does not hold was not refused: $out" ;; esac
WANT=refused run tool import gh "again-$RUN" --select github.com --bindings "$BINDINGS"
case "$out" in *"keeps no token for github.com"*) ;; *) fail "a host keeping no token was not refused: $out" ;; esac
printf 'GH_ENTERPRISE_TOKEN=someone-else:token\n' >>"$BINDINGS"
WANT=refused run tool import gh "clash-$RUN" --select git.example.com --bindings "$BINDINGS"
case "$out" in *"already binds GH_ENTERPRISE_TOKEN"*) ;; *) fail "a variable bound elsewhere was not refused: $out" ;; esac
cmp -s "$HOSTS" "$ROOT/hosts-before-refusals" || fail "a refused import changed hosts.yml"
echo "ok: an unknown host, one without a token and a clashing binding are refused, hosts.yml unchanged" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
