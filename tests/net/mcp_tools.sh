#!/usr/bin/env bash
# Real test of the MCP tools skarbiec_review and skarbiec_pins, through the
# built binary's `skarbiec mcp` on standard input and output, on a vault of
# its own: SKARBIEC_VAULT_FILE, SKARBIEC_AUDIT_FILE and GNUPGHOME point into
# this checkout's target directory, so the operator's vault and keyring are
# never read or written.
#
# It pins one note, then asks the server in one session for its tool list,
# for skarbiec_pins, for skarbiec_review held to a moment, and for
# skarbiec_review without its moment; the list names both tools, pins names
# the note, the review answers its sections with the moment, and the call
# without before is answered with an error naming before.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/net/mcp_tools.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/net/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT" "$KEYRING"
chmod go-rwx "$KEYRING"
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
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: output: $out stderr: $said"
}
answer() {
  jq -c --arg id "$1" 'select(.id == $id)' "$ROOT/mcp-out.jsonl"
}

: >"$ROOT/stdin"
WANT=ok run init "mcp-owner-$RUN"
NOTE="mcp-pinned-$RUN"
printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"%s"},"context":{}}' "$NOTE-value" >"$ROOT/stdin"
WANT=ok run set "$NOTE" --type note
: >"$ROOT/stdin"
WANT=ok run pin add "$NOTE"
LOGIN="mcp-login-$RUN"
CAP="$(printf '%s' "$RUN" | wc -c | tr -d ' ')"
RULES="maxlength: $CAP; required: lower; required: digit"
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"me","password":"mcp-secret-%s"},"context":{"domains":["mcp-%s.invalid"]}}' "$RUN" "$RUN" >"$ROOT/stdin"
WANT=ok run set "$LOGIN" --type login
: >"$ROOT/stdin"
WANT=ok run password rules "$LOGIN" --set "$RULES"
mkdir -p "$ROOT/leak"
printf 'PASSWORD=mcp-secret-%s\n' "$RUN" >"$ROOT/leak/settings.env"
KEY="mcp-key-$RUN"
WANT=ok run ssh new "$KEY"
# One day, counted rather than typed.
WANT=ok run rotation set "$KEY" --every-days "$(printf 'd' | wc -c | tr -d ' ')" --with ssh

BEFORE="2999-01-01T00:00:00Z"
{
  printf '{"jsonrpc":"2.0","id":"list","method":"tools/list"}\n'
  printf '{"jsonrpc":"2.0","id":"pins","method":"tools/call","params":{"name":"skarbiec_pins","arguments":{}}}\n'
  printf '{"jsonrpc":"2.0","id":"review","method":"tools/call","params":{"name":"skarbiec_review","arguments":{"before":"%s"}}}\n' "$BEFORE"
  printf '{"jsonrpc":"2.0","id":"bare","method":"tools/call","params":{"name":"skarbiec_review","arguments":{}}}\n'
  printf '{"jsonrpc":"2.0","id":"rules","method":"tools/call","params":{"name":"skarbiec_password_rules","arguments":{"id":"%s"}}}\n' "$LOGIN"
  printf '{"jsonrpc":"2.0","id":"breaches","method":"tools/call","params":{"name":"skarbiec_site_breaches","arguments":{}}}\n'
  printf '{"jsonrpc":"2.0","id":"scan","method":"tools/call","params":{"name":"skarbiec_scan","arguments":{"path":"%s","fields":"password"}}}\n' "$ROOT/leak"
  printf '{"jsonrpc":"2.0","id":"exposure","method":"tools/call","params":{"name":"skarbiec_exposure","arguments":{"id":"%s"}}}\n' "$LOGIN"
  printf '{"jsonrpc":"2.0","id":"rotations","method":"tools/call","params":{"name":"skarbiec_rotations","arguments":{}}}\n'
} >"$ROOT/mcp-in.jsonl"
"$BIN" mcp <"$ROOT/mcp-in.jsonl" >"$ROOT/mcp-out.jsonl"
echo "mcp transcript: $ROOT/mcp-out.jsonl" >>"$REPORT"

answer list | jq -e '[.result.tools[].name] | (index("skarbiec_review") != null) and (index("skarbiec_pins") != null)' >/dev/null \
  || fail "tools/list does not offer skarbiec_review and skarbiec_pins: $(answer list)"
answer pins | jq -r '.result.content[].text' | jq -e --arg id "$NOTE" 'map(.item) | index($id) != null' >/dev/null \
  || fail "skarbiec_pins does not name the pinned note: $(answer pins)"
answer review | jq -r '.result.content[].text' | jq -e --arg before "$BEFORE" '.before == $before and (.sections | has("secret_health"))' >/dev/null \
  || fail "skarbiec_review did not answer its sections held to the moment: $(answer review)"
case "$(answer bare)" in
  *'"error"'*before*) echo "ok: skarbiec_review without before is answered with an error naming before" >>"$REPORT" ;;
  *) fail "skarbiec_review without before was not refused naming before: $(answer bare)" ;;
esac
if grep -q "$NOTE-value" "$ROOT/mcp-out.jsonl"; then fail "an MCP answer carried the note's value"; fi
echo "ok: the MCP server offers and answers skarbiec_pins and skarbiec_review" >>"$REPORT"

answer rules | jq -r '.result.content[].text' | jq -e --arg rules "$RULES" '.password_rules == $rules' >/dev/null \
  || fail "skarbiec_password_rules did not answer the login's rules: $(answer rules)"
# The login's site is a reserved .invalid host no breach names, so it is in
# neither list; the answer still names the list it read.
answer breaches | jq -r '.result.content[].text' | jq -e --arg id "$LOGIN" \
  '([.exposed[].item, .changed_since[].item] | index($id) == null) and (.source | startswith("https://haveibeenpwned.com/"))' >/dev/null \
  || fail "skarbiec_site_breaches did not answer from the breach list: $(answer breaches)"
answer scan | jq -r '.result.content[].text' | jq -e --arg id "$LOGIN" --arg file "$ROOT/leak/settings.env" \
  '.found | any(.item == $id and .file == $file and .line == 1 and .field == "password")' >/dev/null \
  || fail "skarbiec_scan did not name the copy of the login's password: $(answer scan)"
if grep -q "mcp-secret-$RUN" "$ROOT/mcp-out.jsonl"; then fail "an MCP answer carried the login's password"; fi
echo "ok: the MCP server answers skarbiec_password_rules, skarbiec_site_breaches and skarbiec_scan without a password" >>"$REPORT"
answer exposure | jq -r '.result.content[].text' | jq -e '(.keys.count > 0) and (.keys | has("encrypted_to") | not) and (.journal_entries > 0)' >/dev/null \
  || fail "skarbiec_exposure did not count the keys without naming them, or counted no journal entry: $(answer exposure)"
echo "ok: skarbiec_exposure counts the keys without naming them" >>"$REPORT"
answer rotations | jq -r '.result.content[].text' | jq -e --arg key "$KEY" '.policies | any(.item == $key and .with == "ssh" and (.due | not))' >/dev/null \
  || fail "skarbiec_rotations did not list the key's ssh policy: $(answer rotations)"
if grep -q "PRIVATE KEY" "$ROOT/mcp-out.jsonl"; then fail "an MCP answer carried a private key"; fi
echo "ok: skarbiec_rotations lists the policy and what runs it" >>"$REPORT"

# skarbiec_credential_helpers on a home of its own: Cargo asks this vault,
# and credentials.toml still holds a plain-text token beside it.
(
  export HOME="$ROOT/home" CARGO_HOME="$ROOT/home/.cargo" GIT_CONFIG_GLOBAL="$ROOT/home/gitconfig" DOCKER_CONFIG="$ROOT/home/.docker"
  unset TF_CLI_CONFIG_FILE TF_CLI_CONFIG_DIR AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE KUBECONFIG
  mkdir -p "$CARGO_HOME"
  : >"$GIT_CONFIG_GLOBAL"
  printf '[registry]\ntoken = "left-%s"\n' "$RUN" >"$CARGO_HOME/credentials.toml"
  "$BIN" helper setup cargo &>>"$REPORT"
  printf '{"jsonrpc":"2.0","id":"helpers","method":"tools/call","params":{"name":"skarbiec_credential_helpers","arguments":{}}}\n' \
    | "$BIN" mcp >"$ROOT/mcp-helpers.jsonl"
)
jq -r 'select(.id == "helpers") | .result.content[].text' "$ROOT/mcp-helpers.jsonl" \
  | jq -e '(.helpers.tools[] | select(.tool == "cargo") | .state | .configured and (.registries_in_file | index("crates-io") != null)) and (.helpers_check.status == "fail")' >/dev/null \
  || fail "skarbiec_credential_helpers did not report Cargo asking the vault with a token left in plain text: $(cat "$ROOT/mcp-helpers.jsonl")"
if grep -q "left-$RUN" "$ROOT/mcp-helpers.jsonl"; then fail "skarbiec_credential_helpers carried the plain-text token"; fi
echo "ok: skarbiec_credential_helpers names the plain-text token left beside Cargo's provider, never the token" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
