#!/usr/bin/env bash
# Real test of Skarbiec's in-process HTTPS through the built binary, with no
# curl on PATH, on a vault of its own (HOME isolated, so the operator's vault,
# journal and keys are never read or written).
#
# It asks the real public services the commands read — Have I Been Pwned's
# range API (breach check), its breach list (breach sites) and the 2FA
# Directory (totp missing) — over Skarbiec's own TLS 1.3 client, trusting
# this host's CA bundle, and checks each answers. Then it checks the
# refusals: a trust bundle holding no root that signs those servers is
# refused naming the untrusted chain, a bundle path that does not exist is
# refused naming SSL_CERT_FILE, and a local server speaking only TLS 1.2
# (openssl s_server) is refused naming TLS 1.3, and the same server stopped
# (it accepts and never answers) ends a scheduled run's exchange by the
# schedule's next firing, refused naming the routine and its period. Every
# command and answer goes to report.txt.
#
# Usage: SKARBIEC=<binary under test> tests/net/https_in_process.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test}
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/https/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT/home" "$ROOT/no-curl"
chmod go-rwx "$ROOT"
echo "revision: ${SKARBIEC_TEST_SOURCE_REVISION:-$(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')}" >"$REPORT"
echo "binary: $BIN; sha256: $(openssl dgst -sha256 -r "$BIN" | cut -d' ' -f1)" >>"$REPORT"
export HOME="$ROOT/home"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
# Every program the binary may start, but curl: the commands under test must
# start none.
for program in jq git ssh ssh-keygen; do
  found=$(command -v "$program" || true)
  [ -z "$found" ] || ln -s "$found" "$ROOT/no-curl/$program"
done
SERVER=
trap '[ -z "$SERVER" ] || kill "$SERVER" 2>/dev/null || true' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
run() {
  if out=$(PATH="$ROOT/no-curl" "$BIN" "$@" <"$ROOT/stdin" 2>"$ROOT/said"); then got=ok; else got=refused; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec %s\nresult: %s\noutput: %s\nstderr: %s\n\n' "$*" "$got" "$out" "$said" >>"$REPORT"
  [ "$got" = "$WANT" ] || fail "skarbiec $* was $got, expected $WANT: $out $said"
}
says() {
  case "$said$out" in *"$1"*) echo "ok: $2" >>"$REPORT" ;; *) fail "$2: expected '$1' in: $said $out" ;; esac
}

: >"$ROOT/stdin"
WANT=ok run init "https-owner-$RUN"
# A password every breach corpus holds, so the range API names it.
printf '{"schema":"skarbiec.item.v2","kind":"login","fields":{"username":"u","password":"password"},"context":{"domains":["example.com"]}}' >"$ROOT/stdin"
WANT=ok run set weak --type login
: >"$ROOT/stdin"

WANT=ok run breach check weak
printf '%s' "$out" | jq -e '.checked == true and .pwned == true and (.seen_count | tonumber) > 0' >/dev/null \
  || fail "breach check did not read the range API over HTTPS: $out"
echo "ok: breach check reads Have I Been Pwned's range API in process" >>"$REPORT"
WANT=ok run breach sites
printf '%s' "$out" | jq -e '.source | startswith("https://haveibeenpwned.com/")' >/dev/null \
  || fail "breach sites did not read the breach list: $out"
echo "ok: breach sites reads the breach list in process" >>"$REPORT"
WANT=ok run totp missing
echo "ok: totp missing reads the 2FA Directory in process" >>"$REPORT"

# A bundle holding only a root that signs none of those servers.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$ROOT/other.key" \
  -subj "/CN=https test root $RUN" -days 1 -out "$ROOT/other-root.pem" 2>/dev/null
SSL_CERT_FILE="$ROOT/other-root.pem" WANT=refused run breach sites
says "neither one of the 1 trusted roots" "a chain no trusted root signs is refused naming that"
SSL_CERT_FILE="$ROOT/absent.pem" WANT=refused run breach sites
says "SSL_CERT_FILE" "a trust bundle that does not exist is refused naming SSL_CERT_FILE"

# A server that speaks only TLS 1.2, behind the alert webhook (https only).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$ROOT/tls12.key" \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" -days 1 -out "$ROOT/tls12.pem" 2>/dev/null
# Any free loopback port: s_server prints the address it bound.
mkfifo "$ROOT/s_server.out"
openssl s_server -tls1_2 -www -cert "$ROOT/tls12.pem" -key "$ROOT/tls12.key" -accept "127.0.0.1:0" \
  >"$ROOT/s_server.out" 2>&1 </dev/null &
SERVER=$!
PORT=
while read -r line; do
  case "$line" in ACCEPT*) PORT=${line##*:}; break ;; esac
done <"$ROOT/s_server.out"
cat "$ROOT/s_server.out" >/dev/null &
[ -n "$PORT" ] || fail "openssl s_server ended before it listened"
printf '{"schema":"skarbiec.item.v2","kind":"note","fields":{"value":"https://localhost:%s/hook"},"context":{}}' "$PORT" >"$ROOT/stdin"
WANT=ok run set hook --type note
: >"$ROOT/stdin"
WANT=ok run alert set hook --field value
SSL_CERT_FILE="$ROOT/tls12.pem" WANT=refused run alert test
says "TLS 1.2 or older; this client speaks TLS 1.3 only" "a server speaking only TLS 1.2 is refused naming TLS 1.3"
case "$said$out" in *"localhost:$PORT/hook"*) fail "the refusal printed the webhook address" ;; esac
echo "ok: the refusal names the item, never the webhook address" >>"$REPORT"

# A server that accepts and never answers: the TLS 1.2 server, stopped. Its
# kernel still completes the connection from the listen backlog, and nothing
# is ever sent back. A run a Stado schedule started ends by that schedule's
# next firing, refused naming it; without one the command would wait.
kill -STOP "$SERVER"
LATER=$(($(date +%s) + 3))
DUE=$(date -u -r "$LATER" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$LATER" +%Y-%m-%dT%H:%M:%SZ)
START=$(date +%s)
STADO_SCHEDULE_ID="maintain-$RUN" STADO_SCHEDULE_CRON='* * * * *' STADO_SCHEDULE_NEXT_DUE_AT="$DUE" \
  SSL_CERT_FILE="$ROOT/tls12.pem" WANT=refused run alert test
TOOK=$(($(date +%s) - START))
says "deadline from routine maintain-$RUN period * * * * *" "an exchange with a silent server is refused naming the routine's period"
[ "$TOOK" -le 30 ] || fail "the refusal came $TOOK s after the start, long past the schedule's next firing at $DUE"
echo "ok: a silent server ends the scheduled exchange at the next firing ($TOOK s)" >>"$REPORT"
STADO_SCHEDULE_ID="maintain-$RUN" STADO_SCHEDULE_CRON='* * * * *' \
  SSL_CERT_FILE="$ROOT/tls12.pem" WANT=refused run alert test
says "STADO_SCHEDULE_NEXT_DUE_AT" "a scheduled run with no next firing is refused naming the variable"
kill -CONT "$SERVER"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
