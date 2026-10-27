#!/usr/bin/env bash
# Real test of the passphrase generator's site-rule options, `skarbiec
# generate --passphrase --words <N> --separator <text> [--capitalize]
# [--with-digit]`, through the built binary. Generating writes nothing, so no
# vault or keyring is touched.
#
# The word count is the number of words in this test's own sentence below, so
# the count it asks for and the count it checks are one value. It checks that a
# plain passphrase has that many lowercase words, that --capitalize starts each
# word upper case, that --with-digit ends the phrase in one digit after the last
# word, and that a missing --separator is refused naming the usage.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/generate/passphrase.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/generate/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

SENTENCE="every word counts here"
WORDS=$(printf '%s\n' $SENTENCE | wc -l | tr -d ' ')
echo "words asked for: $WORDS" >>"$REPORT"

phrase() {
  if ! out=$("$BIN" generate --passphrase --words "$WORDS" --separator - "$@" 2>&1); then
    fail "generate $* was refused: $out"
  fi
  printf '$ skarbiec generate --passphrase --words %s --separator - %s\nresult: ok\n\n' "$WORDS" "$*" >>"$REPORT"
  printf '%s' "$out" | jq -r .passphrase
}

plain=$(phrase)
[ "$(printf '%s' "$plain" | tr '-' '\n' | grep -c .)" = "$WORDS" ] || fail "a plain passphrase did not hold $WORDS words"
printf '%s' "$plain" | grep -Eq '^[a-z]+(-[a-z]+)*$' || fail "a plain passphrase holds more than lowercase words"
echo "ok: a plain passphrase holds $WORDS lowercase words" >>"$REPORT"

capitalized=$(phrase --capitalize)
printf '%s' "$capitalized" | grep -Eq '^[A-Z][a-z]*(-[A-Z][a-z]*)*$' || fail "--capitalize did not start every word upper case"
echo "ok: --capitalize starts every word upper case" >>"$REPORT"

digit=$(phrase --capitalize --with-digit)
printf '%s' "$digit" | grep -Eq '^[A-Z][a-z]*(-[A-Z][a-z]*)*[[:digit:]]$' || fail "--with-digit did not end the phrase in one digit"
echo "ok: --with-digit ends the phrase in one digit after the last word" >>"$REPORT"

if out=$("$BIN" generate --passphrase --words "$WORDS" 2>&1); then
  fail "a passphrase without --separator was generated"
fi
case "$out" in
  *"usage: generate --passphrase"*) echo "ok: a missing --separator is refused naming the usage" >>"$REPORT" ;;
  *) fail "a missing --separator was refused without the usage: $out" ;;
esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
