#!/usr/bin/env bash
# Real test of `skarbiec completion`, through the built binary: the script it
# prints is loaded into a bash of its own and asked to complete, as a person
# pressing tab would. The first word must complete to the commands `skarbiec
# help` lists, and a word after `sites` must complete to that command's flags.
# Completing reads no vault, so none is touched.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/cli/completion.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/cli/$RUN"
REPORT="$ROOT/report.txt"
mkdir -p "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}

"$BIN" completion >"$ROOT/completion.bash" || fail "completion was refused"
"$BIN" help | jq -r '.commands[]' | sort >"$ROOT/listed.txt"

# Asks the loaded script what it offers for the words given, one per line.
offered() {
  bash -c '
    source "$1"; shift
    COMP_WORDS=("$@"); COMP_CWORD=$(( $# - 1 ))
    _skarbiec
    printf "%s\n" "${COMPREPLY[@]}"
  ' completion "$ROOT/completion.bash" "$@"
}

offered skarbiec "" | sort >"$ROOT/offered.txt"
diff "$ROOT/listed.txt" "$ROOT/offered.txt" >>"$REPORT" || fail "the first word does not complete to exactly the commands help lists"
echo "ok: the first word completes to every command help lists and no other" >>"$REPORT"

[ "$(offered skarbiec si | sort | tr '\n' ' ')" = "signing sites " ] || fail "si did not complete to signing and sites"
offered skarbiec sites my-login -- | grep -qx -- "--add" || fail "a word after sites does not complete to --add"
offered skarbiec sites my-login -- | grep -qx -- "--remove" || fail "a word after sites does not complete to --remove"
echo "ok: names complete by prefix and sites offers its own flags" >>"$REPORT"

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
