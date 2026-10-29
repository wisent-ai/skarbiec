#!/usr/bin/env bash
# Real test of `skarbiec completion --shell fish`, through the built binary
# and a real fish: the script it prints is loaded into a fish of its own, with
# no user configuration, and asked to complete as a person pressing tab would.
# The first word must complete to every command `skarbiec help` lists, a
# prefix to the commands it starts, and a dash after `sites` to that command's
# flags. Another shell name is refused. Completing reads no vault.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/cli/completion_fish.sh
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
command -v fish >/dev/null || fail "fish is not installed here, so the fish completion cannot be exercised"

"$BIN" completion --shell fish >"$ROOT/skarbiec.fish" || fail "completion --shell fish was refused"
"$BIN" help | jq -r '.commands[]' | sort >"$ROOT/listed.txt"

# What the loaded script offers for a command line, the candidates only.
offered() {
  fish --no-config -c "source '$ROOT/skarbiec.fish'; complete -C '$1'" | cut -f1
}

offered "skarbiec " | sort >"$ROOT/offered.txt"
diff "$ROOT/listed.txt" "$ROOT/offered.txt" >>"$REPORT" || fail "the first word does not complete to exactly the commands help lists"
[ "$(offered "skarbiec si" | sort | tr '\n' ' ')" = "signing sites " ] || fail "si did not complete to signing and sites"
offered "skarbiec sites my-login --" | grep -qx -- "--add-related" || fail "a dash after sites does not complete to --add-related"
echo "ok: fish completes commands, prefixes and a command's own flags" >>"$REPORT"

if out=$("$BIN" completion --shell tcsh 2>"$ROOT/said"); then fail "--shell tcsh was not refused"; fi
said=$(cat "$ROOT/said")
case "$said" in *"bash and fish"*) echo "ok: another shell is refused naming the ones written" >>"$REPORT" ;; *) fail "--shell tcsh refusal names no shells: output: $out stderr: $said" ;; esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
