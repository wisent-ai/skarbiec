#!/usr/bin/env bash
# Real test of where Skarbiec reads the vault Stado declares as
# `secrets.skarbiec.vault_file` when the declaration is written under the
# account's home: `~/<path>` and `$HOME/<path>` both name <home>/<path>, as
# Stado reads them, and an absolute path is taken as written. Before the
# repair `$HOME/` was taken literally, so the broker's state paths and its
# clients' disagreed (`uses different state paths`) on the host that held the
# vault. The built binary runs `status --json` with HOME and STADO_CONFIG set
# into this checkout's target directory and no SKARBIEC_VAULT_FILE, so the
# operator's vault and config are never read; the vault named does not exist,
# so status refuses with `vault not initialized at <path>`, which names the
# path it would open. Every command and verdict goes to the run's report.txt.
#
# Supply SKARBIEC, then run tests/core/declared_home_vault.sh.
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, e.g. SKARBIEC=target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/declared-home-vault/$RUN"
REPORT="$ROOT/report.txt"
HOME_DIR="$ROOT/home"
mkdir -p "$HOME_DIR"
chmod go-rwx "$ROOT"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
echo "binary-git-blob: $(git hash-object "$BIN")" >>"$REPORT"
failed=0

check() {
  declared=$1
  expected=$2
  config="$ROOT/config-$3.json"
  printf '{"secrets":{"skarbiec":{"vault_file":"%s"}}}\n' "$declared" >"$config"
  set +e
  answer=$(env -u SKARBIEC_VAULT_FILE HOME="$HOME_DIR" STADO_CONFIG="$config" "$BIN" status --json 2>&1)
  status=$?
  set -e
  echo "declared $declared -> exit $status: $answer" >>"$REPORT"
  if printf '%s' "$answer" | grep -qF "vault not initialized at $expected "; then
    echo "PASS $3: $declared names $expected" >>"$REPORT"
  else
    echo "FAIL $3: $declared did not name $expected" >>"$REPORT"
    failed=1
  fi
}

check '$HOME/.stado/skarbiec.vault.json' "$HOME_DIR/.stado/skarbiec.vault.json" dollar-home
check '~/.stado/skarbiec.vault.json' "$HOME_DIR/.stado/skarbiec.vault.json" tilde
check "$ROOT/elsewhere/vault.json" "$ROOT/elsewhere/vault.json" absolute

cat "$REPORT"
exit "$failed"
