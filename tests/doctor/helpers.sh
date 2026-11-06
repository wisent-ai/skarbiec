#!/usr/bin/env bash
# Real test of `skarbiec doctor`'s helpers check through the built binary and
# the real git, on a vault of its own: SKARBIEC_VAULT_FILE,
# SKARBIEC_AUDIT_FILE, GNUPGHOME, HOME, GIT_CONFIG_GLOBAL and DOCKER_CONFIG
# point into this checkout's target directory, so the operator's vault,
# keyring, git and Docker setup are never read or written.
#
# With nothing set up the check is not_configured. After helper setup git
# it passes. A forge whose setting names a program that is gone — as
# after an upgrade moved the binary — makes it fail naming the forge and the
# setup command that repairs it. A ~/.git-credentials line still holding a
# sign-in for a forge git asks this vault for makes it fail naming the file,
# the forge and the import command. doctor's own exit status is recorded
# beside its answer, since other checks decide it.
#
# Usage: SKARBIEC=target/debug/skarbiec tests/doctor/helpers.sh
set -eu
cd "$(dirname "$0")/../.."
BIN=${SKARBIEC:?set SKARBIEC to the skarbiec binary under test, such as target/debug/skarbiec}
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ROOT="$PWD/target/real-tests/doctor/$RUN"
REPORT="$ROOT/report.txt"
KEYRING="$PWD/target/g$$"
mkdir -p "$ROOT/home" "$ROOT/docker" "$KEYRING"
chmod go-rwx "$KEYRING"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet || echo ' (dirty)')" >"$REPORT"
echo "binary: $BIN" >>"$REPORT"
export GNUPGHOME="$KEYRING"
export HOME="$ROOT/home"
export SKARBIEC_VAULT_FILE="$ROOT/vault.json"
export SKARBIEC_AUDIT_FILE="$ROOT/audit.jsonl"
export GIT_CONFIG_GLOBAL="$ROOT/gitconfig"
export DOCKER_CONFIG="$ROOT/docker"
: >"$GIT_CONFIG_GLOBAL"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all; rm -rf "$KEYRING"' EXIT

fail() {
  echo "FAIL: $*" | tee -a "$REPORT" >/dev/stderr
  false
}
# Runs doctor and keeps its answer in $doctor and its standard error in $said,
# with its exit status in the report.
diagnose() {
  if doctor=$("$BIN" doctor 2>"$ROOT/said"); then status=ok; else status=failed; fi
  said=$(cat "$ROOT/said")
  printf '$ skarbiec doctor\nexit: %s\noutput: %s\nstderr: %s\n\n' "$status" "$doctor" "$said" >>"$REPORT"
  printf '%s' "$doctor" | jq -e .checks >/dev/null || fail "doctor answered no checks: $doctor; stderr: $said"
}
helpers() {
  printf '%s' "$doctor" | jq -r '.checks[] | select(.check == "helpers") | "\(.status) \(.detail)"'
}

"$BIN" init "helpers-owner-$RUN" &>>"$REPORT" || fail "init was refused"
diagnose
case "$(helpers)" in
  not_configured*) echo "ok: the helpers check is not_configured with nothing set up" >>"$REPORT" ;;
  *) fail "the helpers check was not not_configured: $(helpers)" ;;
esac

FORGE="forge-$RUN.example"
"$BIN" helper setup git "$FORGE" &>>"$REPORT" || fail "helper setup git was refused"
diagnose
case "$(helpers)" in
  pass*) echo "ok: the helpers check passes once git asks this binary" >>"$REPORT" ;;
  *) fail "the helpers check did not pass after setup: $(helpers)" ;;
esac

printf 'https://ci:left-%s@%s\n' "$RUN" "$FORGE" >"$HOME/.git-credentials"
diagnose
case "$(helpers)" in
  fail*".git-credentials"*"$FORGE"*"helper import git <id> $FORGE"*) echo "ok: the helpers check fails naming a plain-text sign-in left for a forge this vault answers" >>"$REPORT" ;;
  *) fail "the helpers check did not name the plain-text sign-in for $FORGE: $(helpers)" ;;
esac
case "$(helpers)" in *"left-$RUN"*) fail "the helpers check printed the stored password" ;; esac
rm "$HOME/.git-credentials"
MOVED="moved-$RUN.example"
git config --global "credential.https://$MOVED.helper" "!$ROOT/gone/skarbiec helper answer git"
diagnose
case "$(helpers)" in
  fail*"$MOVED"*"helper setup git $MOVED"*) echo "ok: the helpers check fails naming the forge whose program is gone, with its repair" >>"$REPORT" ;;
  *) fail "the helpers check did not fail naming $MOVED and its repair: $(helpers)" ;;
esac

touch "$ROOT/passed"
echo "PASS" >>"$REPORT"
echo "PASS: $REPORT"
