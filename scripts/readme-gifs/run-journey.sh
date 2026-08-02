#!/bin/sh
# Run one isolated Skarbiec product journey and emit its real terminal transcript.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
SB=${SKARBIEC_BIN:-$ROOT/target/release/skarbiec}
JOURNEY=${1:-}
TRANSCRIPT=${2:-}

if [ -z "$JOURNEY" ] || [ -z "$TRANSCRIPT" ]; then
  printf '%s\n' "usage: $0 <vault-lifecycle|one-use-acquisition|delete-and-restore> <transcript>" >&2
  exit 2
fi
if [ ! -x "$SB" ]; then
  printf '%s\n' "Skarbiec binary is not executable: $SB" >&2
  exit 1
fi

STATE_ROOT=$(mktemp -d "/tmp/sb-gif.XXXXXX")
RAW_TRANSCRIPT="$STATE_ROOT/transcript.raw"
COMMAND_OUTPUT="$STATE_ROOT/command.out"
cleanup() {
  rm -rf "$STATE_ROOT"
}
trap cleanup EXIT HUP INT TERM

umask 077
export GNUPGHOME="$STATE_ROOT/gnupg"
export SKARBIEC_VAULT_FILE="$STATE_ROOT/demo.vault.json"
export SKARBIEC_AUDIT_FILE="$STATE_ROOT/demo.audit.jsonl"
mkdir "$GNUPGHOME"

record() {
  display=$1
  shift
  printf '\n$ %s\n' "$display" >>"$RAW_TRANSCRIPT"
  status=0
  "$@" >"$COMMAND_OUTPUT" 2>&1 || status=$?
  cat "$COMMAND_OUTPUT" >>"$RAW_TRANSCRIPT"
  if [ "$status" -ne 0 ]; then
    cat "$RAW_TRANSCRIPT" >&2
    return "$status"
  fi
}

case "$JOURNEY" in
  vault-lifecycle)
    printf '%s\n' "REAL JOURNEY: encrypted vault lifecycle and operator status" >"$RAW_TRANSCRIPT"
    record "skarbiec init demo-owner" "$SB" init demo-owner
    record "skarbiec set deploy-note --type note value=not-a-secret" \
      "$SB" set deploy-note --type note value=not-a-secret
    record "skarbiec list" "$SB" list
    record "skarbiec status" "$SB" status
    record "skarbiec verify-chain" "$SB" verify-chain
    ;;

  one-use-acquisition)
    printf '%s\n' "REAL JOURNEY: one field, one use, replay rejected" >"$RAW_TRANSCRIPT"
    ACQUISITION_DIR="$STATE_ROOT/acquisition"
    TOOL_DIR="$STATE_ROOT/tools"
    mkdir "$TOOL_DIR"
    ln -s /usr/bin/wc "$TOOL_DIR/wc"
    ln -s "$(command -v openssl)" "$TOOL_DIR/openssl"
    record "sh docs/examples/acquire-one-field.sh" \
      env PATH="$TOOL_DIR:$PATH" SKARBIEC_EXAMPLE_DIR="$ACQUISITION_DIR" SKARBIEC_BIN="$SB" \
      sh "$ROOT/docs/examples/acquire-one-field.sh"
    ACQUISITION_OUTPUT=$(cat "$COMMAND_OUTPUT")
    case "$ACQUISITION_OUTPUT" in
      *'"ok": true'*'"error": "unauthorized"'*'acquisition-issued'*'acquisition-consumed'*) ;;
      *)
        printf '%s\n' "acquisition journey missed an expected success, replay rejection, or audit event" >&2
        exit 1
        ;;
    esac
    ;;

  delete-and-restore)
    printf '%s\n' "REAL JOURNEY: recoverable deletion and restore" >"$RAW_TRANSCRIPT"
    record "skarbiec init restore-demo-owner" "$SB" init restore-demo-owner
    record "skarbiec set recoverable-note --type note value=restored-not-a-secret" \
      "$SB" set recoverable-note --type note value=restored-not-a-secret
    record "skarbiec delete recoverable-note" "$SB" delete recoverable-note
    record "skarbiec list --all" "$SB" list --all
    record "skarbiec restore recoverable-note" "$SB" restore recoverable-note
    record "skarbiec get recoverable-note" "$SB" get recoverable-note
    RESTORED_OUTPUT=$(cat "$COMMAND_OUTPUT")
    case "$RESTORED_OUTPUT" in
      *restored-not-a-secret*) ;;
      *)
        printf '%s\n' "restored item did not contain the expected demonstration value" >&2
        exit 1
        ;;
    esac
    ;;

  *)
    printf '%s\n' "unknown journey: $JOURNEY" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$TRANSCRIPT")"
sed "s|$STATE_ROOT|<isolated-temp>|g" "$RAW_TRANSCRIPT" >"$TRANSCRIPT"
