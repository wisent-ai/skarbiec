#!/bin/sh
set -eu

: "${SKARBIEC_BIN:?Stado did not pin the release binary}"
: "${SKARBIEC_PORT:?Stado did not assign the service port}"
: "${SKARBIEC_RUNTIME_DIR:?Stado did not assign the runtime directory}"

# Stado deliberately starts release candidates with a minimal environment.
# Skarbiec's runtime tools must therefore be reachable without inheriting an
# interactive shell's Homebrew or local-package PATH.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin${PATH:+:$PATH}"
mkdir -p "$SKARBIEC_RUNTIME_DIR"
exec "$SKARBIEC_BIN" serve --port "$SKARBIEC_PORT"
