#!/bin/sh
set -eu
: "${SKARBIEC_BIN:?Stado did not pin the release binary}"
: "${SKARBIEC_PORT:?Stado did not assign the service port}"
: "${SKARBIEC_RUNTIME_DIR:?Stado did not assign the runtime directory}"
# Runtime tools must not depend on an interactive shell's package-manager PATH.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin${PATH:+:$PATH}"
mkdir -p "$SKARBIEC_RUNTIME_DIR"
exec "$SKARBIEC_BIN" serve --port "$SKARBIEC_PORT"
