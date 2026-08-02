#!/bin/sh
# add-credential.sh — compatibility path: store through Stado, resolve from
# code, and issue a legacy direct scoped grant. New workloads use acquisition.
set -eu

SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}

# 1. store (value comes from the environment, never inline)
printf '%s' "$EXAMPLE_VENDOR_KEY" | "$STADO" secrets put vendor-api

# 2. code holds only a reference and resolves at call time
#    config:  {"vendor_key": "skarbiec://vendor-api/value"}
"$STADO" secrets get vendor-api

# 3. lend exactly that item through the legacy direct-grant path
"$SB" token-mint agent-demo --scopes 'read:vendor-api'
