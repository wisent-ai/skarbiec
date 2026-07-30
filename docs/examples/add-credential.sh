#!/bin/sh
# add-credential.sh — store a credential, use it from code, lend it to an agent.
# Nothing but the commands themselves. Run against your served vault.
set -eu

SB=${SKARBIEC_BIN:-skarbiec}
STADO=${STADO_BIN:-stado}

# 1. store (value comes from the environment, never inline)
printf '%s' "$EXAMPLE_VENDOR_KEY" | "$STADO" secrets put vendor-api

# 2. code holds only a reference and resolves at call time
#    config:  {"vendor_key": "skarbiec://vendor-api/value"}
"$STADO" secrets get vendor-api

# 3. lend exactly that item to an agent (scoped grant)
"$SB" token-mint agent-demo --scopes 'read:vendor-api'
