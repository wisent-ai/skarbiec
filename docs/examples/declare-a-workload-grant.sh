#!/bin/sh
# declare-a-workload-grant.sh -- one workload-bound declaration, and the
# redemption contract it answers with. The secret is never in either.
# Usage: SKARBIEC_BIN=<skarbiec binary> sh declare-a-workload-grant.sh <vault> <item> <field> <for-consumer> <workload-public-key-file>
set -eu

export SKARBIEC_VAULT_FILE=$1
SB=${SKARBIEC_BIN:?SKARBIEC_BIN must name the skarbiec binary this example runs}

"$SB" grant issue "$4" \
  --capabilities "acquire:$2#$3" \
  --workload-public-key-file "$5"
