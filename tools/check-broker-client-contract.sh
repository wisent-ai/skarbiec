#!/usr/bin/env bash
# Does the desktop client ask /v1/operator/credential for an operation this
# broker does not serve?
#
#   tools/check-broker-client-contract.sh <src/net/operator/routes.rs> <client directory or .swift file>
#
# The broker's list is the array routes.rs checks the operation against
# (`if ![...].contains(&operation.as_str())`). The client's operations are the
# literal `"operation": "<name>"` entries in every Swift file of the client,
# which is a directory since BackendClient became BackendClient/*.swift.
# Exit 0: every client operation is served. 1: at least one is not, each named
# with file, line and function. 2: an input is missing or the broker's list
# cannot be found.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf '%s\n' "usage: check-broker-client-contract.sh <src/net/operator/routes.rs> <client directory or .swift file>" >&2
  exit 2
fi
routes="$1"
client="$2"
[ -f "$routes" ] || { printf '%s not found\n' "$routes" >&2; exit 2; }
[ -e "$client" ] || { printf '%s not found\n' "$client" >&2; exit 2; }

# The array literal ends at the line holding `.contains(&operation.as_str())`;
# it starts at the `if ![` above it.
broker="$(awk '
  /if[[:space:]]*![[:space:]]*\[/ { collecting = 1; text = "" }
  collecting { text = text $0 }
  collecting && /\.contains\(&operation\.as_str\(\)\)/ { print text; exit }
' "$routes" | { grep -o '"[^"]*"' || true; } | tr -d '"' | sort -u)"
if [ -z "$broker" ]; then
  printf '%s\n' "no credential operation list found in $routes: expected if ![\"...\", ...].contains(&operation.as_str())" >&2
  exit 2
fi

# file:line:function:operation for every literal operation the client sends.
calls="$(find "$client" -name '*.swift' -type f | sort | while IFS= read -r file; do
  awk -v file="$file" '
    match($0, /func[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
      name = substr($0, RSTART, RLENGTH); sub(/func[[:space:]]+/, "", name); fn = name
    }
    match($0, /"operation":[[:space:]]*"[^"]+"/) {
      op = substr($0, RSTART, RLENGTH); sub(/"operation":[[:space:]]*"/, "", op); sub(/"$/, "", op)
      printf "%s:%d:%s:%s\n", file, NR, (fn == "" ? "unknown" : fn), op
    }
  ' "$file"
done)"

unsupported=""
while IFS= read -r call; do
  [ -n "$call" ] || continue
  operation="${call##*:}"
  if ! printf '%s\n' "$broker" | grep -qx -- "$operation"; then
    unsupported="${unsupported}${call}"$'\n'
  fi
done <<< "$calls"

used="$(printf '%s\n' "$calls" | awk -F: 'NF { print $NF }' | sort -u | paste -sd, -)"
served="$(printf '%s\n' "$broker" | paste -sd, -)"
if [ -n "$unsupported" ]; then
  printf '%s\n' "BROKER-CLIENT CONTRACT VIOLATION: the client sends operations the broker refuses" >&2
  printf '%s' "$unsupported" | while IFS=: read -r file line function operation; do
    printf '  %s: %s() at %s:%s\n' "$operation" "$function" "$file" "$line" >&2
  done
  printf 'broker serves: %s\nclient sends:  %s\n' "$served" "$used" >&2
  exit 1
fi
printf 'every client operation is served\nbroker serves: %s\nclient sends:  %s\n' "$served" "$used"
