#!/usr/bin/env bash
# Does the desktop client ask /v1/operator/credential for an operation this
# broker does not serve?
#
#   tools/check-broker-client-contract.sh <src/net/operator/credential.rs> <client directory or .swift file>
#
# The broker's operations are the variants of the `Operation` enum that
# credential.rs deserializes the request's `operation` into, in the
# kebab-case its `#[serde(rename_all = "kebab-case")]` reads them by; that
# enum is the only list the broker dispatches over. The client's operations
# are the literal `"operation": "<name>"` entries in every Swift file of the
# client, which is a directory since BackendClient became BackendClient/*.swift.
# Exit 0: every client operation is served. 1: at least one is not, each named
# with file, line and function. 2: an input is missing or the broker's list
# cannot be found.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf '%s\n' "usage: check-broker-client-contract.sh <src/net/operator/credential.rs> <client directory or .swift file>" >&2
  exit 2
fi
operations="$1"
client="$2"
[ -f "$operations" ] || { printf '%s not found\n' "$operations" >&2; exit 2; }
[ -e "$client" ] || { printf '%s not found\n' "$client" >&2; exit 2; }

# Every unit variant between `enum Operation {` and its closing brace, in
# kebab-case. A rename_all other than kebab-case would name them differently,
# so the attribute is required rather than assumed.
if ! grep -q '#\[serde(rename_all = "kebab-case")\]' "$operations"; then
  printf '%s\n' "$operations does not read its operations in kebab-case (#[serde(rename_all = \"kebab-case\")])" >&2
  exit 2
fi
broker="$(awk '
  /enum[[:space:]]+Operation[[:space:]]*\{/ { collecting = 1; next }
  collecting && /^[[:space:]]*\}/ { exit }
  collecting && match($0, /^[[:space:]]*[A-Z][A-Za-z0-9]*[[:space:]]*,?[[:space:]]*$/) {
    name = $0; gsub(/[[:space:],]/, "", name)
    kebab = tolower(substr(name, 1, 1))
    for (i = 2; i <= length(name); i++) {
      c = substr(name, i, 1)
      kebab = kebab (c ~ /[A-Z]/ ? "-" tolower(c) : c)
    }
    print kebab
  }
' "$operations" | sort -u)"
if [ -z "$broker" ]; then
  printf '%s\n' "no credential operation enum found in $operations: expected enum Operation { Variant, ... }" >&2
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
