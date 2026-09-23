#!/usr/bin/env bash
# The journeys a release is qualified by, run after release/build.sh against
# the binary it staged. tests/operator-http starts that binary as the one
# Skarbiec process - HTTP and the capability socket together, --no-http with
# the socket alone, a broker handing its socket to a successor - through
# SKARBIEC_TEST_BINARY, so what passes here is what gets packaged.
set -euo pipefail

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
source_dir=${WISENT_SOURCE_DIR:?WISENT_SOURCE_DIR is required}
output_dir=${WISENT_OUTPUT_DIR:?WISENT_OUTPUT_DIR is required}
staged="$output_dir/stage/bin/skarbiec"
if [[ ! -x "$staged" ]]; then
  printf 'no staged skarbiec at %s: release/build.sh stages it before these journeys run\n' "$staged" >&2
  exit 66
fi
SKARBIEC_TEST_BINARY="$staged" \
  cargo test --locked --manifest-path "$source_dir/Cargo.toml" --test operator-http
