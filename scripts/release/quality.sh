#!/usr/bin/env bash
set -euo pipefail

source_dir=${WISENT_SOURCE_DIR:?WISENT_SOURCE_DIR is required}
: "${WISENT_OUTPUT_DIR:?WISENT_OUTPUT_DIR is required}"
platform=${WISENT_PLATFORM:?WISENT_PLATFORM is required}
version=${WISENT_VERSION:?WISENT_VERSION is required}

case "$platform" in
  darwin-arm64|linux-amd64) ;;
  *) printf 'unsupported release platform: %s\n' "$platform" >&2; exit 64 ;;
esac

declared=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$source_dir/Cargo.toml" | sed -n '1p')
if [[ "$declared" != "$version" ]]; then
  printf 'WISENT_VERSION %s does not match Cargo.toml version %s\n' "$version" "$declared" >&2
  exit 65
fi

cargo fmt --manifest-path "$source_dir/Cargo.toml" -- --check
cargo clippy --locked --all-targets \
  --manifest-path "$source_dir/Cargo.toml" -- -D warnings
python3 "$source_dir/scripts/surface.py" >/dev/null
