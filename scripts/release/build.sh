#!/usr/bin/env bash
set -euo pipefail

# The release worker starts workloads with a bare PATH; the toolchain this
# build needs is the script's own concern, exactly like the launcher's.
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

source_dir=${WISENT_SOURCE_DIR:?WISENT_SOURCE_DIR is required}
output_dir=${WISENT_OUTPUT_DIR:?WISENT_OUTPUT_DIR is required}
platform=${WISENT_PLATFORM:?WISENT_PLATFORM is required}
version=${WISENT_VERSION:?WISENT_VERSION is required}

case "$platform" in
  darwin-arm64)
    expected_os=Darwin
    expected_arch=arm64
    ;;
  linux-amd64)
    expected_os=Linux
    expected_arch=x86_64
    ;;
  *)
    printf 'unsupported release platform: %s\n' "$platform" >&2
    exit 64
    ;;
esac
actual_os=$(uname -s)
actual_arch=$(uname -m)
if [[ "$actual_os" != "$expected_os" || "$actual_arch" != "$expected_arch" ]]; then
  printf 'builder %s/%s cannot produce %s\n' "$actual_os" "$actual_arch" "$platform" >&2
  exit 65
fi

declared=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$source_dir/Cargo.toml" | sed -n '1p')
if [[ "$declared" != "$version" ]]; then
  printf 'WISENT_VERSION %s does not match Cargo.toml version %s\n' "$version" "$declared" >&2
  exit 65
fi

# Which revision is being published. The builder compiles an extracted
# `git archive HEAD` snapshot, so there is no `.git` here and Stado passes no
# revision in the environment; `.release-commit` is marked `export-subst`, so the
# archive carries the commit even though the working tree carries a placeholder.
#
# A checkout still holds that placeholder, so ask git directly there. If neither
# answers, refuse: a binary that claims release provenance but cannot name the
# source it came from is exactly the artifact this whole path exists to abolish,
# and a null commit is how a side-loaded build passed for a managed one.
commit=""
commit_file="$source_dir/.release-commit"
if [[ -r "$commit_file" ]]; then
  substituted=$(tr -d '[:space:]' <"$commit_file")
  if [[ "$substituted" =~ ^[0-9a-f]{40}$ ]]; then
    commit="$substituted"
  fi
fi
if [[ -z "$commit" && -d "$source_dir/.git" ]]; then
  commit=$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true)
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'cannot name the source revision for %s: %s carries no substituted commit and %s is not a Git checkout\n' \
    "$version" "$commit_file" "$source_dir" >&2
  exit 67
fi

build_root="$output_dir/.build"
stage="$output_dir/stage"
rm -rf "$build_root" "$stage"
mkdir -p "$build_root" "$stage/bin"

SKARBIEC_RELEASE_URI="stado://releases/skarbiec/$version/$platform/release.tar.gz" \
SKARBIEC_RELEASE_COMMIT="$commit" \
CARGO_TARGET_DIR="$build_root" \
  cargo build --locked --release --bin skarbiec \
    --manifest-path "$source_dir/Cargo.toml"

install -m 0755 "$build_root/release/skarbiec" "$stage/bin/skarbiec"
install -m 0755 "$source_dir/scripts/release/launch.sh" "$stage/bin/start"
install -m 0644 "$source_dir/LICENSE" "$stage/LICENSE"
install -m 0644 "$source_dir/NOTICE" "$stage/NOTICE"
install -m 0644 "$source_dir/TRADEMARKS.md" "$stage/TRADEMARKS.md"

if [[ "$platform" == linux-amd64 ]]; then
  extension_key=${SKARBIEC_EXTENSION_PRIVATE_KEY_FILE:?Skarbiec extension signing-key grant is required}
  if [[ ! -r "$extension_key" ]]; then
    printf 'Skarbiec extension signing-key grant is unreadable: %s\n' "$extension_key" >&2
    exit 66
  fi
  browser_stage="$stage/share/skarbiec/browser"
  mkdir -p "$browser_stage"
  codebase="https://stado.wisent.com/releases/skarbiec/$version/linux-amd64/skarbiec-autofill.crx"
  extension_id=$(tr -d '[:space:]' < "$source_dir/deploy/chrome-extension-id")
  python3 "$source_dir/tools/package-crx3.py" \
    "$source_dir/browser" \
    "$extension_key" \
    "$browser_stage/skarbiec-autofill.crx" \
    "$browser_stage/skarbiec-autofill.xml" \
    "$codebase" \
    "$version" \
    "$extension_id"
fi
