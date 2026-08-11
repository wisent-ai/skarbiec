#!/bin/sh
set -eu

[ "$(uname -s)" = Darwin ] || {
  printf '%s\n' "Skarbiec broker recovery requires macOS" >&2
  exit 1
}

repo="$HOME/.stado/build/skarbiec"
/bin/mkdir -p "$HOME/.stado/build" "$HOME/.stado/bin"
if [ -d "$repo/.git" ]
then
  /usr/bin/git -C "$repo" fetch --prune origin main
else
  /usr/bin/git clone --filter=blob:none https://github.com/wisent-ai/skarbiec.git "$repo"
fi
/usr/bin/git -C "$repo" checkout --detach origin/main
cargo_bin=$(command -v cargo || true)
[ -n "$cargo_bin" ] || cargo_bin="$HOME/.cargo/bin/cargo"
[ -x "$cargo_bin" ]
"$cargo_bin" build --release --manifest-path "$repo/Cargo.toml" --bin skarbiec
/usr/bin/install -m 0755 "$repo/target/release/skarbiec" "$HOME/.stado/bin/skarbiec.next"
/bin/mv "$HOME/.stado/bin/skarbiec.next" "$HOME/.stado/bin/skarbiec"
/usr/bin/codesign --force --sign - "$HOME/.stado/bin/skarbiec"
"$HOME/.stado/bin/skarbiec" version
