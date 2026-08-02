#!/bin/sh
# Execute real product journeys and render their transcripts as deterministic GIFs.
set -eu
PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export PATH

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ -n "${SKARBIEC_BIN:-}" ]; then
  SB=$SKARBIEC_BIN
else
  CARGO=${CARGO_BIN:-cargo}
  if ! command -v "$CARGO" >/dev/null 2>&1; then
    printf '%s\n' "Cargo is required to build the current Skarbiec source" >&2
    exit 1
  fi
  (cd "$ROOT" && "$CARGO" build --release)
  SB="$ROOT/target/release/skarbiec"
fi
MAGICK=${MAGICK_BIN:-magick}
OUT_DIR="$ROOT/assets/demos"
STAGE_DIR=$(mktemp -d "$ROOT/assets/.readme-gifs.XXXXXX")
cleanup() {
  rm -rf "$STAGE_DIR"
}
trap cleanup EXIT HUP INT TERM

if [ -z "$SB" ] || [ ! -x "$SB" ]; then
  printf '%s\n' "No host-compatible Skarbiec binary found; build it or set SKARBIEC_BIN" >&2
  exit 1
fi
if ! command -v "$MAGICK" >/dev/null 2>&1; then
  printf '%s\n' "ImageMagick is required; set MAGICK_BIN if magick is not on PATH" >&2
  exit 1
fi

mkdir -p "$STAGE_DIR/transcripts" "$STAGE_DIR/frames"
export SKARBIEC_BIN="$SB"

render_gif() {
  journey=$1
  transcript="$STAGE_DIR/transcripts/$journey.txt"
  frame_dir="$STAGE_DIR/frames/$journey"
  output="$STAGE_DIR/$journey.gif"
  mkdir "$frame_dir"

  "$ROOT/scripts/readme-gifs/run-journey.sh" "$journey" "$transcript"

  total_lines=$(/usr/bin/wc -l <"$transcript" | tr -d ' ')
  step=$((total_lines / 12))
  if [ "$step" -lt 1 ]; then
    step=1
  fi


  write_frame_text() {
    through=$1
    destination=$2
    if [ "$through" -le 24 ]; then
      sed -n "1,${through}p" "$transcript" >"$destination"
    else
      first_visible=$((through - 21))
      sed -n '1p' "$transcript" >"$destination"
      printf '\n' >>"$destination"
      sed -n "${first_visible},${through}p" "$transcript" >>"$destination"
    fi
  }
  frame=0
  shown=$step
  while [ "$shown" -lt "$total_lines" ]; do
    frame=$((frame + 1))
    frame_text="$frame_dir/frame.txt"
    write_frame_text "$shown" "$frame_text"
    "$MAGICK" \
      -background '#0D1117' -fill '#E6EDF3' -pointsize 20 \
      -size 1160x660 -gravity northwest -interline-spacing 5 \
      "caption:@$frame_text" \
      -gravity center -background '#0D1117' -extent 1200x700 \
      "$frame_dir/frame-$(printf '%03d' "$frame").png"
    shown=$((shown + step))
  done

  frame=$((frame + 1))
  frame_text="$frame_dir/frame.txt"
  write_frame_text "$total_lines" "$frame_text"
  "$MAGICK" \
    -background '#0D1117' -fill '#E6EDF3' -pointsize 20 \
    -size 1160x660 -gravity northwest -interline-spacing 5 \
    "caption:@$frame_text" \
    -gravity center -background '#0D1117' -extent 1200x700 \
    "$frame_dir/frame-$(printf '%03d' "$frame").png"

  "$MAGICK" -delay 45 "$frame_dir"/frame-*.png \
    -delay 220 "$frame_dir/frame-$(printf '%03d' "$frame").png" \
    -loop 0 -layers Optimize "$output"
}

render_gif vault-lifecycle
render_gif one-use-acquisition
render_gif delete-and-restore

BINARY_SHA=$(shasum -a 256 "$SB" | cut -d ' ' -f 1)
BINARY_IDENTITY=$("$SB" --version)
GENERATED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

manifest_entry() {
  journey=$1
  transcript_sha=$(shasum -a 256 "$STAGE_DIR/transcripts/$journey.txt" | cut -d ' ' -f 1)
  gif_sha=$(shasum -a 256 "$STAGE_DIR/$journey.gif" | cut -d ' ' -f 1)
  printf '    {"journey":"%s","transcript":"transcripts/%s.txt","transcriptSha256":"%s","gif":"%s.gif","gifSha256":"%s"}' \
    "$journey" "$journey" "$transcript_sha" "$journey" "$gif_sha"
}

{
  printf '{\n'
  printf '  "schemaVersion": 1,\n'
  printf '  "generatedAt": "%s",\n' "$GENERATED_AT"
  printf '  "source": "real isolated Skarbiec CLI journeys",\n'
  printf '  "binary": %s,\n' "$BINARY_IDENTITY"
  printf '  "binarySha256": "%s",\n' "$BINARY_SHA"
  printf '  "journeys": [\n'
  manifest_entry vault-lifecycle
  printf ',\n'
  manifest_entry one-use-acquisition
  printf ',\n'
  manifest_entry delete-and-restore
  printf '\n  ]\n'
  printf '}\n'
} >"$STAGE_DIR/manifest.json"

rm -rf "$STAGE_DIR/frames"
rm -rf "$OUT_DIR"
mv "$STAGE_DIR" "$OUT_DIR"
trap - EXIT HUP INT TERM
printf '%s\n' "Generated real README journeys in $OUT_DIR"
