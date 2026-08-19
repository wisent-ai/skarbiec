#!/bin/sh
# What Skarbiec binary does this host actually run, and does it carry the
# tag-preserving writer?
#
# A vault write performed by a binary from before that fix drops the tags it
# was not told to keep, and the `brama:agent:<id>` tag is the only thing that
# binds a subscription credential to the agent allowed to spend it. So the
# question "which binary is installed here" is the same question as "why did
# this account vanish from the fleet an hour after someone fixed it".
set -eu
PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
BIN="$HOME/.stado/bin/skarbiec"

printf '=== path\n'
ls -l "$BIN" || printf '    absent: %s\n' "$BIN"
printf '    realpath: %s\n' "$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$BIN" 2>/dev/null || echo unknown)"

printf '\n=== version it reports\n'
"$BIN" version 2>&1 | head -8 || true

# `grep -x retag` cannot answer this and must never be used for it: rustc packs
# string literals into one unterminated blob, so a binary that carries the
# command shows `...setgetretagdeletereclaim...` on a single line and a
# whole-line match reports it as absent. That false negative is not theoretical
# -- it is what a freshly built 0.2.4 carrying the fix reported, which would have
# sent an operator hunting a stale binary that was already correct.
#
# Match the command's own usage literal instead. It is emitted only by cmd_retag,
# which arrived in the same commit as the tag-preserving writer (84b5466, "Keep
# an item's tags and recipients when a write does not mention them"), so its
# presence and that writer's presence are one fact.
printf '\n=== does it carry the tag-preserving writer\n'
if strings -a "$BIN" 2>/dev/null | grep -q 'usage: retag <id> --tags'; then
  printf '    yes: carries retag, so an absent --tags leaves tags alone\n'
else
  printf '    NO: predates the tag-preserving writer; every rotation drops tags\n'
fi

# One host carries several Skarbiec builds under different names, and the one
# that performs rotations is not always `$HOME/.stado/bin/skarbiec`: the operator
# laptop serves the configured agent endpoint (127.0.0.1:19096) through
# `~/.local/bin/skarbiec`, and brama on the mini ships its own
# `skarbiec-entitlements-router` inside a service directory. Reporting only the
# canonical path answered "the installed binary is fixed" while a different build
# kept stripping tags, so ask every candidate the same two questions.
#
# Resolve each one and say so when two names are one file. `~/.local/bin/skarbiec`
# is a symlink to the managed path, so it appears twice with identical answers;
# read as two independent builds it invites either replacing a file that needs no
# replacing, or believing a second binary is still stale after one install fixed
# both.
printf '\n=== every skarbiec build on this host, and whether each carries the fix\n'
for candidate in "$HOME/.stado/bin/skarbiec" \
                 "$HOME/.local/bin/skarbiec" \
                 "$HOME/.stado/services"/*/*/*/bin/skarbiec \
                 "$HOME/.stado/services"/*/*/*/bin/skarbiec-entitlements-router \
                 /opt/homebrew/bin/skarbiec /usr/local/bin/skarbiec; do
  [ -f "$candidate" ] || continue
  reported=$("$candidate" version 2>/dev/null |
    /usr/bin/tr -d ' ",' | /usr/bin/awk -F: '$1=="version"{print $2}')
  if strings -a "$candidate" 2>/dev/null | grep -q 'usage: retag <id> --tags'; then
    verdict=fixed
  else
    verdict=STRIPS-TAGS
  fi
  resolved=$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$candidate" 2>/dev/null)
  if [ "$resolved" = "$candidate" ]; then
    where="$candidate"
  else
    where="$candidate -> $resolved"
  fi
  printf '    %-12s %-12s %s  %s\n' "${reported:-unknown}" "$verdict" \
    "$(ls -l "$candidate" | /usr/bin/awk '{print $6, $7, $8}')" "$where"
done

# Replacing the file on disk does not replace a process already running the old
# bytes. A resident `skarbiec serve` keeps performing rotations with whatever it
# was started from, so "the installed binary carries the fix" and "the writer
# carries the fix" are two different claims, and only this section answers the
# second one. Report each live process with its start time: a process older than
# the file beneath it is the one still dropping tags.
printf '\n=== live skarbiec processes (the actual writers)\n'
found=no
for pid in $(/bin/ps -axo pid=,comm= | /usr/bin/awk '$2 ~ /skarbiec/ {print $1}'); do
  found=yes
  printf '    pid %s started %s\n' "$pid" \
    "$(/bin/ps -o lstart= -p "$pid" 2>/dev/null | /usr/bin/sed 's/^ *//')"
  printf '      argv: %s\n' "$(/bin/ps -o command= -p "$pid" 2>/dev/null | /usr/bin/cut -c1-160)"
done
[ "$found" = no ] && printf '    none: every rotation is a fresh exec of the file above\n'
exit 0
