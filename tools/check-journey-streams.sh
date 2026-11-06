#!/usr/bin/env bash
# Does a journey under tests/ read a program's standard error as part of its
# answer?
#
#   tools/check-journey-streams.sh [<tests directory>]
#
# Skarbiec announces every wait on standard error (`czekam: …` and
# `koniec czekania: …`, from stado_wait), and its refusals are written there
# too. A journey that captures `&>/dev/stdout` or `2>&1` into the text it
# compares or parses reads those lines as part of a stored value or a JSON
# answer, and fails on any read that waited. A journey keeps standard output
# in one variable and standard error in another, and asserts each where the
# product writes it.
# Exit 0: no journey merges the two. 1: each merge is listed with file and
# line. 2: the tests directory is missing.
set -euo pipefail

tests="${1:-tests}"
[ -d "$tests" ] || { printf '%s is not a directory\n' "$tests" >&2; exit 2; }

found="$(grep -rnE --include='*.sh' -e '&>[[:space:]]*/dev/stdout' -e '2>&1[[:space:]]*\)' -e '\$\([^)]*2>&1[^)]*\|' "$tests" || true)"
if [ -n "$found" ]; then
  printf '%s\n' "$found"
  printf '%s\n' "these journeys read standard error as part of the answer they compare: capture standard output and standard error into separate variables" >&2
  exit 1
fi
