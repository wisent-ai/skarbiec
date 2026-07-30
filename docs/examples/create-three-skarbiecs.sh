#!/bin/sh
# Example 02 — create three independent vaults (executable).
# Usage:  sh 02-stworzenie-trzech-skarbcow.sh <vaults-directory>
# Requires: EXAMPLE_SECRET in env (value of the test item).
set -eu

if [ $# -gt 0 ]; then
  DIR=$1
else
  DIR="$HOME/.skarbiec-trio"
fi
SB=${SKARBIEC_BIN:-skarbiec}
die() { echo "ERROR: $1" > /dev/stderr; false; exit; }
: "${EXAMPLE_SECRET:=example-value}"

mkdir -p "$DIR"
for name in osobisty zespol maszynowy; do
  [ -f "$DIR/$name.vault.json" ] && die "vault already exists: $DIR/$name.vault.json"
done

echo "== step: three initializations"
for name in osobisty zespol maszynowy; do
  SKARBIEC_VAULT_FILE="$DIR/$name.vault.json" \
    "$SB" init "skarbiec-$name <moj@email.pl>" > /dev/null
  echo "init ok: $name"
done

echo "== step: item only in the personal vault"
SKARBIEC_VAULT_FILE="$DIR/osobisty.vault.json" "$SB" set konto-bank --type login \
  "login_email=moj@email.pl" "login_password=$EXAMPLE_SECRET" > /dev/null

echo "== step: isolation proof (expected error: no item)"
for name in zespol maszynowy; do
  if SKARBIEC_VAULT_FILE="$DIR/$name.vault.json" "$SB" get konto-bank > /dev/null; then
    die "ISOLATION BROKEN: konto-bank visible in $name"
  else
    echo "isolation ok: $name cannot see konto-bank"
  fi
done

echo "== step: recovery export per vault (fpr from recovery-status)"
for name in osobisty zespol maszynowy; do
  fpr=$(SKARBIEC_VAULT_FILE="$DIR/$name.vault.json" "$SB" recovery-status | awk -F'"' '/recovery_fpr/ {print $4; exit}')
  gpg --batch --yes --pinentry-mode loopback --passphrase '' \
    --export-secret-keys --armor "$fpr" > "$DIR/recovery-$name.asc"
  echo "recovery export ok: $name"
done
chmod u=rw,go= "$DIR"/recovery-*.asc
ls "$DIR"/recovery-*.asc
