#!/bin/sh
# acquire-one-field.sh — register one workload, borrow one field once, prove replay fails.
# Run from a source checkout after installing skarbiec. The demo value is not a secret.
set -eu

SB=${SKARBIEC_BIN:-skarbiec}
DEMO_DIR=${SKARBIEC_EXAMPLE_DIR:-${TMPDIR:-/tmp}/skarbiec-acquisition-example}

if [ -e "$DEMO_DIR" ]; then
  printf '%s\n' "refusing to overwrite $DEMO_DIR; remove it or set SKARBIEC_EXAMPLE_DIR"
  false
fi

umask u=rwx,go=
mkdir "$DEMO_DIR"
chmod u=rwx,go= "$DEMO_DIR"
export GNUPGHOME="$DEMO_DIR/gnupg"
export SKARBIEC_VAULT_FILE="$DEMO_DIR/demo.vault.json"
export SKARBIEC_AUDIT_FILE="$DEMO_DIR/demo.audit.jsonl"
mkdir "$GNUPGHOME"
chmod u=rwx,go= "$GNUPGHOME"

WORKLOAD_PRIVATE_KEY="$DEMO_DIR/workload-private.pem"
WORKLOAD_PUBLIC_KEY="$DEMO_DIR/workload-public.pem"
CONSUMER=demo-workload
ITEM=demo-note
FIELD=value
WORKLOAD_ID=quickstart-workload

"$SB" init demo-owner
"$SB" set "$ITEM" --type note "$FIELD=not-a-secret"
openssl genpkey -algorithm ED25519 -out "$WORKLOAD_PRIVATE_KEY"
openssl pkey -in "$WORKLOAD_PRIVATE_KEY" -pubout -out "$WORKLOAD_PUBLIC_KEY"

"$SB" token-mint "$CONSUMER" \
  --acquisition-scopes "$ITEM#$FIELD" \
  --workload-public-key-file "$WORKLOAD_PUBLIC_KEY"

NONCE_BYTES=$(printf '%s' '................................' | wc -c | tr -d ' ')
WORKLOAD_TIMESTAMP=$(date +%s)
WORKLOAD_NONCE=$(openssl rand -base64 "$NONCE_BYTES" | tr '+/' '-_' | tr -d '=\n')
WORKLOAD_PAYLOAD="$DEMO_DIR/workload-payload.bin"
printf 'SKARBIEC-WORKLOAD-ACQUISITION\0v1\0%s\0%s\0%s\0%s\0%s\0%s' \
  "$CONSUMER" "$ITEM" "$FIELD" "$WORKLOAD_ID" "$WORKLOAD_TIMESTAMP" "$WORKLOAD_NONCE" \
  >"$WORKLOAD_PAYLOAD"
WORKLOAD_SIGNATURE=$(
  openssl pkeyutl -sign -inkey "$WORKLOAD_PRIVATE_KEY" -rawin -in "$WORKLOAD_PAYLOAD" \
  | od -An -tx1 \
  | tr -d ' \n'
)
rm -f "$WORKLOAD_PAYLOAD"

ACQUISITION_RESPONSE=$(
  "$SB" acquisition-request "$CONSUMER" "$ITEM" "$FIELD" \
    --workload-id "$WORKLOAD_ID" \
    --workload-timestamp "$WORKLOAD_TIMESTAMP" \
    --workload-nonce "$WORKLOAD_NONCE" \
    --workload-signature "$WORKLOAD_SIGNATURE"
)
ACQUISITION_TOKEN=$(printf '%s\n' "$ACQUISITION_RESPONSE" | sed -n 's/.*"token": "\([^"]*\)".*/\1/p')

if [ -z "$ACQUISITION_TOKEN" ]; then
  printf '%s\n' "$ACQUISITION_RESPONSE"
  printf '%s\n' 'acquisition-request returned no token'
  false
fi

"$SB" acquisition-read "$CONSUMER" "$ITEM" "$FIELD" --token "$ACQUISITION_TOKEN"
"$SB" acquisition-read "$CONSUMER" "$ITEM" "$FIELD" --token "$ACQUISITION_TOKEN"
"$SB" audit-query --consumer "$CONSUMER"
printf '%s\n' "demo state: $DEMO_DIR"
