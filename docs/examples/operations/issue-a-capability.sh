#!/bin/sh
# issue-a-capability.sh — map a resource onto a vault field and issue a finite
# capability against it, and see what issuance refuses before it hands one out.
#
# Goal: understand the contract `capability-issue` enforces, which is stricter
# than "is this resource known": a non-`challenge:` resource must map to a
# credential that can actually serve, and issuance proves that before it issues
# rather than leaving the failure to redemption.
# Requires: skarbiec on PATH (or SKARBIEC_BIN), and openssl.
#
# Runs entirely inside its own demo directory and keyring — it never reads or
# writes your real vault. The demo values are not secrets.
set -eu

SB=${SKARBIEC_BIN:-skarbiec}
DEMO_DIR=${SKARBIEC_EXAMPLE_DIR:-${TMPDIR:-/tmp}/skarbiec-capability-example}

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
export SKARBIEC_CAPABILITY_FILE="$DEMO_DIR/demo.capabilities.json"
export SKARBIEC_CAPABILITY_ROUTES_FILE="$DEMO_DIR/demo.capability-routes.json"
mkdir "$GNUPGHOME"
chmod u=rwx,go= "$GNUPGHOME"

"$SB" init demo-owner

# 1. Two credentials: one that holds a value and one that does not. An emptied
#    credential is the case this example exists for — it is indistinguishable
#    from a working one in the route table, and only opening it tells them
#    apart.
"$SB" set demo-provider-good --type api-key api_key=not-a-secret
printf '{"schema":"skarbiec.item.v2","kind":"api-key","fields":{"api_key":""},"context":{}}' \
  | "$SB" set-json demo-provider-empty --type api-key

# 2. Map each onto a resource. The table maps names to coordinates and
#    authorises nothing: whether a workload may redeem a resource is decided at
#    redemption by the live vault token registering its Ed25519 key.
"$SB" routes add --resource provider:demo-good \
  --item demo-provider-good --field api_key \
  --reason "example: a credential that holds a value"
"$SB" routes add --resource provider:demo-empty \
  --item demo-provider-empty --field api_key \
  --reason "example: a credential that was emptied"

# 3. Issue against the working credential. This succeeds and prints the
#    capability id and its state.
"$SB" capability-issue \
  --agent demo-agent --purpose example --target demo \
  --resource provider:demo-good --ttl 600 --max-uses 1

# 4. Issue against the emptied one. This refuses. Issuance resolves the route,
#    opens the item it names, and applies exactly the rules `routes verify`
#    applies — so a missing, renamed, trashed or unopenable item, a field the
#    item does not carry, and a field that is present but empty are all refused
#    here rather than at redemption. Opening the item means issuing a
#    non-`challenge:` capability may decrypt the item the route names; no value
#    is ever printed, and only the coordinate appears in the refusal.
#
#    `challenge:` resources are the documented exception and skip this check
#    entirely, because their value is written later by the relay.
if "$SB" capability-issue \
     --agent demo-agent --purpose example --target demo \
     --resource provider:demo-empty --ttl 600 --max-uses 1
then
  printf '%s\n' 'expected capability-issue to refuse the emptied credential'
  false
fi

# 5. The same question asked of the whole table at once.
"$SB" routes verify || true

printf '%s\n' "demo state: $DEMO_DIR"

# Verify: step 3 prints {"capability_id": "...", "status": "issued"}.
#
# Step 4 refuses, and the refusal is legible on both streams. On stdout it is a
# document, because the caller is usually a gateway running skarbiec as a
# subprocess and reading its stdout:
#
#   {
#     "command": "capability-issue",
#     "field": "api_key",
#     "item": "demo-provider-empty",
#     "reason": "vault item demo-provider-empty field api_key is present but empty",
#     "remedy": "inspect every route with: skarbiec routes verify, or skarbiec doctor",
#     "resource": "provider:demo-empty",
#     "status": "refused"
#   }
#
# and on stderr it is the same sentence as an error, with a non-zero exit:
#
#   Error: capability-issue refused for provider:demo-empty: vault item
#   demo-provider-empty field api_key is present but empty; inspect every route
#   with: skarbiec routes verify, or skarbiec doctor
#
# A refusal that names neither the coordinate nor the reason is what let a
# gateway record `capability_issue_refused` with an empty detail for a month
# while its release was quarantined eighteen times, so both carry both.
#
# If it fails:
#
#   Error: capability-issue refused for <resource>: no capability route maps
#   <resource> to a vault field; map it with: skarbiec routes add ...
#     → the resource is not in the table. `skarbiec routes add` maps it, or
#       `skarbiec routes reconcile` derives it from what vault items declare.
#
#   Error: capability-issue refused for <resource>: vault item <item> does not
#   open: ...
#     → this host cannot decrypt the item, which is a key or gpg fault rather
#       than a credential fault. It will name every route at once; check
#       `skarbiec key-doctor`.
#
# Next: docs/examples/operations/diagnose-a-vault.sh to ask the same question
# of every route at once, and docs/examples/acquire-one-field.sh for the
# workload-bound access path.
