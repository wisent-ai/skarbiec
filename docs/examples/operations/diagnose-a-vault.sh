#!/bin/sh
# diagnose-a-vault.sh — answer "is this installation healthy" without opening
# the desktop app, and declare the endpoint a fresh machine is missing.
#
# Goal: read every fact the Overview renders, from the command line, on a
# machine you have just installed skarbiec on.
# Requires: skarbiec on PATH (or SKARBIEC_BIN), and a vault this user owns.
#
# Runs read-only against your real vault except for step 3, which writes one
# owner-only file naming the loopback endpoint. Nothing here prints a secret
# value. The `credentials` check does decrypt: it opens each item a capability
# route names, because whether the routed field is empty is not a question the
# cleartext envelope can answer. It reports only the coordinate and what is
# wrong with it, never the value, and it costs one gpg per distinct item.
set -eu

SB=${SKARBIEC_BIN:-skarbiec}

# 1. The whole operator picture in one call. Reads the vault file, the audit
#    journal and the forward marker directly — never through the HTTP API it
#    is diagnosing, so it still answers when that API is down.
"$SB" doctor

# 2. The chain on its own, with the split that makes it affordable.
#    Linkage covers every entry because it is two string comparisons; digests
#    cost one shasum process each, so --tail bounds them to the newest window.
"$SB" verify-chain --tail 200

# 3. Declare where the canonical Skarbiec answers. A fresh installation has no
#    forward file at all, and every `credential` call refuses until it does.
#    With no argument this names the port `serve` binds by default.
"$SB" credential declare-endpoint

# 4. The newest journal entries, read from the file's tail rather than by
#    parsing the whole journal.
"$SB" audit --limit 10

# Verify: step 1 prints one object per check with a status of pass, fail or
# not_configured, and a tally. On the machine this example was written on:
#
#   {"check":"vault","detail":"539 items, 157 grants, at ~/.stado/skarbiec.vault.json","status":"pass"}
#   {"check":"audit","detail":"74981 of 74982 entries linked, newest 200 digests intact; 1 fault(s), first at line 2311 (2026-07-30T23:16:21Z)","status":"fail"}
#   {"check":"endpoint","detail":"http://127.0.0.1:8787, declared by ~/.stado/forwards/skarbiec.local","status":"pass"}
#   {"check":"worm","detail":"set SKARBIEC_WORM_RECEIPT_DIR and SKARBIEC_WORM_CHECKPOINT ...","status":"not_configured"}
#   {"check":"grants","detail":"157 grants resolve","status":"pass"}
#   {"check":"credentials","detail":"20 routes hold a usable credential","status":"pass"}
#
# Read "not_configured" as "nobody switched this on", not as an outage. Only
# "fail" is an incident.
#
# If it fails:
#
#   SKARBIEC_ENDPOINT_UNRESOLVED: no canonical forward at
#   ~/.stado/forwards/skarbiec.local; declare it with
#   `skarbiec credential declare-endpoint <url>`
#     → the state of every fresh install. Run step 3.
#
#   {"check":"endpoint","status":"fail","detail":"nothing answers
#   http://127.0.0.1:8785, declared by ~/.stado/forwards/skarbiec.local"}
#     → the file names an address no Skarbiec serves. Re-run step 3 with the
#       right URL; the default port is 8787.
#
#   {"check":"audit","status":"fail","detail":"... 1 fault(s), first at line
#   2311 ..."}
#     → a linkage fault is a second writer that appended against a stale tail,
#       not a forged entry. Read the line and its predecessor:
#         sed -n '2310,2311p' "$HOME/.stado/skarbiec.audit.jsonl"
#       A digest fault is the other case, and means the line's own fields no
#       longer hash to the hash it carries.
#
#   {"check":"credentials","status":"fail","detail":"1 of 20 routes cannot
#   serve a credential","problems":[{"resource":"provider:claude-code",
#   "item":"provider:claude-code:brama-sub-...","field":"value",
#   "problem":"vault item provider:claude-code:brama-sub-... field value is
#   present but empty"}]}
#     → the route is fine and the credential behind it is not, so every
#       workload asking for that resource is refused while the table still
#       looks correct. Write the value back with `skarbiec set`, then re-run.
#       `skarbiec routes verify` asks the same question on its own and exits
#       non-zero, which is the form a provisioning sequence wants.
#       The other problems this reports are `no vault item <item>` (purged),
#       `vault item <item> was renamed to <new>`, `vault item <item> is in
#       trash`, `vault item <item> has no <field> field`, and `vault item
#       <item> does not open: ...` — that last one is this host's gpg, not the
#       credential, and it will name every route at once.
#
# Next: docs/CLI.md for the full command surface, and
# docs/examples/acquire-one-field.sh for the workload-bound access path.
