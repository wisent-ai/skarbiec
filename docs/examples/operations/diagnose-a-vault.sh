#!/bin/sh
# diagnose-a-vault.sh — answer "is this installation healthy" without opening
# the desktop app, and declare the endpoint a fresh machine is missing.
#
# Goal: read every fact the Overview renders, from the command line, on a
# machine you have just installed skarbiec on.
# Usage: SKARBIEC_BIN=<skarbiec binary> sh diagnose-a-vault.sh <canonical-url> <digest-window> <journal-entries>
#   <canonical-url>    the address the canonical Skarbiec answers on from this
#                      machine, as `skarbiec serve --port` listens or Stado's
#                      service directory publishes it
#   <digest-window>    how many of the newest journal entries step 2 recomputes
#                      the digest of
#   <journal-entries>  how many of the newest journal entries step 4 prints
#
# Runs read-only against your real vault except for step 3, which writes one
# owner-only file naming the canonical endpoint. Nothing here prints a secret
# value. The `credentials` check does decrypt: it opens each item a capability
# route names, because whether the routed field is empty is not a question the
# cleartext envelope can answer. It reports only the coordinate and what is
# wrong with it, never the value, and it costs one gpg per distinct item.
set -eu

SB=${SKARBIEC_BIN:?SKARBIEC_BIN must name the skarbiec binary this example runs}
CANONICAL_URL=$1
DIGEST_WINDOW=$2
JOURNAL_ENTRIES=$3

# 1. The whole operator picture in one call. Reads the vault file, the audit
#    journal and the forward marker directly — never through the HTTP API it
#    is diagnosing, so it still answers when that API is down.
"$SB" doctor

# 2. The chain on its own, with the split that makes it affordable.
#    Linkage covers every entry because it is two string comparisons; digests
#    cost one shasum process each, so --tail bounds them to the newest window.
"$SB" audit verify --tail "$DIGEST_WINDOW"

# 3. Declare where the canonical Skarbiec answers. A fresh installation has no
#    forward file at all, and every `credential` call refuses until it does.
#    The address is always stated: the command never guesses the port `serve`
#    binds, because on a machine whose Skarbiec runs elsewhere that guess would
#    name an unrelated local process the canonical one.
"$SB" credential endpoint declare "$CANONICAL_URL"

# 4. The newest journal entries, read from the file's tail rather than by
#    parsing the whole journal.
"$SB" audit list --limit "$JOURNAL_ENTRIES"

# Verify: step 1 prints one object per check with a status of pass, fail or
# not_configured, and a tally, for example:
#
#   {"check":"vault","detail":"<n> items, <n> grants, at <vault path>","status":"pass"}
#   {"check":"audit","detail":"<n> of <n> entries linked, newest <window> digests intact; 1 fault(s), first at line <line> (<moment>)","status":"fail"}
#   {"check":"endpoint","detail":"<canonical-url>, declared by <forward file>","status":"pass"}
#   {"check":"worm","detail":"set SKARBIEC_WORM_RECEIPT_DIR and SKARBIEC_WORM_CHECKPOINT ...","status":"not_configured"}
#   {"check":"grants","detail":"<n> grants resolve","status":"pass"}
#   {"check":"credentials","detail":"<n> routes hold a usable credential","status":"pass"}
#
# Read "not_configured" as "nobody switched this on", not as an outage. Only
# "fail" is an incident.
#
# If it fails:
#
#   SKARBIEC_ENDPOINT_UNRESOLVED: no canonical forward at <forward file>;
#   declare it with `skarbiec credential endpoint declare <url>`
#     → the state of every fresh install. Run step 3.
#
#   {"check":"endpoint","status":"fail","detail":"nothing answers
#   <canonical-url> (Connection refused (os error ...)), declared by
#   <forward file>"}
#     → the parenthesis is the operating system's answer to the connect.
#       "Connection refused": the file names an address no Skarbiec serves;
#       re-run step 3 with the URL `skarbiec serve --port` listens on.
#       "Operation not permitted" or "Permission denied": something on this
#       machine blocks the connection itself, and the address may be right.
#
#   {"check":"audit","status":"fail","detail":"... 1 fault(s), first at line
#   <line> ..."}
#     → a linkage fault is a second writer that appended against a stale tail,
#       not a forged entry. Read that line and the one before it in the
#       journal file. A digest fault is the other case, and means the line's
#       own fields no longer hash to the hash it carries.
#
#   {"check":"credentials","status":"fail","detail":"1 of <n> routes cannot
#   serve a credential","problems":[{"resource":"<resource>","item":"<item>",
#   "field":"value","problem":"vault item <item> field value is present but
#   empty"}]}
#     → the route is fine and the credential behind it is not, so every
#       workload asking for that resource is refused while the table still
#       looks correct. Write the value back with `skarbiec set`, then re-run.
#       `skarbiec route verify` asks the same question on its own and exits
#       non-zero, which is the form a provisioning sequence wants.
#       The other problems this reports are `no vault item <item>` (purged),
#       `vault item <item> was renamed to <new>`, `vault item <item> is in
#       trash`, `vault item <item> has no <field> field`, and `vault item
#       <item> does not open: ...` — that last one is this host's gpg, not the
#       credential, and it will name every route at once.
#
# Next: https://skarbiec.wisent.com/docs/cli for the full command surface,
# docs/examples/operations/issue-a-capability.sh for the contract issuance
# enforces against these same routes, and docs/examples/acquire-one-field.sh
# for the workload-bound access path.
