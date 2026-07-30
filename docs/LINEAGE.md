# Lineage

Skarbiec existed as two diverged code bases. This document records what they
were and what this branch is for, so the next person does not repeat the
mistake of fixing one copy and shipping the other.

## The two lineages

**`main` — the deployed lineage.** The binary that serves the fleet on
loopback is built from this tree. It carries the `/v1/items/*` HTTP surface,
the one-time field acquisition flow (`acquisition-request`,
`acquisition-read`), and the honest failure reporting added after the July
credential outage.

**`vendored-superset` — this branch.** Skarbiec was also vendored inside
`lbartoszcze/entitlements-rotator` under `src/skarbiec/`, built there as a
second binary named `skarbiec-entitlements-router`, and published from that
repository as its own rolling release. That copy was never a mirror: it grew
sixteen commands the deployed lineage does not have, seven modules
(`access/capability.rs`, `access/reauth.rs`, `core/chrome_cards.rs`,
`credential.rs`, `release.rs`, `runtime/mailbox.rs`, `secure_input.rs`), and a
much wider dependency set — SQLite, AES-CBC, ed25519, PBKDF2 and an HTTP
client. Of the files present in both, most differed.

Its extra surface: Apple challenge and credential storage
(`apple-challenge-put`, `apple-credential-put`, `credential-put`), delegated
capabilities (`capability-serve`, `capability-issue`, `capability-status`,
`capability-cancel`, `capability-delegate`), Chrome card import (`card-set`,
`card-import-chrome`), mailbox brokering (`mailbox-broker`, `mailbox-probe`,
`seed-resend`), credential request/return, and release publishing.

## Why this branch exists

Both lineages now live in this one repository. Nothing about the vendored copy
is lost, and no second repository builds or publishes a credential broker any
more. This branch is the working-tree state of that copy at the moment of
consolidation, including work that had never been committed anywhere.

It compiles standalone. It is **not** deployed, and it is not merged: merging
it means deciding, feature by feature, what belongs in a broker the whole
fleet depends on. The dependency surface is the reason to be deliberate —
`main` states "no hosted dependency" and delegates cryptography to `gpg`,
`openssl` and `shasum`, while this branch links a database engine, a block
cipher and a network client into the process that holds every secret.

## What must not happen again

A credential broker with two sources and two publish paths cannot be reasoned
about. One of them was reached by production; the other accumulated features
and a release nobody consumed. During the outage that followed, the wrong copy
was read as the source of truth for hours, and a command found only in the
unreachable copy was cited as the recovery procedure.

One repository. One publish path. If a feature is worth having, it lands on
`main`.

## Archiwum: examples z 2026-07-28 (odrzucone)

Poniższe przykłady wyleciały z `CLI.md` decyzją właściciela („totalnie bez
sensu"). Zostają jako kontekst decyzji — zastąpione examples właściciela
(tworzenie skarbca od zera; trzy skarbce na jednym hoście).

### [archived] Odczyt jednej wartości z vaulta

```sh
skarbiec get MODEL_ROUTER_URL --field value
```

### [archived] Dodanie nowego sekretu (secret-safe)

```sh
read -rs NEWKEY < ~/new-api-key.txt        # albo NEWKEY=$SOME_ENV_VAR
skarbiec set VENDOR_API_KEY --type env "value=$NEWKEY"; unset NEWKEY
skarbiec get VENDOR_API_KEY | jq -r 'has("value")'
```

### [archived] Aplikacja czytająca kredyty przez referencje

```json
"url": "skarbiec://MODEL_ROUTER_URL/value",
"key": "skarbiec://agent:wisent-app/value",
"agent_id": "skarbiec://WISENT_APP_AGENT_ID/value"
```

```sh
node pipeline/cli.js check-config
```

### [archived] Wykonanie pracy przez Bramę z kredytami ze skarbca

```sh
curl http://127.0.0.1:8080/health           # → {"status":"ok"}
blender --python /tmp/start_blender_mcp.py &  # socket 9876
node pipeline/cli.js sculpt 'krasnolud wojownik, low-poly RTS, T-pose' --out assets --filename krasnolud.glb
node pipeline/cli.js verify assets/krasnolud.glb
```

### [archived] Odzyskiwanie dostępu po problemie z kluczem

```sh
skarbiec recovery-status
gpg --list-secret-keys skarbiec-owner-20260728
# na INNEJ maszynie:
gpg --import ~/.skarbiec-recovery-20260728.asc
skarbiec get MODEL_ROUTER_URL --field value
```

### [archived] Współdzielenie jednego itemu z innym kluczem

```sh
skarbiec add-user 'worker-nazwa' --import ./worker-pub.asc --role member
skarbiec share MODEL_ROUTER_URL 'worker-nazwa'
# na maszynie workera:
skarbiec get MODEL_ROUTER_URL --field value   # → wartość
skarbiec get STRIPE_PRIVATE_KEY               # → No secret key
```
