# Examples — skarbiec in practice

A collection of **executable scripts** (sh) demonstrating real vault work.
Each script is self-contained and refuses to overwrite existing vault files.

## Command surfaces — which tool for what

- **Vault creation, multi-vault work, owner rotation, recovery exports** —
  the `skarbiec` CLI (`init`, `token-mint`, `serve`, `rotate-owner`).
  stado has no `create`; it manages items INSIDE an existing vault.
- **Item operations** — `stado secrets put / get / ls / rm`, talking to a
  running `skarbiec serve` over loopback HTTP (`WC_SKARBIEC_URL`) with a
  consumer grant (`STADO_CONFIG` + token file).
- **One vault.** Operator and Weles items live side by side in
  `~/.stado/brama-runtime-config/local.vault.json`; the scope is the
  boundary, not the file. The pre-consolidation Weles vault remains
  archived at `~/.stado/weles-skarbiec.vault.json`; both launchd serves
  (`com.wisent.skarbiec`, `skarbiec-weles` on 8786) now serve the single
  vault, and Weles consumer grants were migrated with their hashes intact.
- The launchd service `com.wisent.skarbiec` serves the operator vault
  (`~/.stado/brama-runtime-config/local.vault.json`), so plain
  `stado secrets get <item>` works without a custom port. The archived,
  permanently sealed pre-incident vault remains at
  `~/.stado/skarbiec.vault.json` — do not create new vaults there.

## Index

1. [`create-skarbiec.sh`](create-skarbiec.sh) — from zero to a stado-managed
   vault: `skarbiec init` → `token-mint` → `skarbiec serve` →
   `stado secrets put / ls / get`. Tested end-to-end.
2. [`create-three-skarbiecs.sh`](create-three-skarbiecs.sh) — three
   independent vaults, isolation proof, per-vault recovery exports.
   Tested end-to-end.
3. [`rotate-skarbiec-owner.sh`](rotate-skarbiec-owner.sh) — owner-rotation
   fire-drill: backup, successor key, `rotate-owner`, decrypt verification
   of every item. Tested end-to-end.
4. [`add-credential.sh`](add-credential.sh) — the credential lifecycle:
   store manually via stdin, use from code through a `skarbiec://`
   reference, lend to an agent with a one-item scoped grant (proof the
   agent reads only that item). Tested end-to-end.
5. [`sharing/share-credential-with-user.sh`](sharing/share-credential-with-user.sh) —
   GIVE (not lend) a credential to another user: recipient exports only
   their public key, donor encrypts one item value to it, armor travels
   over any channel, recipient decrypts into their OWN vault. Tested
   end-to-end (donor vault unchanged).
6. [`operations/change-skarbiec-location.sh`](operations/change-skarbiec-location.sh) —
   migrate the served vault to a new host endpoint: the vault file carries
   its hashed grants inside itself, so the same consumer token reads items
   through the new location; old endpoint proven closed. Tested end-to-end.
7. [`operations/build-skarbiec-host.sh`](operations/build-skarbiec-host.sh) —
   build a complete host from zero: init, grants (`sync:pull` for replicas,
   read/write for the operator), serve, verify through stado secrets.
   Tested end-to-end.
8. [`operations/change-skarbiec-host.sh`](operations/change-skarbiec-host.sh) —
   migrate a vault with the bond `pull` primitive: pull ciphertext from the
   old serve with a `sync:pull` grant, serve it on the new host, prove the
   operator grant traveled with the file. Tested end-to-end.
9. [`sharing/donate-item-to-host.sh`](sharing/donate-item-to-host.sh) —
   p2p donation: encrypt one item to the remote owner pubkey, POST to the
   donations endpoint with a `donate` grant, prove it lands and a repeat is
   rejected with status `exists`. Tested end-to-end.
10. [`git/git-sync-two-hosts.sh`](git/git-sync-two-hosts.sh) —
    the git bond mode: owner pushes ciphertext to a shared bare repo,
    replica pulls it and opens exactly the shared item. Tested end-to-end.
7. [`sharing/give-person-access-to-service.sh`](sharing/give-person-access-to-service.sh) —
   lend a person access to ONE service (Supabase): scoped grant for exactly
   those items, handoff bundle, proof she reads Supabase and nothing else,
   off-switch via `token-revoke`. Tested end-to-end.
7. [`operations/check-skarbiec-host.sh`](operations/check-skarbiec-host.sh) —
   where is my skarbiec host right now: serve processes with ports and
   vaults, launchd services, operator health through `stado secrets`.
   Tested end-to-end.
8. [`operations/print-skarbiec-config.sh`](operations/print-skarbiec-config.sh) —
   full config dump without any secret value: vault + item count,
   recipients, recovery, consumer tokens with scopes, env, consumer
   configs, launchd services. Tested end-to-end.
9. [`weles/give-credential-to-weles.sh`](weles/give-credential-to-weles.sh) —
   hand Weles a credential in its own trust domain: write a
   `weles-<vendor>-api` item into the Weles vault, grant the matching
   `weles-<vendor>-client` consumer, prove it reads only that item.
   Tested end-to-end.
10. [`weles/weles-writes-credential.sh`](weles/weles-writes-credential.sh) —
    the acquire write-path: an automation-produced credential lands in the
    vault as a login-shaped item (`created_via=weles-acquire`) and the
    owning client reads it back. Tested end-to-end.
11. [`weles/remote-access-for-weles-host.sh`](weles/remote-access-for-weles-host.sh) —
    Weles on ANOTHER host (mac-mini) against the skarbiec served here:
    scoped grant + bundle for transfer + the exact remote-side tunnel
    setup (secure tunnel to the loopback port, or cloudflared edge).
    Grant proven working locally.

## Running them

```sh
export SKARBIEC_BIN=~/Documents/CodingProjects/Wisent/skarbiec/target/release/skarbiec
export STADO_BIN=~/.stado/bin/stado

sh create-skarbiec.sh ~/.skarbiec-moj.vault.json <port>
sh create-three-skarbiecs.sh ~/.skarbiec-trio
sh rotate-skarbiec-owner.sh ~/.skarbiec-moj.vault.json \
  'skarbiec-moj <moj@email.pl>' 'skarbiec-moj-year2 <moj@email.pl>'
```

## Template for a new example

Per `../PRODUCT.md` ("Examples are a product requirement"):

- shebang + `set -eu`, usage comment at the top,
- parameters via arguments/env, no hardcoded paths beyond `$HOME` defaults,
- refuse to overwrite existing files,
- every step marked `echo "== step: ..."` and closed with a verification,
- secrets only via env vars / stdin, never inline,
- before committing: run it on a clean directory and paste the real output.
