# Examples — skarbiec in practice

Executable examples as **plain command sequences** — the commands
themselves, no scaffolding. Each script is runnable end-to-end and refuses
to overwrite existing vault files.

## Command surfaces — which tool for what

- **New workload access** — workload-bound one-use acquisition through
  `token-mint --acquisition-scopes`, `acquisition-request`, and
  `acquisition-read`. This is the default for a new machine integration.
- **Vault creation, multi-vault work, owner rotation, recovery exports** —
  the `skarbiec` CLI (`init`, `serve`, `rotate-owner`).
  Stado has no `create`; it manages items inside an existing vault.
- **Compatibility item operations** — `stado secrets put / get / ls / rm`,
  talking to a running `skarbiec serve` over loopback HTTP
  (`WC_SKARBIEC_URL`) with a direct consumer grant (`STADO_CONFIG` + token
  file). These examples document deployed integrations, not the default for a
  new workload.
- **One vault.** Operator and Weles items live side by side in
  `~/.stado/brama-runtime-config/local.vault.json`; the scope is the
  boundary, not the file. Both launchd serves now serve this single vault.
- **Sync (bond)** — `pull` / `sync-init`+`sync-push`/`sync-pull` /
  `enroll` / `donate` + `donations` / `sync-daemon` / `sync-status`.

## Index

1. [`acquire-one-field.sh`](acquire-one-field.sh) — register an Ed25519 workload, consume one exact field once, prove replay fails, inspect audit.
2. [`create-skarbiec.sh`](create-skarbiec.sh) — init, first item, read-back, status.
3. [`create-three-skarbiecs.sh`](create-three-skarbiecs.sh) — three vaults, isolation proof.
4. [`rotate-skarbiec-owner.sh`](rotate-skarbiec-owner.sh) — backup, rotate-owner, verify.
5. [`add-credential.sh`](add-credential.sh) — store via stdin, reference in code, legacy direct scoped lend.
6. [`operations/build-skarbiec-host.sh`](operations/build-skarbiec-host.sh) — init, compatibility grants, serve, health.
7. [`operations/change-skarbiec-host.sh`](operations/change-skarbiec-host.sh) — pull to a new host, serve.
8. [`operations/check-skarbiec-host.sh`](operations/check-skarbiec-host.sh) — where is my host right now.
9. [`operations/print-skarbiec-config.sh`](operations/print-skarbiec-config.sh) — full config dump, no secrets.
10. [`git/git-sync-two-hosts.sh`](git/git-sync-two-hosts.sh) — two vaults through a bare git remote.
11. [`bond/enroll-replica.sh`](bond/enroll-replica.sh) — replica enroll handshake.
12. [`bond/donation-inbox.sh`](bond/donation-inbox.sh) — donate, review in remote inbox.
13. [`bond/invite-person.sh`](bond/invite-person.sh) — one redeemable package for a human.
14. [`sharing/share-credential-with-user.sh`](sharing/share-credential-with-user.sh) — GIVE to another user's vault.
15. [`sharing/give-person-access-to-service.sh`](sharing/give-person-access-to-service.sh) — LEND one service to a person.
16. [`sharing/donate-item-to-host.sh`](sharing/donate-item-to-host.sh) — donate + duplicate rejection.
17. [`weles/`](weles/) — deployed Weles compatibility flows: give, write back, remote access.

## Run the acquisition proof

```sh
SKARBIEC_EXAMPLE_DIR="${TMPDIR:-/tmp}/skarbiec-acquisition-example" \
  sh acquire-one-field.sh
```

The first `acquisition-read` returns `ok: true` with
`value: "not-a-secret"`. Repeating that exact read returns
`{"error":"unauthorized","ok":false}` because successful consumption deletes the
capability hash before returning the field. `audit-query` then shows one
`acquisition-issued` and one `acquisition-consumed` entry without recording the
value or token.

If `acquisition-request` returns `unauthorized`, remove the demo directory and
rerun the whole script: the signed timestamp has a short acceptance window, and
the nonce is intentionally single-use. If initialization or decryption fails,
run `skarbiec key-doctor` against the same `SKARBIEC_VAULT_FILE` and
`GNUPGHOME`.

## Running the remaining examples

```sh
sh create-skarbiec.sh
sh create-three-skarbiecs.sh
sh operations/build-skarbiec-host.sh ~/.skarbiec-moj.vault.json <port>
```

## Template for a new example

Per `../PRODUCT.md` (CLI design contract + examples requirement):

- shebang + `set -eu`, usage comment at the top,
- plain command sequences — the commands themselves, no helpers,
- `${SKARBIEC_BIN:-skarbiec}` for the binary, env vars for values,
- refuse to overwrite existing files,
- secrets only via env/stdin, never inline,
- before committing: run it and paste the real output.
