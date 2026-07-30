# Examples — skarbiec in practice

Executable examples as **plain command sequences** — the commands
themselves, no scaffolding. Each script is runnable end-to-end and refuses
to overwrite existing vault files.

## Command surfaces — which tool for what

- **Vault creation, multi-vault work, owner rotation, recovery exports** —
  the `skarbiec` CLI (`init`, `token-mint`, `serve`, `rotate-owner`).
  stado has no `create`; it manages items INSIDE an existing vault.
- **Item operations** — `stado secrets put / get / ls / rm`, talking to a
  running `skarbiec serve` over loopback HTTP (`WC_SKARBIEC_URL`) with a
  consumer grant (`STADO_CONFIG` + token file).
- **One vault.** Operator and Weles items live side by side in
  `~/.stado/brama-runtime-config/local.vault.json`; the scope is the
  boundary, not the file. Both launchd serves now serve this single vault.
- **Sync (bond)** — `pull` / `sync-init`+`sync-push`/`sync-pull` /
  `enroll` / `donate` + `donations` / `sync-daemon` / `sync-status`.

## Index

1. [`create-skarbiec.sh`](create-skarbiec.sh) — init, first item, read-back, status.
2. [`create-three-skarbiecs.sh`](create-three-skarbiecs.sh) — three vaults, isolation proof.
3. [`rotate-skarbiec-owner.sh`](rotate-skarbiec-owner.sh) — backup, rotate-owner, verify.
4. [`add-credential.sh`](add-credential.sh) — store via stdin, reference in code, scoped lend.
5. [`operations/build-skarbiec-host.sh`](operations/build-skarbiec-host.sh) — init, grants, serve, health.
6. [`operations/change-skarbiec-host.sh`](operations/change-skarbiec-host.sh) — pull to a new host, serve.
7. [`operations/check-skarbiec-host.sh`](operations/check-skarbiec-host.sh) — where is my host right now.
8. [`operations/print-skarbiec-config.sh`](operations/print-skarbiec-config.sh) — full config dump, no secrets.
9. [`git/git-sync-two-hosts.sh`](git/git-sync-two-hosts.sh) — two vaults through a bare git remote.
10. [`bond/enroll-replica.sh`](bond/enroll-replica.sh) — replica enroll handshake.
11. [`bond/donation-inbox.sh`](bond/donation-inbox.sh) — donate, review in remote inbox.
12. [`bond/invite-person.sh`](bond/invite-person.sh) — one redeemable package for a human.
13. [`sharing/share-credential-with-user.sh`](sharing/share-credential-with-user.sh) — GIVE to another user's vault.
14. [`sharing/give-person-access-to-service.sh`](sharing/give-person-access-to-service.sh) — LEND one service to a person.
15. [`sharing/donate-item-to-host.sh`](sharing/donate-item-to-host.sh) — donate + duplicate rejection.
16. [`weles/`](weles/) — giving Weles a credential, Weles writing one back, remote access.

## Running them

```sh
sh create-skarbiec.sh
sh create-three-skarbiecs.sh
sh build-skarbiec-host.sh ~/.skarbiec-moj.vault.json <port>
```

## Template for a new example

Per `../PRODUCT.md` (CLI design contract + examples requirement):

- shebang + `set -eu`, usage comment at the top,
- plain command sequences — the commands themselves, no helpers,
- `${SKARBIEC_BIN:-skarbiec}` for the binary, env vars for values,
- refuse to overwrite existing files,
- secrets only via env/stdin, never inline,
- before committing: run it and paste the real output.
