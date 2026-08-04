# Examples — skarbiec in practice

Executable examples as **plain command sequences** — the commands
themselves, no scaffolding. Each script is runnable end-to-end and refuses
to overwrite existing vault files.

## Command surfaces — which tool for what

- **New workload access** — workload-bound one-use acquisition through
  `token-mint --capabilities acquire:item#field`, `acquisition-request`, and
  `acquisition-read`. This is the default for a new machine integration.
- **Vault creation, multi-vault work, owner rotation, recovery exports, and
  service access** — use the `skarbiec` CLI and loopback broker directly.
- **One vault.** Workload separation is enforced by exact capabilities and
  recipient policy, not by another product's configuration namespace.
- **Sync (bond)** — `pull` / `sync-init`+`sync-push`/`sync-pull` /
  `enroll` / `donate` + `donations` / `sync-daemon` / `sync-status`.

## Index

1. [`acquire-one-field.sh`](acquire-one-field.sh) — register an Ed25519 workload, consume one exact field once, prove replay fails, inspect audit.
2. [`create-skarbiec.sh`](create-skarbiec.sh) — init, first item, read-back, status.
3. [`create-three-skarbiecs.sh`](create-three-skarbiecs.sh) — three vaults, isolation proof.
4. [`rotate-skarbiec-owner.sh`](rotate-skarbiec-owner.sh) — backup, rotate-owner, verify.
5. [`operations/build-skarbiec-host.sh`](operations/build-skarbiec-host.sh) — init, grants, serve, health.
6. [`operations/change-skarbiec-host.sh`](operations/change-skarbiec-host.sh) — pull to a new host, serve.
7. [`git/git-sync-two-hosts.sh`](git/git-sync-two-hosts.sh) — two vaults through a bare git remote.
8. [`bond/enroll-replica.sh`](bond/enroll-replica.sh) — replica enroll handshake.
9. [`bond/donation-inbox.sh`](bond/donation-inbox.sh) — donate, review in remote inbox.
10. [`bond/invite-person.sh`](bond/invite-person.sh) — register one workload-bound, one-field acquisition contract.
11. [`sharing/share-credential-with-user.sh`](sharing/share-credential-with-user.sh) — GIVE to another user's vault.
12. [`sharing/donate-item-to-host.sh`](sharing/donate-item-to-host.sh) — donate + duplicate rejection.

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
