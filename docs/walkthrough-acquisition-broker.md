# Walkthrough: the acquisition broker, CLI and HTTP

The product's defining path — borrow one field once, with no standing
secret — executed on 2026-08-24 against a disposable vault and a source
build, over both surfaces: the CLI and the loopback broker
(`skarbiec serve`). Every block is pasted output; the demo values are not
secrets. The scripted single-command version is
[`examples/acquire-one-field.sh`](examples/acquire-one-field.sh).

## Setup

```sh
export HOME=/tmp/skarbiec-wt-acq2
export GNUPGHOME=/tmp/skarbiec-wt-acq2/gnupg
export SKARBIEC_VAULT_FILE=/tmp/skarbiec-wt-acq2/demo.vault.json
export SKARBIEC_AUDIT_FILE=/tmp/skarbiec-wt-acq2/demo.audit.jsonl
```

```text
$ skarbiec init demo-owner
{ "ok": true, "vault": "/tmp/skarbiec-wt-acq2/demo.vault.json", ... }

$ skarbiec set demo-note --type note value=not-a-secret
{ "id": "demo-note", "kind": "note", "ok": true }

$ skarbiec set demo-other --type note value=also-not-a-secret
{ "id": "demo-other", "kind": "note", "ok": true }
```

Generate the workload's Ed25519 identity. The first mint attempt teaches
the file contract — `openssl` writes group-readable files, and Skarbiec
refuses them:

```text
$ openssl genpkey -algorithm ED25519 -out workload-private.pem
$ openssl pkey -in workload-private.pem -pubout -out workload-public.pem
$ skarbiec token-mint demo-workload --capabilities 'acquire:demo-note#value' \
    --workload-public-key-file workload-public.pem
Error: workload public key must be an owner-controlled regular file

$ chmod 600 workload-public.pem workload-private.pem
$ skarbiec token-mint demo-workload --capabilities 'acquire:demo-note#value' \
    --workload-public-key-file workload-public.pem
{
  "audience": "demo-workload",
  "capabilities": [{"action": "acquire", "field": "value", "item": "demo-note"}],
  "consumer": "demo-workload",
  "expires_at": 1790202978,
  "ok": true,
  "token": null,
  "workload_bound": true
}
```

`"token": null` is the point: an acquisition grant stores a public key and
returns no standing bearer ([grant](concepts/grant.md)). One direct-bearer
consumer is minted alongside for the HTTP comparison — its bearer is
returned exactly once:

```text
$ skarbiec token-mint demo-reader --capabilities 'read:demo-note#value'
{ ..., "token": "9dc79c88ff5ea227...", "workload_bound": false }
```

## Signing a proof

Each borrow signs the domain-separated payload with the private key
([capability token](concepts/capability-token.md#one-time-acquisition-bearer)):

```sh
TS=$(date +%s)
NONCE=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')   # exactly 43 base64url chars
printf 'SKARBIEC-WORKLOAD-ACQUISITION\0v1\0%s\0%s\0%s\0%s\0%s\0%s' \
  demo-workload demo-note value wt-workload "$TS" "$NONCE" > payload.bin
SIG=$(openssl pkeyutl -sign -inkey workload-private.pem -rawin -in payload.bin \
      | od -An -tx1 | tr -d ' \n')                              # 128 hex chars
```

## CLI leg: issue, consume, replay

```text
$ skarbiec acquisition-request demo-workload demo-note value \
    --workload-id wt-workload --workload-timestamp "$TS" \
    --workload-nonce "$NONCE" --workload-signature "$SIG"
{
  "consumer": "demo-workload",
  "expires_at": 1787611039,
  "field": "value",
  "item": "demo-note",
  "ok": true,
  "token": "634117b40cc2313866075f036b9afc04eac6a62f7b76c580c53d36c996c19509"
}

$ skarbiec acquisition-read demo-workload demo-note value --token <issued>
{
  "consumer": "demo-workload",
  "field": "value",
  "item": "demo-note",
  "ok": true,
  "value": "not-a-secret"
}

$ skarbiec acquisition-read demo-workload demo-note value --token <issued>   # replay
{
  "error": "unauthorized",
  "ok": false
}
```

The bearer is consumed atomically on first read; the replay is refused with
the same uniform `unauthorized` every failed check answers — a caller never
learns which check it failed.

## HTTP leg

Start the loopback broker and repeat with a fresh proof
([HTTP API](http-api.md#acquisitions)):

```text
$ skarbiec serve --port 8971 &
skarbiec API listening on http://127.0.0.1:8971 (loopback only)

$ curl -X POST http://127.0.0.1:8971/v1/acquisitions -H 'X-Consumer: demo-workload' \
    -d '{"id":"demo-note","field":"value","workload_id":"wt-workload",
         "workload_timestamp":'$TS',"workload_nonce":"'$NONCE'","workload_signature":"'$SIG'"}'
{"consumer":"demo-workload","expires_at":1787611039,"field":"value","item":"demo-note","token":"96c7abe2636a426b..."}

$ curl POST /v1/acquisitions/read   # with 'Authorization: Bearer <one-time token>'
{"consumer":"demo-workload","field":"value","item":"demo-note","value":"not-a-secret"} [200]

$ curl POST /v1/acquisitions/read   # replay
{"error":"unauthorized"} [401]
```

No standing bearer travels on the issue request — `X-Consumer` plus the
proof fields is the whole authentication.

## The direct bearer, authorized and not

The reader's grant names `demo-note#value` exactly; anything else is `403`,
and an unauthorized item is indistinguishable from an unauthorized field
([field](concepts/field.md#existence-is-checked-at-every-boundary)):

```text
$ curl POST /v1/items/read  {"id":"demo-note","field":"value"}    # granted
{"field":"value","id":"demo-note","value":"not-a-secret"} [200]

$ curl POST /v1/items/read  {"id":"demo-other","field":"value"}   # not granted
{"error":"consumer not authorized to read item field"} [403]
```

A trashed item answers `410 Gone` with the way out in `detail`
([trash and purge](concepts/trash-and-purge.md)):

```text
$ skarbiec delete demo-note
$ curl POST /v1/items/read  {"id":"demo-note","field":"value"}
{"detail":"restore it first: skarbiec restore demo-note","error":"item is in trash","error_code":"not_found"} [410]
$ skarbiec restore demo-note
```

## Revocation kills a valid proof

After `token-revoke`, even a fresh, correctly signed proof answers
`401 unauthorized` — the grant entry is gone, and an unknown consumer and an
expired one are indistinguishable ([grant](concepts/grant.md#stored-shape)):

```text
$ skarbiec token-revoke demo-workload
{ "consumer": "demo-workload", "ok": true }

$ curl -X POST http://127.0.0.1:8971/v1/acquisitions ...   # fresh signature, new nonce
{"error":"unauthorized"} [401]
```

## The journal names both legs

```text
$ skarbiec audit-query --consumer demo-workload --limit 4
{
  "matched": 4,
  "returned": 4,
  "ops": ["acquisition-issued", "acquisition-consumed",
          "http-acquisition-issued", "http-acquisition-consumed"]
}
```

Item, field, consumer, and workload id are journalled; the value never is
([WORM audit](concepts/worm-audit.md)).

## Cleanup

```sh
kill %1                       # the serve process
rm -rf /tmp/skarbiec-wt-acq2
```

One observed footgun: killing `serve` mid-append can leave
`demo.audit.append.lock` behind; the next writer clears it after the
30-second abandonment window ([runbook](runbook.md#audit-journal-lock-is-still-held)).
