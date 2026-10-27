# Acquisition walkthrough

The acquisition walkthrough is executable rather than a transcript that can drift.
From a source checkout with `skarbiec` installed, it creates a disposable vault,
an isolated GPG keyring, and an Ed25519 workload identity. It stores only the
literal non-secret value `not-a-secret`.

```sh
SKARBIEC_BIN=<the installed skarbiec> \
SKARBIEC_EXAMPLE_DIR=<a directory that does not exist yet> \
  sh docs/examples/acquire-one-field.sh
```

The script performs the product's defining path:

1. create a vault and item;
2. register `demo-workload` for exactly `demo-note#value`, with no standing
   bearer;
3. sign a timestamped, nonced acquisition request with the workload key;
4. consume the issued capability once;
5. retry the same capability and receive `unauthorized`;
6. print the matching audit records.

Setup commands also print JSON. The decisive first read and replay have these
output shapes:

```json
{
  "consumer": "demo-workload",
  "field": "value",
  "item": "demo-note",
  "ok": true,
  "value": "not-a-secret"
}
{
  "error": "unauthorized",
  "ok": false
}
```

The registration output has `workload_bound: true`, `token: null`, and one exact
`acquire` capability. The final audit query contains `acquisition-issued` and
`acquisition-consumed`; it never contains the field value, signature, public
key, or one-use token.

`POST /v1/acquisitions` answers Bad Request when a required request member is
missing, the id or field is empty, or the timestamp is not an unsigned integer.
Supplied item, field, or workload values that fail exact-name or workload-proof
validation answer Unauthorized with `{"error":"unauthorized"}`, as do an absent
consumer, a missing or ended acquisition grant, a timestamp after now or older
than the workload's newest spent proof, or a replay.
After the workload has proved its identity, a field that the item does not
carry answers Not Found with `{"error":"acquisition field does not exist on item"}`.
Other issuance failures answer Service Unavailable with `{"error":"infra_down"}`.
The missing-field distinction is therefore available to an authorized workload
without exposing field existence to an unproved caller.

The script refuses to overwrite an existing demo directory. Remove the
directory named in `SKARBIEC_EXAMPLE_DIR` when finished.

For a real vault, first follow
[the recovery boundary](https://skarbiec.wisent.com/docs/security#recovery-and-rotation), move the
recovery private material to its custodian, and verify it with
`recovery drill`. Store real values through stdin, as shown in
[the executable examples](https://skarbiec.wisent.com/docs/examples), and register new
workloads through acquisition rather than a legacy direct bearer.
