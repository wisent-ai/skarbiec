# Kind

Why does the vault refuse a perfectly good secret because it has the wrong
field name? Because a kind is a contract about shape, and shape is what
downstream readers enumerate: a `login` is what browser-fill trajectories
iterate, so a machine root account must not be one. This page is the exact
validation contract in `src/core/schema.rs`; the reasoning is in
[the item model](../item-model.md#kinds).

## The fifteen kinds

Every payload is one JSON object validated against `skarbiec.item.v2`.
Allowed top-level properties are `schema`, `kind`, `fields` (non-empty
object), `context` (required object), and optional `extensions`
(`validate_payload`).

| Kind | Allowed fields | Required |
| --- | --- | --- |
| `login` | `username`, `password`, `totp_secret`, `recovery_codes` | `username`, plus at least one authentication factor |
| `host-account` | `username`, `password` | both, plus `context.account_ref` naming `<user>@<host>` |
| `note` | `value` | `value` |
| `api-key` | `api_key`, `api_user`, `username`, `client_ip` | `api_key` |
| `access-key` | `access_key_id`, `secret_access_key`, `session_token` | `access_key_id`, `secret_access_key` |
| `token` | `token` | `token` |
| `oauth-client` | `client_id`, `client_secret` | both |
| `proxy` | `username`, `password`, `host`, `ports`, `zone` | `username`, `password` |
| `key-pair` | `private_key`, `public_key`, `passphrase`, `key_id`, `issuer_id`, `team_id` | `private_key` |
| `certificate` | `certificate`, `private_key`, `chain`, `passphrase` | `certificate`, `private_key` |
| `service-account` | `credential_json` | `credential_json` |
| `credential-operation` | free-form names | `value` |
| `bundle`, `stado-secret`, `internal-authority` | free-form names | none |

Field values must be strings, with exactly three exceptions: `ports`,
`recovery_codes`, and `chain` may be arrays; `credential_json` may be an
object. The free-form kinds accept any value type and any field whose name is
1–128 ASCII characters from `[A-Za-z0-9._-]` (`exact_component`).

## Refusals, verbatim

Validation runs on every `set`, `set-json`, `import`, decryption, and grant
mint that names a field. Each refusal is one sentence:

```text
unsupported canonical item kind: <kind>
canonical item payload must be an object
unknown canonical item property: <key>
canonical item schema must be skarbiec.item.v2
payload kind does not match the item envelope kind
canonical item fields must be an object
canonical item fields cannot be empty
field <name> is not allowed for <kind>
<kind> field <name> has an invalid value type
invalid logical field name: <name>
<kind> payload requires fields.<name>
login payload requires at least one authentication factor
host-account payload requires context.account_ref naming <user>@<host>
canonical item context must be an object
canonical item extensions must be an object
```

## Why `host-account` is not a `login`

The two kinds carry the same members and stay deliberately disjoint. The
comment above `HOST_ACCOUNT_FIELDS` states the invariant: host-placement and
host-repair readers iterate `login` items never; browser trajectories iterate
`login` items only. Overloading `login` would hand a machine root account to
a browser form fill. `host-account` is also the one kind that constrains its
context, because an account credential that does not name `<user>@<host>`
cannot be matched to the host it opens (`validate_payload`).

## Kind versus type flag

`set --type <t>` defaults to `login`. `set-json --type <t>` overrides the
payload's `kind` only when both describe the same valid schema — the payload
is re-validated against the flag, so a mismatch answers
`payload kind does not match the item envelope kind`. Decryption re-validates
too: a stored payload that no longer matches its envelope kind fails the read
rather than returning a half-valid object (`src/core/vault.rs::get_item`).

## Not to be confused with

- **A tag.** A kind states what shape a secret has; what it is *for* belongs
  in [tags](tag.md).
- **A schema version.** `skarbiec.item.v2` is the payload schema; the
  envelope's `format` is a separate version, and a legacy envelope is refused
  with `run migrate-v2` everywhere it is touched ([item](item.md)).
- **A field.** The kind constrains which [fields](field.md) may exist; access
  is granted per field, not per kind.
