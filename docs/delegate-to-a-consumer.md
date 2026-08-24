# Delegate to a consumer

An operator holding the owner key can read everything; the whole point of a
consumer is that it cannot. This page is the decision guide: which of the
four delegation shapes fits, and the exact provisioning steps for each. The
mechanics live in [grants and consumers](grants-and-consumers.md), the token
taxonomy in [capability token](concepts/capability-token.md).

## Decide first

| The delegate is… | Use | Standing secret held |
| --- | --- | --- |
| A service reading the same field for months | Standing bearer | One opaque bearer |
| A workload that borrows a field at execution time | Acquisition identity | None — an Ed25519 private key signs per borrow |
| A browser flow that must type a secret it may never hold | Brokered capability | None — the secret crosses one socket, once |
| A person | Recipient sharing, never a grant | Their own `gpg` key |

Two rules cut across all four:

- One consumer, one purpose. Two processes that need different fields are
  two consumers ([consumer](concepts/consumer.md#invariants)).
- A grant answers "may this identity act on this item#field" and nothing
  else; which caller may use which model or provider is the consuming
  product's policy, not a Skarbiec capability
  ([grants and consumers](grants-and-consumers.md#grants-are-not-model-policy)).

## Path 1: standing bearer

For a long-lived service with a stable, narrow read set.

```sh
skarbiec token-mint ci-deployer --capabilities 'read:deploy-token#token' [--ttl-seconds n]
```

1. The mint response carries `"token"` exactly once; hand it to the service.
   The vault keeps only its SHA-256 hash
   ([grant](concepts/grant.md#stored-shape)).
2. The service presents `X-Consumer: ci-deployer` and
   `Authorization: Bearer <token>` on `POST /v1/items/read`
   ([HTTP API](http-api.md#items)).
3. Widen later with the idempotent
   `token-ensure-read ci-deployer <item> --field <field> --token-file <path>`
   — re-minting a different capability set is refused without
   `--replace-capabilities true`
   ([grant](concepts/grant.md#composition-rules)).
4. End it with `token-revoke ci-deployer`.

Choose the narrowest actions that exist: `read` for values, `trash` for
soft-delete, `stage`/`rotate`/`verify` only for lifecycle writers,
`introspect` for a gateway that must classify inbound bearers.

## Path 2: acquisition identity

The default machine path: nothing standing to steal. The workload keeps an
Ed25519 private key; the vault keeps the public half.

```sh
# workload side, once — and mode 0600, or the mint is refused with
# "workload public key must be an owner-controlled regular file":
openssl genpkey -algorithm ED25519 -out workload-private.pem
openssl pkey -in workload-private.pem -pubout -out workload-public.pem
chmod 600 workload-private.pem workload-public.pem

# operator side, once — either form:
skarbiec token-mint report-builder --capabilities 'acquire:analytics-db#password' \
  --workload-public-key-file workload-public.pem
skarbiec invite analytics-db --field password --for report-builder \
  --workload-public-key-file workload-public.pem   # also returns a non-secret redemption contract
```

Per borrow, the workload signs
`SKARBIEC-WORKLOAD-ACQUISITION\0v1\0<consumer>\0<item>\0<field>\0<workload_id>\0<timestamp>\0<nonce>`
and exchanges it for a one-use bearer (TTL
`SKARBIEC_ACQUISITION_TTL_SECONDS`, 1–300 s, default 30):
`acquisition-request` then `acquisition-read`, or `POST /v1/acquisitions`
then `POST /v1/acquisitions/read`. Replay, expiry, revocation, and every
binding mismatch answer the same uniform `unauthorized` — executed end to
end, with the refusals, in
[the acquisition walkthrough](walkthrough-acquisition-broker.md).

Constraints that keep this path honest
([grant](concepts/grant.md#composition-rules)):
`acquire capabilities cannot share a grant with direct capabilities`,
`acquire capabilities require --workload-public-key-file`, and
`acquire capabilities cannot use --token-file`. Bulk registration for a
catalog of items is `token-register-acquisitions <absolute-catalog>
--workload-public-key-file key.pem`.

## Path 3: brokered capability

For a browser trajectory that must fill a form and never see, hold, or log
the secret. Two tables cooperate:

1. **Route the resource.** The workload asks for a name, never an item:

   ```sh
   skarbiec routes add --resource 'origin:https://example.test/password' \
     --item example-login --field password --reason 'browser fill for example.test'
   skarbiec routes verify        # names any route that cannot deliver
   ```

   `routes reconcile` derives the standard `provider:*` and `agent:*`
   routes from the vault without guessing
   ([CLI reference](CLI.md#capability-routes)).
2. **Issue and serve.** `capability-issue --agent <a> --purpose <p>
   --resource <r> --target <t> [--ttl s] [--max-uses n]` records the
   promise (TTL 1–3600 s, default 600; uses 1–16); `capability-serve
   --socket <path>` answers `skarbiec.redeem.v1` redemptions with an
   Ed25519 proof per read. Every denial is one opaque refusal on the wire
   while the journal records the reason
   ([capability token](concepts/capability-token.md#brokered-capability-capability-broker)).

## Path 4: a person is never a consumer

People decrypt; services present bearers. Give a human access by
registering their `gpg` key and re-encrypting the item to them:

```sh
skarbiec add-user 'Alice <alice@example.test>' --import alice.pub
skarbiec share <item-id> alice
skarbiec revoke <item-id> alice        # re-encrypts to the remaining group
```

Time-delayed break-glass access for a human is `emergency-grant`
([CLI reference](CLI.md#recovery-and-emergency-access)) — recipient
sharing with a delay, not a capability.

## Revoking, observing, repairing

- `token-revoke <consumer>` ends every token shape at once: the standing
  bearer, future acquisitions, and broker redemptions all check the live
  grant entry per call — there is no session to outlive it.
- `tokens` lists every grant with expiry and `workload_bound`;
  `token-verify` checks one exact binding; `audit-query --consumer <name>`
  is the consumer's trail ([WORM audit](concepts/worm-audit.md)).
- An item a dead consumer controlled is repaired with `reclaim <id>`
  ([grants and consumers](grants-and-consumers.md#reclaim-repairing-an-item-with-no-writer)).
