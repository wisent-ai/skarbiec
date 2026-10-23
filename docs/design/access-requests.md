# Access requests: an agent asks, a person decides, Skarbiec grants

Status: accepted by Zuzanna (2026-10-22). Implemented in Skarbiec (delivery step 1) and Las (step 2); steps 3–5 belong to Oko, Tama and Most. Decisions below are settled.

## Problem

Agents working for a person regularly hit something they are not allowed to do on their own:

- a **secret or account**: a provider key for Jeden, the Oko database fields, a Wisent account session for `oko login`;
- a **device permission**: installing Tama hooks into omp, adding a test target (`tama tests approve`), a cloud action;
- a **membership**: being added to a Wisent organization, or to another person's vault.

Today each case ends with the agent printing a command and asking the person to run it in their own terminal. Nothing records the request, nothing reaches the person when they are away from the machine, and a colleague's agent has no way to ask Zuzanna (or anyone else) for access at all.

## Goal

One flow, shared by every Wisent product and every agent harness:

1. An agent files a **request**: what (exact resource and action), why (free text), for whom (agent identity), and who should decide.
2. The **decider** gets it where they are (Oko Desktop, Oko iOS, the channels `oko contact set` configures) and answers approve or deny. The decider states the lifetime and number of uses when approving; no product picks them.
3. On approval, the product that owns that kind of authority **issues the grant**, bound to the request id. On denial, nothing changes. Both answers are journaled.
4. The agent learns the outcome through the same surface it asked on.

## What already exists (and is reused, not duplicated)

| Need | Existing piece | Where |
|---|---|---|
| Owner-side pending queue with accept/reject | donation inbox | `skarbiec/src/core/inbox.rs` |
| Grant bound to an approval id | `grant capability --authorization-id`, signed into the redemption proof | `skarbiec/src/access/capability/issue.rs`, `redeem/request.rs` |
| Tamper-evident record | hash-chained audit journal | `skarbiec/src/runtime/audit/journal.rs` |
| Asking a person on any channel and waiting | `oko asks ask/wait/answer` | `oko/rust/src/asks/` |
| Device permissions | Tama session capabilities and consents | `tama-hooks` `session_capability`, `owner_consent` |
| One MCP endpoint for all agents | Las, Skarbiec boundary (broker v1) | `las/src/registry/` |

## Design

### 1. Skarbiec owns the request register

Skarbiec is the only component that already holds grant authority and an audit chain, so the register lives there.

- New owner-only file `<vault>.requests.json`, structured like the donation inbox: `{id (UUID), requested_at, requester {agent, harness, host, person}, kind (secret|device|membership), resource, action, reason, decider, state (pending|approved|denied|withdrawn), decision {by, at, lifetime, uses}}`.
- CLI group `skarbiec request file|list|show|approve|deny|withdraw`. `approve` takes the lifetime and use count from the decider (`--until-revoked` or `--ttl-seconds`, `--uses`); no default.
- Operator routes `/v1/operator/requests`, `/approve`, `/deny` (updates the skarbiec-desktop broker contract check).
- Audit ops `access-requested`, `access-approved`, `access-denied`, `access-withdrawn`.
- Cross-host: `POST /v1/access-requests` on the owner's `skarbiec serve`, gated by a new exact grant action `request:<scope>` (same pattern as `donate:<item>`), so a colleague's vault host can file into Zuzanna's register without any other authority.

### 2. Granting, by kind

| Kind | Who issues on approval | How the agent uses it |
|---|---|---|
| secret / service account | Skarbiec `grant capability --authorization-id <request id>` (single use) or `grant issue` (standing consumer grant) | `stado credentials get --role …` or Las `capability_request`, exactly as Oko and Most already read credentials |
| device permission | Tama: an Oko ruling `capability:<tool>[:<action>]@session:<id>`, which Tama already honours (needs Oko's ruling recorder to accept that subject) | the hook allows the action for that session |
| membership | the existing owner of that membership (Wisent org roles in `organization_members`; `skarbiec recipient add` + `share` for a vault) | normal login / normal vault access |

Skarbiec records every decision even when another product issues the grant, so there is one history of who asked for what and who said yes.

### 3. Reaching the decider: `oko asks`

- Skarbiec files an ask on approval request: `oko asks ask --from skarbiec --subject skarbiec-request:<id> --question … --detail … --choice approve --choice deny`. Deduplication, delivery to Desktop/iOS/Stado channels and Realtime waiting already exist.
- The vault host (signed into Oko as the decider) runs the watcher (`oko asks wait`) and applies the answer through `skarbiec request approve|deny`. Lifetime and uses are asked as part of the approval (a second ask with the decider's options, or Oko Desktop's free-text answer).
- **Required Oko change:** an ask can only be addressed to the signed-in user today (RLS `user_id = auth.uid()`). Add an `addressee` (Wisent user id) column and policy in `wisent-supabase-oko`, and `--to <person>` in `oko asks`, limited to members of the same organization.
- **Local fallback** when Oko is not available on the vault host (no Wisent session yet): a native dialog on the vault host's screen, shown by `skarbiec request watch --local`. This is how the very first request (for the Oko session itself) is answered.
- **Reply by message (later):** a Most webhook → `oko asks answer` bridge lets the decider approve by replying to an iMessage/SMS. Not needed for the first version.

### 4. Agents reach it through Las

- Skarbiec's MCP server implements Las broker v1 (`health`, `capability_available`, `capability_request`) — Las already pins those names; Skarbiec does not serve them yet.
- `capability_request` may answer `{status: "pending", request_id}` when no grant exists, filing a request instead of failing; plus a new `access_request_status {request_id}` tool. Las registry: schema digests, descriptions, argument and result validators, `allowTools`, docs, and a newly signed manifest with a higher sequence.
- Fix the Las Skarbiec surface command (it points at `entitlements-rotator/…`, which is not in the workspace).
- **Identity:** Las requires `initialize.params.agentId` when the Skarbiec surface is active, which omp, Claude Code and Codex do not send. Proposed: Las takes the identity from its own operator-provided environment (`SKARBIEC_MCP_AGENT_ID`) when the client sends none, so the operator, not the model, states which agent this is.
- Oko: add a read-only `oko` surface to Las later so agents can see their open requests in one catalogue.

### 5. Many people in wisent-ai

- Every request names a decider: a person (Wisent user) or a role in the organization (`owner`, `admin`).
- A person decides only for resources they own: their vault items, their device, organizations where they hold the role. Skarbiec refuses `approve` from anyone else.
- A colleague's agent files into the decider's register through `POST /v1/access-requests`; it never receives the decider's secrets, only the grant the decider issues.
- The register and the audit chain stay on the decider's vault host. The planned Hosted Hub can later mirror them for the organization; nothing here depends on it.

## Delivery plan (each step lands through a PR in its repo)

1. **Skarbiec**: register, CLI, operator routes, audit ops, local dialog watcher; broker v1 in MCP. Tests registered per the repo's `tama tests approve` policy.
2. **Las**: Skarbiec boundary for broker v1 + request tools, identity from operator env, fixed command; signed manifest procedure documented.
3. **wisent-supabase-oko + Oko**: addressed asks (`--to`), and the ruling subject Tama reads.
4. **Tama**: device-permission requests filed into the register instead of printing commands.
5. **Most** (optional): reply-to-approve bridge.

## Implemented in Skarbiec

- Register `<vault>.requests.json` (mode 0600, flock beside it): `src/access/request/register.rs`. Records carry `{id (UUID v4), requested_at, requester {agent, harness, host, person}, kind, resource, action, reason, decider, dual_control, grant, via, state, decisions [{by, at, answer, lifetime, uses}], issued}`. `grant` is `{form: capability, purpose, target, ttl_seconds, max_uses}` (asked bounds), `{form: consumer, consumer}` or `{form: record}`.
- CLI `skarbiec request file|list|show|approve|deny|withdraw|watch` (`src/access/request/`). `--decider` is `owner`, `admin` (any owner or admin, the default) or one recipient uid. A request is dual-control when filed with `--dual-control` or when its secret resolves to an item tagged `dual-control`.
- Approval issues `grant capability … --authorization-id <request id>` or `grant issue <consumer> --capabilities <action>:<resource> --token-file <owner-only file>`; a consumer that already holds a grant is refused rather than having its bearer replaced. Two approvals of a dual-control request take the narrower lifetime and fewer uses.
- `skarbiec request watch --local --by <uid>`: osascript dialogs; between requests it blocks on the FIFO `<vault>.requests.wake`, which every register write pokes.
- Journal ops `access-requested`, `access-approved` (with `granted`), `access-denied`, `access-withdrawn`, and `access-request-sent` on the filing host.
- Operator routes `/v1/operator/requests`, `/requests/approve`, `/requests/deny`; cross-host `POST /v1/access-requests` gated by `request:secret|device|membership`.
- `skarbiec mcp broker`: exactly `health`, `capability_available`, `capability_request`, `access_request_status`, with the input schemas Las pins. `health` reports `policy_sequence` = the vault document generation, `registry_sequence` = audit journal entries, `anomaly_count` = audit chain faults.
- Runnable proof: `docs/examples/sharing/request-access.sh` (in `sharing/` because `docs/examples/` already holds its five files); refusals: `tests/access/request.sh`.

## Decisions

1. Membership and organization-wide resources are approved by the organization's `owner` and `admin` roles; in a vault, by recipients with role `owner` or `admin`.
2. Las takes the agent identity from its operator-provided environment (`SKARBIEC_MCP_AGENT_ID`) when the client sends no `agentId`.
3. High-authority resources (marked dual-control by their owner, e.g. the Oko `service_role_key`) need two different deciders before the grant is issued.
4. Until the decider has a Wisent account on the vault host, the local dialog is the delivery channel; `oko asks` is used once it is available.
