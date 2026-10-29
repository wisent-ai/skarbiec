# Broker-Client Contract Validation

## Overview

The broker and desktop client communicate via HTTP over loopback. The client sends requests to `/v1/operator/*` routes with specific operations that the broker must support.

This check validates that the desktop client only calls credential operations the broker implements, catching integration defects early.

## Access request routes

The broker also serves the access request register (docs/design/access-requests.md) to a console. These routes are not credential operations, so the check below does not compare them; a client calling them sends exactly these bodies:

| Route | Body | Answer |
| --- | --- | --- |
| `POST /v1/operator/requests` | `{"state"?: "pending"\|"approved"\|"denied"\|"withdrawn"}` | the `request list` array |
| `POST /v1/operator/requests/approve` | `{"id", "by", "ttl-seconds": N \| "until-revoked": true, "uses"?: N}` | the `request approve` answer: `status` `granted` or `awaiting-second-decider` |
| `POST /v1/operator/requests/deny` | `{"id", "by", "reason"?}` | `{"ok", "request_id", "state": "denied"}` |

`by` names the deciding recipient; the broker refuses anyone who is not an `owner` or `admin` recipient with their secret key in this host's keyring, and an approval that states no lifetime. Approve and deny are mutations and take the listener's write lock.

## How It Works

The check extracts:
1. **Supported operations** from `src/net/operator/credential.rs` — the variants of the `Operation` enum the broker deserializes the request's `operation` into, in the kebab-case its `#[serde(rename_all = "kebab-case")]` reads them by
2. **Called operations** from every Swift file under `Sources/SkarbiecDesktop` — each literal `"operation": "<name>"` the client sends

It compares them and fails if the client calls any unsupported operation, naming the operation, the client function that sends it, and the file and line:

```
BROKER-CLIENT CONTRACT VIOLATION: the client sends operations the broker refuses
  get: getFieldValue() at Sources/SkarbiecDesktop/BackendClient/BackendClient+Status.swift:112
broker serves: acquire,resume,rotate,status
client sends:  get,resume,rotate,status
```

The check fails, and CI cannot proceed until the contract is valid. An operation the client passes as a variable (`["operation": operation, ...]`) is not a literal and is not counted.

## Running Locally

```bash
tools/check-broker-client-contract.sh \
  src/net/operator/credential.rs \
  ../skarbiec-desktop/Sources/SkarbiecDesktop
```

Exit code 0 = all operations valid.  
Exit code 1 = unsupported operations found.  
Exit code 2 = an input is missing, or credential.rs holds no kebab-case `Operation` enum.

## In CI

The check runs as the `broker-client-contract` job in `.github/workflows/ci.yml`, before all other jobs. The `gates` and `evidence` jobs depend on it passing.

## Design Decisions

- **Source-derived, not hand-maintained**: The check extracts directly from both codebases, so it never drifts from the real implementations
- **Precise diagnostics**: Reports include function name, line number, and request context, so reviewers can fix the problem immediately
- **Early gate**: The check runs first in CI, so a developer learns about the mismatch before waiting for the full test suite
- **Separate repositories**: Each repo owns its code; the check runs in the broker's CI to catch any desktop changes that break the contract
