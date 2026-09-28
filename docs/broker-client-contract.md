# Broker-Client Contract Validation

## Overview

The broker and desktop client communicate via HTTP over loopback. The client sends requests to `/v1/operator/*` routes with specific operations that the broker must support.

This check validates that the desktop client only calls credential operations the broker implements, catching integration defects early.

## How It Works

The check extracts:
1. **Supported operations** from `src/net/operator/routes.rs` — the array the broker checks the operation against (`if ![...].contains(&operation.as_str())`)
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
  src/net/operator/routes.rs \
  ../skarbiec-desktop/Sources/SkarbiecDesktop
```

Exit code 0 = all operations valid.  
Exit code 1 = unsupported operations found.  
Exit code 2 = an input is missing, or routes.rs holds no operation list in the expected shape.

## In CI

The check runs as the `broker-client-contract` job in `.github/workflows/ci.yml`, before all other jobs. The `gates` and `evidence` jobs depend on it passing.

## Design Decisions

- **Source-derived, not hand-maintained**: The check extracts directly from both codebases, so it never drifts from the real implementations
- **Precise diagnostics**: Reports include function name, line number, and request context, so reviewers can fix the problem immediately
- **Early gate**: The check runs first in CI, so a developer learns about the mismatch before waiting for the full test suite
- **Separate repositories**: Each repo owns its code; the check runs in the broker's CI to catch any desktop changes that break the contract
