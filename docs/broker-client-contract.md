# Broker-Client Contract Validation

## Overview

The broker and desktop client communicate via HTTP over loopback. The client sends requests to `/v1/operator/*` routes with specific operations that the broker must support.

This check validates that the desktop client only calls credential operations the broker implements, catching integration defects early.

## How It Works

The check extracts:
1. **Supported operations** from `src/net/operator.rs` — the broker's operation validation code
2. **Called operations** from `Sources/SkarbiecDesktop/BackendClient.swift` — what the client sends

It compares them and fails if the client calls any unsupported operation, naming:
- The operation name (e.g., `get`, `totp`)
- The client function that sends it (e.g., `getFieldValue()`)
- The exact file and line number
- The request body context

## Example: Today's Defect

When the client calls `operation: "get"` but the broker only supports `["status", "acquire", "rotate", "resume"]`:

```
❌ BROKER-CLIENT CONTRACT VIOLATION

Unsupported operations in client code:

  Operation: get
    - getFieldValue() at line 325
      var body: [String: Any] = ["operation": "get", "item": itemID]

Broker supports: ['acquire', 'resume', 'rotate', 'status']
Client calls:   ['get', 'resume', 'rotate', 'status']
```

The check fails, and CI cannot proceed until the contract is valid.

## Running Locally

```bash
python3 tools/check-broker-client-contract.py \
  src/net/operator.rs \
  ../skarbiec-desktop/Sources/SkarbiecDesktop/BackendClient.swift
```

Exit code 0 = all operations valid.  
Exit code 1 = unsupported operations found.

## In CI

The check runs as the `broker-client-contract` job in `.github/workflows/ci.yml`, before all other jobs. The `gates` and `evidence` jobs depend on it passing.

## Design Decisions

- **Source-derived, not hand-maintained**: The check extracts directly from both codebases, so it never drifts from the real implementations
- **Precise diagnostics**: Reports include function name, line number, and request context, so reviewers can fix the problem immediately
- **Early gate**: The check runs first in CI, so a developer learns about the mismatch before waiting for the full test suite
- **Separate repositories**: Each repo owns its code; the check runs in the broker's CI to catch any desktop changes that break the contract
