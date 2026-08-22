# Sentinel Swarm Architecture

Sentinel Swarm v0.1.1 proves a narrow control-plane and evidence contract before any live model or broader tool execution is added.

## Runtime flow

```text
Browser UI
   │
   ├── GET /api/status
   ├── POST /api/missions
   └── WS /ws/mission
          │
          ▼
  Local FastAPI boundary
  host/origin/body/rate limits
          │
          ▼
  Fixed deterministic scenario
  RECON → ANALYSIS → CHALLENGE → REMEDIATION → VERIFY → REPORT
          │
          ▼
  Private mission workspace
  before + after + report + hash-chained ledger + anchored manifest
          │
          ▼
  Self-verifier / API verifier / offline verifier
```

## Input contract

HTTP and WebSocket use the same strict `MissionRequest` schema:

- `scenario_id` must be exactly `ssh-misconfig`;
- `task` is a normalized 1–500 character operator note;
- unknown fields and non-string notes are rejected;
- message/body size limits apply before mission execution.

The note cannot select a target, scenario, command, path, tool, or network operation.

## Evidence contract

The original fixture is copied to `before/sshd_config` and never patched. The remediation is written to `after/sshd_config`. Evidence paths are workspace-relative and contain a SHA-256 digest, optional line, and excerpt.

Every canonical JSONL ledger record contains:

- a schema version and strict event payload;
- `previous_sha256`, linking it to the prior entry;
- `entry_sha256`, calculated over the complete record except that field.

`manifest.json` records the mission/scenario, completion time, event count, ledger head, and each required artifact's relative path, role, size, and digest. `manifest.sha256` anchors the manifest locally.

The verifier rejects duplicate JSON keys, malformed schema, workspace escapes, symlinks, duplicates, missing files, invalid sizes/hashes, ledger discontinuity, evidence mismatch, unmanifested evidence, or a changed manifest anchor.

## Trust boundaries

### Browser

The browser is presentation only. It uses same-origin HTTP/WebSocket connections, strict CSP-compatible external assets, and DOM `textContent`/node construction for every dynamic value. It never executes agent output as markup.

### API boundary

Trusted Host and WebSocket Origin checks limit browser cross-site access. Mission starts are rate-limited, messages are bounded, work runs off the async event loop, and safe operational errors map to bounded HTTP/WebSocket outcomes. The API has no user authentication, so loopback is part of the supported boundary.

### Mission engine

The engine accepts no user path and generates a full random UUID workspace beneath the configured data root. Capacity is checked under a lock; evidence is never silently evicted. A semaphore bounds concurrent execution.

### Filesystem and evidence

Directories begin private (`0700`) and completed files/directories finish read-only (`0400`/`0500`). Paths are resolved and checked against the workspace before verification. File modes do not protect against the owner or administrator deliberately changing them.

The local manifest sidecar is not a signature. Security against wholesale workspace rewriting requires an externally retained manifest digest or a future signing service.

### Container

Compose publishes loopback only. The process is non-root and the root filesystem is read-only. A dedicated data volume is writable; capabilities are dropped and resource/log limits apply. This boundary has not been designed to run arbitrary hostile code.

## Explicit non-goals

- live network scanning or remote targets;
- shell, arbitrary tools, or autonomous exploitation;
- multi-user authentication/authorization;
- distributed rate limiting or storage;
- live LLM/cloud dependency;
- cryptographically signed evidence.
