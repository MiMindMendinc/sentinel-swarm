# Sentinel Swarm Architecture

Sentinel Swarm v0.1.0 is intentionally small, deterministic, and evidence-first. The goal is to prove the control-plane and evidence contract before adding live models or broader tool execution.

## Runtime flow

The README uses a static SVG of this flow (`assets/architecture.svg`) plus live console screenshots.

```text
Browser UI
   │
   ├── GET /api/status
   ├── GET /api/health
   └── WS /ws/mission
          │
          ▼
      FastAPI control plane
          │
          ▼
      Mission engine
          │
          ├── RECON
          ├── EXPLOIT-ANALYSIS
          ├── THREAT-MODEL
          ├── SECURE-CODING
          └── REPORT-WRITER
          │
          ▼
   data/<mission_id>/
          ├── sshd_config
          ├── events.jsonl
          └── report.md
```

## Evidence contract

A user-visible security claim should be traceable to an artifact. In v0.1.0 the artifact is the mission-local copy of the SSH configuration fixture. Evidence records contain:

- a workspace-relative path;
- an optional line reference;
- a SHA-256 digest;
- a short excerpt.

The remediation step produces a new digest. Verification re-reads the patched file instead of assuming that a write succeeded.

## Mission lifecycle

1. Create a unique mission ID and workspace.
2. Copy the bundled fixture into the workspace.
3. Inspect the workspace copy and record pre-change evidence.
4. Analyze and challenge the finding without inventing CVEs or network observations.
5. Apply a minimal patch to the workspace copy only.
6. Re-read the file and verify the required settings.
7. Write a Markdown report.
8. Persist the full six-event JSONL ledger.

## Trust boundaries

### Browser

The browser is a presentation layer. It does not execute system commands. Agent messages are escaped before being rendered into the mission stream.

### FastAPI control plane

The API validates mission input. WebSocket requests use the same Pydantic request model as HTTP mission requests so length and content constraints are consistent.

### Mission workspace

Each run writes only beneath `data/<mission_id>/`. v0.1.0 does not accept arbitrary filesystem paths from the user.

### Container

The Docker image runs as a non-root user. The Compose profile drops Linux capabilities, enables `no-new-privileges`, uses a read-only root filesystem, and mounts a dedicated writable data volume for mission artifacts.

## Explicit non-goals in v0.1.0

The following are deliberately not implemented:

- live network scanning;
- arbitrary shell execution;
- autonomous exploitation;
- remote target support;
- a live LLM or cloud model dependency.

Future adapters should preserve the same evidence contract: claims must remain distinguishable from observations, and actions must produce auditable artifacts and verification results.
