<div align="center">

# Sentinel Swarm

**Local cybersecurity agents you can watch—and independently verify.**

[![CI](https://github.com/MiMindMendinc/sentinel-swarm/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MiMindMendinc/sentinel-swarm/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MiMindMendinc/sentinel-swarm?display_name=tag)](https://github.com/MiMindMendinc/sentinel-swarm/releases)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**LOCAL · EVIDENCE-FIRST · TAMPER-EVIDENT · REPRODUCIBLE**

<img src="assets/console-verified.jpg" alt="Sentinel Swarm mission console after a verified SSH hardening run" width="900">

</div>

Sentinel Swarm **v0.1.1** is a deliberately bounded local lab. Five deterministic agent roles inspect the bundled `ssh-misconfig` fixture, challenge unsupported claims, write a separate hardened configuration, re-read the result, and produce a report plus a verifiable evidence bundle.

The text entered in the UI or API is an **operator note**, not a command or arbitrary task. v0.1.1 never scans a network, runs a shell, accepts a remote target, or invokes a model.

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/MiMindMendinc/sentinel-swarm.git
cd sentinel-swarm
docker compose up --build
```

Open **http://127.0.0.1:7777**. Compose publishes the service on loopback only.

### Python

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip==26.2.1
python -m pip install --require-hashes -r requirements-dev.lock
make test
make run
```

Open **http://127.0.0.1:7777**. The OpenAPI document is available at `/openapi.json`; CDN-backed interactive documentation is disabled.

## What one mission does

1. Creates a private, full-UUID workspace under `data/`.
2. Preserves the vulnerable fixture as read-only `before/sshd_config`.
3. Records the observed lines and SHA-256 digest.
4. Explains the risk without inventing a scan, CVE, or exploit result.
5. Writes the minimal fix to a separate `after/sshd_config`.
6. Re-reads the result and checks that both safe directives are present and unsafe directives are absent.
7. Writes a Markdown report and six-entry hash-chained JSONL ledger.
8. Writes `manifest.json`, anchors it in `manifest.sha256`, and self-verifies the complete bundle before returning success.

Mission files finish read-only (`0400`) inside read-only mission directories (`0500`). This is useful accidental-mutation resistance, not an OS-level immutable flag.

## Evidence bundle

```text
data/<32-character-mission-id>/
├── before/sshd_config
├── after/sshd_config
├── events.jsonl
├── report.md
├── manifest.json
└── manifest.sha256
```

Each ledger entry includes the previous entry digest and its own content digest. The manifest records every artifact's path, size, and SHA-256 plus the ledger head. Verification rejects malformed JSON, duplicate keys, path traversal, symlinks, missing or duplicate artifacts, hash/size mismatches, broken ledger links, invalid event schemas, and unmanifested evidence.

Verify a retained mission through the API:

```bash
curl http://127.0.0.1:7777/api/missions/<mission-id>/verify
```

Or offline, optionally comparing the manifest with a digest retained somewhere outside the mission directory:

```bash
python -m scripts.verify_mission <mission-id>
python -m scripts.verify_mission <mission-id> \
  --expected-manifest-sha256 <digest-returned-when-the-mission-completed>
```

Important: the hash chain is **tamper-evident only relative to a trusted anchor**. A local attacker who can rewrite the entire mission directory can recompute `manifest.sha256`. v0.1.1 does not cryptographically sign evidence; retain the returned manifest digest externally when that threat matters.

## Truthful scope

| Capability | v0.1.1 |
|---|---|
| Fixed built-in SSH fixture | Implemented |
| HTTP and WebSocket mission execution | Implemented |
| Separate before/after artifacts | Implemented |
| SHA-256 manifest + hash-chained ledger | Implemented |
| Independent verifier | Implemented |
| Bounded concurrency, storage, body size, and rate | Implemented |
| Loopback-only Compose publication | Default |
| Security headers and strict CSP | Implemented |
| Network scanning / remote targets | Not implemented |
| Arbitrary shell or tool execution | Not implemented |
| Autonomous exploitation | Not implemented |
| Live LLM or cloud model | Not implemented |
| Cryptographic evidence signatures | Not implemented |

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Lightweight liveness check |
| `GET /api/status` | Scope, limits, storage capacity, and truthful capabilities |
| `POST /api/missions` | Run the fixed built-in scenario synchronously |
| `GET /api/missions/{mission_id}/verify` | Re-verify a retained evidence bundle |
| `WS /ws/mission` | Stream the same validated scenario events to the UI |
| `GET /openapi.json` | Local OpenAPI schema |

All mission inputs use the same strict schema. Unknown fields, unsupported scenarios, non-string notes, whitespace-only notes, and oversized payloads are rejected. WebSockets also enforce same-origin/allowlisted origins.

## Security defaults

- Loopback-only host publication in Compose and the local Make target.
- Non-root container, read-only root filesystem, all capabilities dropped, `no-new-privileges`, PID/CPU/memory limits, and bounded logs.
- Trusted Host enforcement, strict CSP, clickjacking/MIME/referrer/permissions headers, and no runtime CDN dependency.
- Maximum 4 concurrent missions, 500 retained missions, 4 KiB mission messages, and 60 mission starts per client per minute by default.
- Exact direct dependencies, hash-locked transitive dependencies, pinned GitHub Actions commits, pinned container base digest, Ruff, Bandit, pip-audit, and a 95% coverage gate in CI.

Limits can be adjusted with the documented `SENTINEL_*` environment variables in [SECURITY.md](SECURITY.md). Exposing the service beyond loopback is outside the v0.1.1 supported boundary and requires an authenticated, TLS-terminating reverse proxy plus a fresh threat review.

## Validation

```bash
make lint
make test
make audit
```

The suite contains 45 regression and adversarial checks covering evidence preservation, hash-chain verification, tampering, traversal/symlink rejection, strict HTTP/WebSocket parity, body/origin/host/rate/capacity boundaries, concurrency, safe failure mapping, response headers, and DOM injection sinks.

## Project layout

```text
.github/    CI, Dependabot, issue/PR templates, release workflow
app/        FastAPI boundary, mission engine, verifier, schemas
scripts/    Offline mission verifier
static/     Strict-CSP mission console
range/      Safe reproducible fixture
data/       Generated mission workspaces (gitignored)
tests/      Regression and adversarial tests
docs/       Architecture and release notes
```

See [docs/architecture.md](docs/architecture.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [ROADMAP.md](ROADMAP.md) for the operating contract and next steps.

## License

MIT — see [LICENSE](LICENSE).
