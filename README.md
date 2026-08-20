<div align="center">

# Sentinel Swarm

**Local AI cybersecurity agents you can actually watch work.**

[![CI](https://github.com/MiMindMendinc/sentinel-swarm/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MiMindMendinc/sentinel-swarm/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MiMindMendinc/sentinel-swarm?display_name=tag)](https://github.com/MiMindMendinc/sentinel-swarm/releases)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![pytest](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)](tests/test_mission.py)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Local First](https://img.shields.io/badge/default-local--first-00c853)](#truthful-scope)

**LOCAL · EVIDENCE-FIRST · REPRODUCIBLE**

<img src="assets/console-verified.jpg" alt="Sentinel Swarm v0.1.0 mission console after a verified SSH hardening run, with backend online, five agent roles, truth mode, and SHA-256 evidence in the mission stream" width="900">

</div>

Sentinel Swarm is an evidence-first, local multi-agent cybersecurity lab. **v0.1.0** is a clone-and-run demo: five named agent roles inspect a real SSH configuration fixture, challenge unsupported claims, apply a hardening patch to an isolated mission copy, verify the result, and write an evidence-backed report.

## 60-second quick start

### Docker

```bash
git clone https://github.com/MiMindMendinc/sentinel-swarm.git
cd sentinel-swarm
docker compose up --build
```

Open **http://localhost:7777** and click **Run verified demo**.

### Python

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest -q
uvicorn app.main:app --reload --port 7777
```

Then open **http://localhost:7777**. Interactive API docs: **http://localhost:7777/docs**.

<p align="center">
  <img src="assets/console-standby.jpg" alt="Sentinel Swarm standing by with backend online, five observable roles, and truth mode showing what is real versus not implemented" width="900">
</p>

## What the verified demo does

1. Copies `range/ssh-misconfig/sshd_config` into a unique mission workspace.
2. `RECON` reads the isolated copy and records evidence.
3. `EXPLOIT-ANALYSIS` explains the configuration risk without inventing a CVE.
4. `THREAT-MODEL` explicitly rejects unsupported claims.
5. `SECURE-CODING` changes `PermitRootLogin yes` and `PasswordAuthentication yes` to `no`.
6. `RECON` re-reads the file and verifies both hardening settings.
7. `REPORT-WRITER` writes `report.md` and the mission persists a six-event `events.jsonl` ledger.

## Truthful scope

| Capability | v0.1.0 |
|---|---|
| Backend-driven mission | Implemented |
| WebSocket live events | Implemented |
| Evidence SHA-256 hashes | Implemented |
| Isolated per-mission workspace | Implemented |
| Real config remediation | Implemented |
| Post-change verification | Implemented |
| Markdown report + JSONL ledger | Implemented |
| Network scanning | Not implemented |
| Arbitrary shell execution | Not implemented |
| Autonomous exploitation | Not implemented |
| Local LLM / Ollama | Planned |
| Swarm replay UI | Planned |

<p align="center">
  <img src="assets/truth-mode.jpg" alt="Truth mode panel: fixture analysis, SHA-256 evidence, remediation, and verification are real; network scanning and arbitrary shell are not implemented" width="420">
</p>

## Verified evidence

These SHA-256 digests are produced from the bundled fixture and are locked by the test suite:

| Artifact | Digest |
|---|---|
| Fixture before patch (`PermitRootLogin yes`, `PasswordAuthentication yes`) | `846a4fa9f53987da218fbda4e242eb07cdbf154c0ff1f027d94cd1fda554fdfa` |
| Isolated copy after verified patch (`PermitRootLogin no`, `PasswordAuthentication no`) | `a144438e493b12fa3c265a4fa87bd762de2d51dfdc1333ccf0dfa376105bba46` |

Each mission also writes `data/<mission_id>/events.jsonl` and `data/<mission_id>/report.md`. Generated workspaces are gitignored.

<p align="center">
  <img src="assets/mission-stream.jpg" alt="Full mission stream showing RECON, EXPLOIT-ANALYSIS, THREAT-MODEL, SECURE-CODING, verification, report writer, and SHA-256 evidence blocks" width="520">
</p>

## Architecture

<p align="center">
  <img src="assets/architecture.png" alt="Sentinel Swarm v0.1.0 architecture: Web UI to FastAPI over HTTP and WebSocket, deterministic mission engine, five observable roles, and an isolated workspace with events.jsonl and report.md" width="900">
</p>

```text
WEB UI  --HTTP/WS-->  FASTAPI  -->  MISSION ENGINE  -->  ISOLATED WORKSPACE
                                         |
                    RECON · EXPLOIT-ANALYSIS · THREAT-MODEL · SECURE-CODING · REPORT-WRITER
                                         |
                              events.jsonl  +  report.md
```

The current "agents" are explicit deterministic roles in the mission engine. A live LLM is **not** required or claimed in v0.1.0.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Lightweight health check |
| `GET /api/status` | Truthful capability state |
| `POST /api/missions` | Run a mission synchronously |
| `WS /ws/mission` | Stream mission events into the UI |
| `GET /docs` | FastAPI interactive API docs |

## Test

```bash
pytest -q
```

The suite verifies the health/status contract, real fixture remediation, documented SHA-256 evidence, report + ledger creation, HTTP validation, WebSocket mission streaming, and WebSocket input limits.

## Project layout

```text
.github/    CI, issue templates, PR template, Dependabot, release workflow
app/        FastAPI control plane + mission engine
assets/     README screenshots and architecture diagram
static/     Sentinel Swarm mission console
range/      safe reproducible demo fixture
data/       generated mission workspaces (gitignored)
tests/      regression tests
docs/       architecture notes and GitHub Release copy
```

## Security

Sentinel Swarm v0.1.0 is a **local safe demo**, not an offensive automation framework. Read [SECURITY.md](SECURITY.md) before extending it with tools that touch real systems.

## Contributing

Contributions are welcome — especially reproducible demo ranges, evidence formats, verification logic, accessibility improvements, and local-model adapters. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

The evidence-first contract comes before autonomy. Planned work includes local model adapters, stronger sandboxing, replay, signed evidence, additional safe ranges, benchmarks, and an agent/tool SDK. See [ROADMAP.md](ROADMAP.md).

## License

MIT — see [LICENSE](LICENSE).
