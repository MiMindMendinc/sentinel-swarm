# Changelog

## 0.1.0 — 2026-08-19
- Converted the original Sentinel Swarm visual prototype into a FastAPI-backed local demo.
- Added WebSocket mission streaming with validated inputs and safe failure states.
- Added five-role evidence-first mission pipeline.
- Added isolated per-mission copies of a reproducible SSH configuration fixture.
- Added real remediation, re-read verification, SHA-256 evidence, Markdown reports, and JSONL event ledgers.
- Added `/api/health`, truthful `/api/status`, and interactive FastAPI docs.
- Added non-root Docker packaging, read-only Compose runtime, dropped Linux capabilities, `no-new-privileges`, and container healthchecks.
- Expanded regression coverage to HTTP validation and WebSocket input limits.
- Added Python 3.11/3.12 GitHub Actions CI, Dependabot, issue templates, PR template, security/contribution docs, and a polished badge-rich README.
- Replaced the README Mermaid architecture block with a static SVG so GitHub does not stall on a loading state.
- Added v0.1.0 GitHub Release notes and a tag-triggered release workflow.
- Added `.dockerignore` and a Makefile for common developer workflows.
- Removed the Google Fonts network dependency from the runtime UI.
