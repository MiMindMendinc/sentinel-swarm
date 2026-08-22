# Changelog

## 0.1.1 — 2026-08-22
- Preserved separate read-only before/after evidence so every recorded digest still matches its referenced artifact.
- Added canonical hash-chained ledger entries, artifact manifest/anchor, mission self-verification, a verifier API, and an offline verifier with external-anchor comparison.
- Made HTTP and WebSocket input semantics strict and identical; the only supported scenario is now explicit and user text is truthfully labeled an operator note.
- Added body/message/host/origin/rate/concurrency/storage limits and safe HTTP/WebSocket failure mappings.
- Added strict CSP and security headers, removed CDN-backed documentation, eliminated dynamic HTML sinks, and fixed landmark/keyboard accessibility issues.
- Bound Compose to loopback and added container PID/CPU/memory/tmpfs/log bounds while retaining the non-root, read-only, capability-free runtime.
- Updated vulnerable/outdated packages, added exact and hash-locked dependency sets, pinned the base image and GitHub Actions by digest/commit, and added Docker Dependabot coverage.
- Expanded the suite from 5 to 45 regression/adversarial tests with an enforced 95% application coverage floor, Ruff, Bandit, pip-audit, and independently verified container smoke tests.
- Documented the evidence trust model: local hashes are not signatures, and wholesale tampering requires comparison with an externally retained manifest digest.

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
- Replaced the README Mermaid architecture block with a static PNG diagram GitHub can render on mobile and desktop.
- Documented and test-locked the bundled fixture SHA-256 digests.
- Added v0.1.0 GitHub Release notes and a tag-triggered release workflow.
- Added `.dockerignore` and a Makefile for common developer workflows.
- Removed the Google Fonts network dependency from the runtime UI.
