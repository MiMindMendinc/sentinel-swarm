## Sentinel Swarm v0.1.1 — Evidence integrity and local-boundary hardening

v0.1.1 repairs the integrity gap in the original demo and hardens every supported boundary without expanding its offensive capability.

### Evidence you can re-check

- The vulnerable fixture is preserved in read-only `before/`; remediation is written separately to `after/`.
- Every event is canonical JSON linked to the previous event digest.
- A manifest records the path, size, and SHA-256 of every required artifact plus the ledger head.
- Missions self-verify before success; retained missions can be checked through the API or offline CLI.
- The returned manifest digest can be retained outside the mission directory for detection of wholesale workspace rewriting.

This is tamper-evident hashing, not cryptographic signing. Signed evidence remains a future capability.

### Safer local boundary

- One fixed `ssh-misconfig` scenario; user text is an operator note, never a command.
- Strict and consistent HTTP/WebSocket schemas.
- Host, WebSocket Origin, body/message, rate, concurrency, wait, and retained-storage limits.
- Loopback-only Compose publication plus non-root/read-only/capability-free container controls and resource/log bounds.
- Strict CSP and security headers, no runtime CDN, no dynamic HTML insertion, and accessibility fixes.

### Supply chain and verification

- Updated FastAPI/Starlette/Uvicorn/Pydantic and test tooling.
- Exact top-level pins plus hash-locked production/development dependency graphs.
- Pinned Python base image digest and GitHub Actions commits.
- CI now runs 45 tests on Python 3.11/3.12 with a 95% coverage floor, Ruff, Bandit, pip-audit, and a container mission + verifier smoke test.

### Quick start

```bash
docker compose up --build
```

Open http://127.0.0.1:7777 and run the built-in mission.
