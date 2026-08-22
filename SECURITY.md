# Security Policy

Sentinel Swarm v0.1.1 is a **local, fixed-scenario demonstration**, not a production security scanner or hardened sandbox for untrusted tools. It operates only on the bundled SSH configuration fixture and does not implement a shell, network scanner, remote target, autonomous exploitation, or model/tool execution.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.1 | Yes |
| 0.1.0 | Upgrade recommended |
| < 0.1 | No |

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Use GitHub private vulnerability reporting / Security Advisories when available. Include the affected version or commit, minimal reproduction, impact, expected behavior, and any suggested mitigation. Do not attach secrets or sensitive target data.

## Supported trust boundary

- Run the UI/API on a trusted local machine.
- Keep the Docker port bound to `127.0.0.1`, as supplied in `docker-compose.yml`.
- Treat the `data/` volume and returned mission paths as sensitive if the fixture or engine is extended.
- Do not expose v0.1.1 directly to an untrusted network. There is no user authentication or authorization layer.
- Do not present an operator note as a command: it is recorded for context but never determines the target or action.

If remote access is required, place Sentinel behind an authenticated TLS reverse proxy, narrowly configure allowed hosts/origins, add authorization and per-user quotas, and perform a new threat review. That deployment is not covered by the v0.1.1 security claim.

## Evidence integrity model

Each mission writes separate before/after artifacts, a hash-chained event ledger, a manifest of artifact paths/sizes/digests, and a manifest digest sidecar. The engine verifies the bundle before returning success, and the API/CLI can verify it again later.

This detects accidental changes and partial tampering. It is not a cryptographic signature. An attacker who can rewrite every file in the mission workspace can recompute the local sidecar. For stronger detection, retain the `manifest_sha256` returned at completion outside the mission directory and pass it to the offline verifier:

```bash
python -m scripts.verify_mission <mission-id> \
  --expected-manifest-sha256 <externally-retained-digest>
```

Read-only modes are defense in depth against accidental mutation, not immutability against the owning OS account or an administrator.

## Default limits

| Environment variable | Default | Allowed range | Purpose |
|---|---:|---:|---|
| `SENTINEL_MAX_MISSIONS` | 500 | 1–100000 | Retained workspace ceiling; old evidence is never auto-deleted |
| `SENTINEL_MAX_CONCURRENT_MISSIONS` | 4 | 1–64 | Mission worker bound |
| `SENTINEL_MISSION_WAIT_SECONDS` | 5 | 0–60 | Wait for a worker slot |
| `SENTINEL_MAX_HTTP_BODY_BYTES` | 4096 | 512–1048576 | HTTP mission body bound |
| `SENTINEL_MAX_WS_MESSAGE_BYTES` | 4096 | 512–1048576 | WebSocket mission message bound |
| `SENTINEL_RATE_LIMIT_REQUESTS` | 60 | 1–10000 | Mission starts per client/window |
| `SENTINEL_RATE_LIMIT_WINDOW_SECONDS` | 60 | 1–3600 | In-memory rate window |
| `SENTINEL_DATA_DIR` | `./data` | local path | Mission data root |
| `SENTINEL_ALLOWED_HOSTS` | local/test hosts | comma-separated | Trusted Host allowlist |
| `SENTINEL_ALLOWED_ORIGINS` | local/test origins | comma-separated | WebSocket Origin allowlist |

The in-memory rate limiter is appropriate only for this single-process local demo. It is not a distributed abuse-control system.

## Container boundary

The supplied Compose service runs as a non-root user with a read-only root filesystem, a dedicated writable data volume, no Linux capabilities, `no-new-privileges`, bounded PIDs/CPU/memory/logs, and a small `noexec` temporary filesystem. The image base and Python dependency graph are pinned. These controls reduce impact; they do not turn the container into a safe boundary for arbitrary hostile code.

## Dependency and CI policy

Direct dependencies are exact-pinned in `requirements*.txt`. Reproducible install sets and hashes are in `requirements*.lock`. CI installs with `--require-hashes`, pins Actions by commit, runs on Python 3.11 and 3.12, enforces 95% application coverage, runs Ruff and Bandit, audits both locks with pip-audit, and smoke-tests the containerized API plus independent verifier endpoint.
