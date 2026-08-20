## Sentinel Swarm v0.1.0

Local-first multi-agent cybersecurity lab with observable agents, isolated workspaces, and SHA-256 evidence.

### Implemented

- FastAPI control plane + WebSocket mission streaming
- 5 deterministic roles: RECON → EXPLOIT-ANALYSIS → THREAT-MODEL → SECURE-CODING → REPORT-WRITER
- Isolated per-mission workspaces
- Real remediation of `sshd_config` (`PermitRootLogin` + `PasswordAuthentication`)
- Post-change verification
- SHA-256 evidence ledger (`events.jsonl`)
- Markdown report generation
- Docker + docker-compose
- pytest suite + GitHub Actions CI

### Explicitly not included

- Network scanning
- Arbitrary shell execution
- Autonomous exploitation
- Local LLM / Ollama (planned)
- Mission replay UI (planned)

### Quick start

```bash
docker compose up --build
```

Open http://localhost:7777
