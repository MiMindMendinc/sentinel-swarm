# Contributing to Sentinel Swarm

Thanks for helping improve Sentinel Swarm. The project values **reproducibility, evidence, and truthful capability claims** over flashy output.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install --upgrade pip==26.2.1
python -m pip install --require-hashes -r requirements-dev.lock
make test
make run
```

## Pull request expectations

- Keep changes focused and explain the user-visible impact.
- Add or update tests for behavior changes.
- Do not add simulated scan results, fabricated confidence scores, or unsupported security claims.
- Keep generated mission data out of git.
- Preserve the local-first default.
- Update `README.md`, `CHANGELOG.md`, or `ROADMAP.md` when behavior or scope changes.
- Version tags (`v*`) publish a GitHub Release from the matching `docs/release-<tag>.md` file. Add that notes file before tagging.

## New capabilities

Any new tool or agent capability should document:

1. what it actually executes;
2. what permissions it needs;
3. what evidence it records;
4. how failures are surfaced;
5. how a contributor can reproduce the result.

## Before opening a PR

```bash
make lint
make test
make audit
```

If Docker is available, also verify:

```bash
docker compose up --build
```
