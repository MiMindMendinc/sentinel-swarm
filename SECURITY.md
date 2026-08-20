# Security Policy

Sentinel Swarm is intentionally conservative in v0.1: it operates on a bundled local fixture and does **not** implement arbitrary shell execution, autonomous exploitation, or live network scanning.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Please avoid publishing exploitable details in a public issue. Prefer GitHub's private vulnerability reporting / Security Advisory flow when available. If that is unavailable, contact the maintainer through the contact method listed on the GitHub profile and include:

- affected version or commit;
- reproduction steps;
- expected vs. actual behavior;
- impact assessment;
- any suggested mitigation.

## Security boundaries

The built-in range is a local demonstration fixture. Do not represent Sentinel Swarm v0.1 as a production network scanner, offensive exploitation framework, or hardened isolation boundary. Generated mission workspaces are local artifacts and should be treated as potentially sensitive if you later extend the project to real inputs.
