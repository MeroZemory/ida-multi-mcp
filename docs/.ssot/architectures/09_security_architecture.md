# 09. Security Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Trust Boundaries
- Default communication is localhost (127.0.0.1)
- Enforcing explicit `instance_id` at the central server mitigates misrouting/confusion

## IDA HTTP Protections
- `/config` POST: Origin validation
- `/config.html` GET: Host validation
- CSP + X-Frame-Options applied
- CORS policy: `unrestricted | local | direct`

## Explicit Risks
- Unsafe tools (`@unsafe`): high-risk such as debugging, memory writes, `py_eval`
- Exposure can be controlled via extension gating (`@ext`)

## Residual Risks
- Local-host threat model (malicious code within the same user session)
- Registry file tampering can poison routing
- Dependent on MCP client configuration file permissions/integrity

