# Product Requirements Document (PRD)

Last updated: 2026-02-17
Status: Active
Change class: B (scope/architecture)

## 1. Product Goal
`ida-multi-mcp` provides an analysis environment that safely routes to multiple IDA instances through a single MCP endpoint.

## 2. Core Requirements
- Explicit per-instance routing: every IDA tool call requires `instance_id`.
- Multi-instance operation: supports concurrent analysis of multiple binaries.
- Tool surface stability: maintains tool visibility via static + dynamic schema federation.
- Install/operational practicality: supports cross-platform plugin installation and MCP client configuration automation.

## 3. In Scope
- Registry-based instance lifecycle management
- Router-based `instance_id` enforced dispatch
- Cache/paged retrieval of large responses
- IDA plugin auto-load/auto-register

## 4. Out of Scope
- External public HTTP API platform
- DB-backed persistent storage
- On-call operational services (services requiring a runbook)

## 5. Project Profile
```yaml
project_profile:
  interfaces:
    http_api: false
    external_api: false
    cli: true
  persistence:
    has_db_or_persistent_store: false
  ai_tooling:
    uses_ai_agents: true
    uses_rag_kb: false
```

## 6. N/A Document Types
- API Spec: `N/A`
- Data Model/Schema (DB): `N/A`
- Runbook: `N/A`
- KB Config: `N/A`

## 7. Authority Links
- Contracts (SSOT): `docs/.ssot/contracts/INDEX.md`
- Decisions: `docs/.ssot/decisions/INDEX.md`
- Architecture: `docs/.ssot/architectures/00_INDEX.md`
- Roadmap: `docs/ops/ROADMAP.md`
