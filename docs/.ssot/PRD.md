# Product Requirements Document (PRD)

Last updated: 2026-02-17
Status: Active

## Product Goal
Provide a single MCP endpoint that safely routes reverse-engineering tool calls to multiple live IDA instances.

## Scope
- Multi-instance registration and discovery
- Explicit `instance_id` routing contract
- Dynamic/static tool schema federation
- Cross-platform plugin install/uninstall and client configuration

## Non-Goals
- External HTTP API platform
- DB-backed persistence (file-based registry is current profile)

## Authoritative References
- Contracts: `docs/.ssot/contracts/INDEX.md`
- Architecture: `docs/.ssot/architectures/00_INDEX.md`
- Decisions: `docs/.ssot/decisions/INDEX.md`
