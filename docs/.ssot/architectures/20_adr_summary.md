# 20. Architecture Decision Record Summary

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## ADR-001 Single MCP Aggregator Server
- Decision: central server + multi-IDA routing
- Rationale: simplifies client configuration, enables concurrent analysis of multiple binaries

## ADR-002 Dynamic Port Usage
- Decision: IDA plugin binds port 0
- Rationale: eliminates port conflicts

## ADR-003 File-based Registry
- Decision: `~/.ida-mcp/instances.json`
- Rationale: simplicity, ease of debugging, cross-process sharing

## ADR-004 Explicit `instance_id` Enforcement
- Decision: `instance_id` is required on every IDA tool call
- Rationale: prevents cross-contamination in multi-agent environments

## ADR-005 Static + Dynamic Schema Hybrid
- Decision: offline visibility (static) + runtime accuracy (dynamic)
- Rationale: improves UX while IDA is disconnected and preserves version compatibility

## ADR-006 Output Truncation and Caching
- Decision: preview large responses + paginate via cache
- Rationale: ensures MCP channel stability and user responsiveness

## ADR-007 IDA Main-thread Synchronization
- Decision: enforce `execute_sync(MFF_WRITE)`
- Rationale: guarantees IDA API thread safety

