# 18. Module Ownership and Responsibilities

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Aggregator Layer
- `server.py`: protocol entrypoint, tool schema federation, response shaping
- `router.py`: instance resolution, request forwarding
- `health.py`: liveness and rediscovery
- `registry.py`: authoritative instance state

## Runtime Support Layer
- `cache.py`: large-output pagination state
- `filelock.py`: cross-platform lock primitive
- `instance_id.py`: deterministic id generation

## Integration Layer
- `__main__.py`: CLI UX + installer orchestration
- `plugin/*`: IDA runtime binding and registry bridge

## IDA Capability Layer
- `ida_mcp/*`: actual RE capability surface
- `vendor/zeromcp/*`: MCP protocol base runtime

