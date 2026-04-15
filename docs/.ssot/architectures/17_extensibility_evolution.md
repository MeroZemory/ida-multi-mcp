# 17. Extensibility and Evolution

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Extension Points
- New management tool: add to `server._register_handlers()`
- New IDA tool: add `@tool` to `ida_mcp/api_*.py`
- New resource: `@resource("ida://...")`
- Extension groups: `@ext("group")`

## Evolution Strategy
- Forward compatibility via static schema + backward compatibility via dynamic discovery
- The enforced `instance_id` contract is the key invariant preventing multi-agent conflicts

## Refactoring Priorities
- Abstract the registry backend (JSON -> sqlite-capable)
- Introduce structured logging
- Add a parallel-execution control policy for decompile orchestration

