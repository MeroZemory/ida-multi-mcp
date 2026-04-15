# 08. Concurrency and Synchronization

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Central Server Concurrency
- Registry access is serialized via a file lock
- MCP requests may run in parallel at I/O boundaries

## IDA Internal Concurrency
- All IDA SDK calls go through `@idasync` -> `idaapi.execute_sync(..., MFF_WRITE)`
- IDA's single-main-thread execution model
- Long-running calls can block other requests

## Cancellation/Timeout
- Default timeout: 15 seconds (`IDA_MCP_TOOL_TIMEOUT_SEC`)
- Per-call override via `@tool_timeout` (e.g., `decompile` at 90 seconds)
- Cancellation driven by `notifications/cancelled` events and profile hooks

## Reentrancy Protection
- `call_stack` inspection detects reentrancy errors on the synchronization path

