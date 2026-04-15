# 14. Observability and Diagnostics

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Log Channels
- Central server: status logs via stderr/print
- Plugin: IDA console logs

## Observable State
- Instance registration/deregistration/cleanup
- Auto-discovery success/failure
- Tool-discovery failure causes
- Heartbeat errors

## Operational Diagnostic Routine
1. Check `ida-multi-mcp --list`
2. Verify plugin startup logs in the IDA console
3. Inspect the registry file (`~/.ida-mcp/instances.json`) directly
4. Run `refresh_tools` if needed

## Improvement Opportunities
- No structured logs (JSON)
- No metrics (exporter)
- No trace-ID-based request tracing

