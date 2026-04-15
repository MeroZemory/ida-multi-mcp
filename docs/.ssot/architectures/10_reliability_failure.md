# 10. Reliability and Failure Handling

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Primary Failure Scenarios
- Tool call while no IDA is connected
- Use of a missing/expired `instance_id`
- Stale registry after IDA process exit
- HTTP connection failure/timeout

## Response Strategies
- Provide proactive error messages and recovery hints
- Guide users to current state via `list_instances`
- Clean up dead processes at startup
- Auto-recover via rediscovery and re-registration

## Degraded Behavior
- On metadata-lookup failure, binary verification is fail-open (True)
- On tool-discovery failure, serve only the static schema

## Operational Notes
- Error responses are designed to include human-readable hints

