# 04. Instance Lifecycle Model

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## States
- `registered` (active set)
- `expired` (history set)
- `removed` (cleanup target)

## Creation
- Inputs: `pid`, `port`, `idb_path`
- ID generation: 4-digit base36 derived from `sha256(pid:port:idb_path)`
- On collision: extend to 5 digits or append a suffix

## Maintenance
- Heartbeat refresh: `last_heartbeat`
- Health cleanup: based on process liveness

## Expiration
- Reasons: `process_dead`, `stale_heartbeat`, or other specified reason
- Recorded: `expired_at`, `binary_name`, `binary_path`, `reason`

## Rediscovery
- On empty registry, perform OS-level port scanning (`lsof`/`ss`/`netstat`)
- Register if `ping` succeeds and `ida://idb/metadata` lookup succeeds

## Routing Safeguards
- Unknown instance: surface `available_instances`
- Expired instance: suggest replacement candidates
- Binary mismatch: emit a stale warning

