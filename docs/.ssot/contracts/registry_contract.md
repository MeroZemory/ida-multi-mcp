# Registry Contract

Last updated: 2026-09-19
Version: v1.1

## Authority
This contract defines the instance registry file path, schema, and recovery behavior.

## Path Resolution
- If the `IDA_MULTI_MCP_REGISTRY_PATH` environment variable is set, use that path.
- Otherwise, use `~/.ida-mcp/instances.json`.

## Required Top-level Keys
- `instances`
- `active_instance`
- `expired`

## Lifecycle Invariants
- register -> heartbeat update -> expire/unregister
- On corrupt-JSON detection, quarantine as `*.corrupt-<ts>` and recover with an empty default structure.

## Registration Identity
- GUI registration, managed-worker registration, and rediscovery capture `input_fingerprint` from the loaded IDB.
- The field is persisted as registration metadata. Forwarding and migration requirements are defined by [Routing Contract v2](routing_contract.md#loaded-input-identity).

## Traceability
- Implementation: `src/ida_multi_mcp/registry.py`
- Plugin bridge: `src/ida_multi_mcp/plugin/registration.py`
- Managed workers: `src/ida_multi_mcp/idalib_manager.py`
- Rediscovery: `src/ida_multi_mcp/health.py`
