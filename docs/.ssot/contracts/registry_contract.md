# Registry Contract

Last updated: 2026-02-17
Version: v1

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

## Traceability
- Implementation: `src/ida_multi_mcp/registry.py`
- Plugin bridge: `src/ida_multi_mcp/plugin/registration.py`
