# Registry Contract

## File
Default registry file is resolved by `IDA_MULTI_MCP_REGISTRY_PATH` or `~/.ida-mcp/instances.json`.

## Required Top-level Keys
- `instances`
- `active_instance`
- `expired`

## Lifecycle
- register -> heartbeat updates -> expire/unregister
- corrupted JSON must be quarantined and recovered to empty default

## Traceability
Implementation: `src/ida_multi_mcp/registry.py`
