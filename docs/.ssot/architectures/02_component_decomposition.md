# 02. Component Decomposition

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Top-level Components
- MCP Aggregator Server: `server.py`
- Router: `router.py`
- Registry: `registry.py`
- Health: `health.py`
- Cache: `cache.py`
- CLI/Installer: `__main__.py`
- Plugin Runtime: `plugin/ida_multi_mcp.py`
- IDA Tool Provider: `ida_mcp/*`

## Server Internal Decomposition
- Management tools (local): `list_instances`, `refresh_tools`, `get_cached_output`, `decompile_to_file`
- IDA tools (proxy): static schema (`ida_tool_schemas.json`) + dynamic tool-list federation
- MCP override: customization of `tools/list`, `tools/call`

## Plugin Internal Decomposition
- Loader: `plugin/ida_multi_mcp_loader.py`
- Runtime plugin: HTTP server start/stop + registry registration
- Registration adapter: `plugin/registration.py`
- Lifecycle hooks: `IDB_Hooks.closebase`, `UI_Hooks.database_inited`

## Tool Layer
- Base analysis tools: `api_core`, `api_analysis`, `api_memory`, `api_types`, `api_modify`, `api_stack`, `api_python`
- Extended debug tools: `api_debug` (`@ext("dbg")`)
- Resources: `api_resources` (`ida://...`)

