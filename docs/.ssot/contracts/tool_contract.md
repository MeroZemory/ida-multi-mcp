# Tool Federation Contract

Last updated: 2026-02-17
Version: v1

## Authority
This contract defines the central MCP server's tool schema federation and large-response handling rules.

## Schema Rules
- IDA tools expose `instance_id` as a required input.
- For client compatibility, the output schema must be object-compatible.

## Output Rules
- Large outputs may be served as preview + cache pagination.
- Cache retrieval is performed via `get_cached_output` using offset/size.

## Traceability
- Tool cache/federation: `src/ida_multi_mcp/server.py`
- Cache model: `src/ida_multi_mcp/cache.py`
