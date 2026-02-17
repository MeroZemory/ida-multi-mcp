# Tool Federation Contract

## Schema Rules
- IDA tools must advertise required `instance_id`
- output schema must be object-compatible for strict clients

## Output Rules
- large outputs may be truncated and retrievable via cache pagination

## Traceability
Implementation: `src/ida_multi_mcp/server.py`, `src/ida_multi_mcp/cache.py`
