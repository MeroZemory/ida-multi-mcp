# Routing Contract

## Mandatory Input
All IDA tool calls must include `instance_id`.

## Error Contract
When missing or invalid:
- include `error`
- include actionable `hint`
- include `available_instances` when relevant

## Traceability
Implementation: `src/ida_multi_mcp/router.py`
