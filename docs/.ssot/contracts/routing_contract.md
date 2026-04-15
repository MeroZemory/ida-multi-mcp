# Routing Contract

Last updated: 2026-02-17
Version: v1

## Authority
This contract defines the required inputs and error shape for IDA tool routing requests.

## Rules
- Every IDA tool call must include `instance_id`.
- If missing or invalid, the response must contain the following fields:
  - `error`
  - `hint`
  - `available_instances` (when applicable)

## Traceability
- Implementation: `src/ida_multi_mcp/router.py`
- Error envelope shaping: `src/ida_multi_mcp/server.py`
