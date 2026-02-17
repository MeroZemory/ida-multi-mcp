# 18. Module Ownership and Responsibilities

## Aggregator Layer
- `server.py`: protocol entrypoint, tool schema federation, response shaping
- `router.py`: instance resolution, request forwarding
- `health.py`: liveness and rediscovery
- `registry.py`: authoritative instance state

## Runtime Support Layer
- `cache.py`: large-output pagination state
- `filelock.py`: cross-platform lock primitive
- `instance_id.py`: deterministic id generation

## Integration Layer
- `__main__.py`: CLI UX + installer orchestration
- `plugin/*`: IDA runtime binding and registry bridge

## IDA Capability Layer
- `ida_mcp/*`: actual RE capability surface
- `vendor/zeromcp/*`: MCP protocol base runtime

