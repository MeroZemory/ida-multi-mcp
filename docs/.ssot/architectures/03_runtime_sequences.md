# 03. Runtime Sequences

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## A. Initial Startup Sequence
1. Operator runs `ida-multi-mcp`.
2. `server.run()` performs stale-process cleanup and auto-rediscovery.
3. `_refresh_tools()` prepares management + static tool schemas.
4. The stdio MCP server begins waiting for requests.

## B. IDA Instance Start Sequence
1. On IDA load, the PLUGIN_FIX plugin auto-loads.
2. `start_server()` starts the in-IDA MCP HTTP server on `127.0.0.1:0`.
3. Reads the actual bound port and registers it with the registry.
4. Starts a 60-second heartbeat thread.

## C. Tool Call Sequence
1. The client issues a `tools/call(name, args)` request.
2. The central server dispatches based on whether the call is management/local or IDA/proxy.
3. If proxy, validate `instance_id`.
4. Forward to IDA via JSON-RPC POST `/mcp`.
5. Normalize the result to `content + structuredContent`.
6. If output is large, cache it and return a preview.

## D. Shutdown Sequence
1. DB close or plugin term event fires.
2. Heartbeat stops.
3. Registry unregister.
4. HTTP server stop.

