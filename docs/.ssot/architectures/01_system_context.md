# 01. System Context Architecture

## Governance Alignment
- Authority order: `docs/.ssot/contracts/*` -> `docs/.ssot/PRD.md` -> `docs/.ssot/decisions/*` -> this document.
- Contract reference baseline: `docs/.ssot/contracts/INDEX.md` (v1 baseline).
- This document explains architecture and does not redefine contract semantics.


## Purpose
`ida-multi-mcp` unifies multiple IDA Pro instances behind a single MCP endpoint.

## External Actors
- MCP clients: Claude/Cursor/Codex, etc.
- IDA Pro processes: each instance runs a local HTTP MCP server
- Operators: `ida-multi-mcp --install/--list/--uninstall`
- Local file system: `~/.ida-mcp/instances.json`, client configuration files

## System Boundary
- Central server process: `src/ida_multi_mcp/server.py`
- IDA in-process plugin: `src/ida_multi_mcp/plugin/ida_multi_mcp.py`
- IDA tool provider layer: `src/ida_multi_mcp/ida_mcp/*`

## Context Flow
1. The IDA plugin starts an HTTP MCP server on a dynamic port (0).
2. The plugin registers the instance with the central registry.
3. The MCP client connects to the central server over stdio.
4. The central server routes requests to the corresponding IDA based on `instance_id`.

## Core Non-functional Goals
- Concurrent multi-instance support
- Port-conflict avoidance
- Safe routing (explicit `instance_id` enforcement)
- Resilience to plugin restart / process termination

