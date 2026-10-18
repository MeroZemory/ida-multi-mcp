# Architecture

Last updated: 2026-10-18

[← back to README](../README.md)

## Architecture

### Instance Registry

Location:
- macOS/Linux: `~/.ida-mcp/instances.json`
- Windows: `%USERPROFILE%\.ida-mcp\instances.json`

Each registered instance includes:
- **id** — 4-char instance identifier (k7m2, px3a, etc.)
- **pid** — Process ID of the IDA Pro instance
- **host** — Loopback only: Windows managed workers prefer `::1` after a
  successful bind probe and otherwise use `127.0.0.1`; all other platforms use
  `127.0.0.1`
- **port** — Dynamically assigned HTTP port
- **binary_name** — Filename (malware.exe, driver.dll, etc.)
- **binary_path** — Full path to binary
- **arch** — Architecture (x86_64, x86, arm64, etc.)
- **registered_at** — Timestamp when instance registered
- **last_heartbeat** — Last heartbeat check timestamp

### IDA Plugin Directory

- macOS/Linux: `~/.idapro/plugins/`
- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`

### Request Routing

1. MCP client calls a tool (e.g., `decompile`) with required `instance_id` parameter
2. Server routes to the target instance via HTTP JSON-RPC
3. IDA instance processes the request
4. Result returned to client

### Health Monitoring

- Each IDA instance sends a heartbeat every 60 seconds
- Stale instances (no heartbeat for 2+ minutes) are automatically cleaned up
- On server startup, dead processes are removed from the registry
- If an instance crashes, subsequent requests get a helpful error message

### Binary Change Detection

Uses dual-strategy detection:

**Primary (Fast)** — IDA event hooks trigger immediately when binary changes
**Fallback (Safe)** — Every tool call verifies binary hasn't changed, handles hook failures

When a binary change is detected:
- Old instance ID is marked as expired
- New instance registers with new ID
- LLM receives helpful message with replacement ID

## Instance IDs Explained

Instance IDs are 4-character base36 strings (0-9, a-z) like `k7m2`, `px3a`, `9bf1`.

**Why 4 characters?**
- Short and readable
- 1.68 million combinations (collision-free for typical use)
- Auto-expands to 5 characters if collision detected

**How are they generated?**
- Based on: process ID, port, and IDB file path
- Same binary reopened = same ID (deterministic)
- Binary replaced/changed = new ID (automatic)

**What happens when you change binaries?**
When you open a different binary in an IDA instance:
1. Old instance expires (e.g., `k7m2` → expired)
2. New instance registers (e.g., `b12`)
3. If LLM tries to use old ID, you get a helpful error with the replacement ID

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Loopback-only transport | Keeps workers local; Windows prefers IPv6 loopback when available to avoid IPv4 filter-stack resets, with IPv4 fallback |
| Port 0 (auto-assigned) | Eliminates port conflicts, scales to unlimited instances |
| 4-char base36 IDs | Short, readable, 1.68M combinations, easy to remember |
| File-based registry | Simple, cross-process, debuggable, no database dependency |
| Dynamic tool discovery | Future-proof, automatic updates, no hardcoded tool list |
| Dual binary-change detection | Robust fallback if IDA hooks fail |
| Subprocess-per-binary (idalib) | True parallelism, crash isolation, no in-process DB switching |
| compat.py shims | Single source for IDA 8.5–9.3 API differences |
| Worker pool for stdio dispatch | Instances are separate processes; serializing at the router wasted that. Only stdout writes are locked (`IDA_MCP_STDIO_WORKERS`) |
| Deadline fires IDA's `set_cancelled()` | A Python-level timeout cannot preempt a C SDK call; IDA's own cancel flag can (`IDA_MCP_CANCEL_GRACE_SEC`) |

## Managed worker identity and shutdown

Managed workers read canonical module names and the IDB-stored
`input_fingerprint` through [`ida://idb/identity`](../src/ida_multi_mcp/ida_mcp/api_resources.py),
not the expensive disk-hashing metadata resource. The manager uses a shared
30-second identity budget and bounded transient retries; an IDB without a
canonical module is not registered. See
[`IdalibManager.spawn_session`](../src/ida_multi_mcp/idalib_manager.py) and the
[registry v2 contract](.ssot/contracts/registry_contract.md).

The Windows loopback preference is bind-tested by
[`_preferred_loopback_host`](../src/ida_multi_mcp/idalib_manager.py); both
[plugin ZeroMCP](../src/ida_multi_mcp/ida_mcp/zeromcp/mcp.py) and
[router ZeroMCP](../src/ida_multi_mcp/vendor/zeromcp/mcp.py) select IPv6 servers
and bracket their advertised URLs.

Authenticated shutdown is sent once. A missing acknowledgement does not prove
non-delivery: the manager retains a shared 300-second in-flight-call drain plus
60-second save deadline before signal/kill fallback. An acknowledged shutdown
receives up to 60 seconds for saving within that deadline. This is bounded
recovery, not a guarantee that an arbitrarily long save cannot be interrupted.
See [`_terminate_gracefully`](../src/ida_multi_mcp/idalib_manager.py),
[`_register_shutdown_rpc` and `_close_database_packed`](../src/ida_multi_mcp/idalib_worker.py).
