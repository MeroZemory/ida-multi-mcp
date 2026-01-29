# ida-multi-mcp

Multi-instance IDA Pro MCP server for simultaneous reverse engineering of multiple binaries through a single MCP endpoint.

## Overview

**ida-multi-mcp** enables you to analyze multiple binaries in parallel using IDA Pro, with all instances accessible through a single MCP connection. Instead of juggling multiple MCP client configurations, you open multiple IDA instances and the server automatically discovers and routes requests to each.

```
MCP Client (Claude, Cursor, etc.)
    │  stdio (MCP Protocol)
    ▼
┌─────────────────────────────────┐
│  ida-multi-mcp Server (Router)  │
│  - Dynamic tool discovery       │
│  - instance_id injection        │
│  - Management tools             │
└───┬──────┬──────┬───────────────┘
    │      │      │  HTTP JSON-RPC
    ▼      ▼      ▼
  IDA #1  IDA #2  IDA #3
  (auto)  (auto)  (auto)
```

## Key Features

- **Zero-configuration instance discovery** — Each IDA Pro instance auto-registers on startup
- **Port-collision free** — Uses OS auto-assigned ports (port 0)
- **Dynamic tool discovery** — All 71+ IDA tools available automatically
- **Cross-binary analysis** — Target specific instances via `instance_id` parameter
- **Smart instance tracking** — 4-character IDs (k7m2, px3a, etc.) with automatic binary-change detection
- **File-based registry** — `~/.ida-mcp/instances.json` tracks all active instances
- **Graceful fallback** — Handles binary changes, stale instances, and crashes

## Requirements

- Python 3.11 or later
- IDA Pro 8.3+ (9.0 recommended)
- `ida-pro-mcp` package (provides IDA tools)

## Installation

### Step 1: Install the Package

```bash
pip install git+https://github.com/MeroZemory/ida-multi-mcp.git
```

### Step 2: Install IDA Tools

```bash
pip install ida-pro-mcp
```

### Step 3: Install IDA Plugin and Configure MCP Client

```bash
ida-multi-mcp install
```

This command:
- Copies the plugin loader to your IDA plugins directory
- Shows you the MCP client configuration to add

### Step 4: Configure Your MCP Client

The `install` command displays the configuration. Add this to your MCP client config:

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ida-multi-mcp": {
      "command": "ida-multi-mcp",
      "args": ["serve"]
    }
  }
}
```

**Cursor** (`.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "ida-multi-mcp": {
      "command": "ida-multi-mcp",
      "args": ["serve"]
    }
  }
}
```

**Windsurf** (`.codeium/windsurf/mcp_config.json`):
```json
{
  "mcpServers": {
    "ida-multi-mcp": {
      "command": "ida-multi-mcp",
      "args": ["serve"]
    }
  }
}
```

## Usage

### Opening Multiple Binaries

1. Open IDA Pro and load your first binary (e.g., `malware.exe`)
   - Plugin auto-loads (PLUGIN_FIX flag)
   - Instance auto-registers with 4-char ID (e.g., `k7m2`)

2. Open another IDA Pro instance with a second binary (e.g., `dropper.dll`)
   - Another instance auto-registers (e.g., `px3a`)

3. Repeat for more binaries

### Viewing Registered Instances

```bash
ida-multi-mcp list
```

Output:
```
Registered IDA instances (3):

  k7m2 [ACTIVE]
    Binary: malware.exe
    Path: C:/samples/malware.exe
    Arch: x86_64
    Port: 49152
    PID: 12345

  px3a
    Binary: dropper.dll
    Path: C:/samples/dropper.dll
    Arch: x86_64
    Port: 49153
    PID: 12346

  9bf1
    Binary: payload.exe
    Path: C:/samples/payload.exe
    Arch: x86
    Port: 49154
    PID: 12347
```

### Using in Your LLM

Once connected, all 71+ IDA tools are available. Use the `instance_id` parameter to target a specific instance:

**Analyzing a single instance:**
```
Decompile the main function in malware.exe
```
This uses the active instance.

**Cross-binary analysis:**
```
Decompile main in malware.exe (k7m2) and compare it with the entry point in dropper.dll (px3a)
```

**Switching active instance:**
```
Set px3a as the active instance, then list all functions
```

## Management Tools

The server provides 4 built-in management tools:

### list_instances()
Lists all registered IDA instances with metadata (binary name, path, architecture, port).

### get_active_instance()
Returns the currently active instance (used when `instance_id` is not specified).

### set_active_instance(instance_id: str)
Sets the active instance for subsequent tool calls.

### refresh_tools()
Re-discovers tools from the active IDA instance. Use this if you update the IDA plugin.

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

## CLI Commands

### `ida-multi-mcp serve`
Start the MCP server (stdio). Used by MCP clients.

```bash
ida-multi-mcp serve
```

### `ida-multi-mcp list`
List all registered IDA instances.

```bash
ida-multi-mcp list
```

### `ida-multi-mcp install [--ida-dir DIR]`
Install the IDA plugin and show MCP client configuration.

```bash
ida-multi-mcp install
ida-multi-mcp install --ida-dir "C:/Program Files/IDA Pro 9.0"
```

### `ida-multi-mcp uninstall [--ida-dir DIR]`
Remove the IDA plugin and clean up registry.

```bash
ida-multi-mcp uninstall
```

### `ida-multi-mcp config`
Print the MCP client configuration JSON for easy reference.

```bash
ida-multi-mcp config
```

## Architecture

### Instance Registry

Location: `~/.ida-mcp/instances.json`

Each registered instance includes:
- **id** — 4-char instance identifier (k7m2, px3a, etc.)
- **pid** — Process ID of the IDA Pro instance
- **host** — Always 127.0.0.1 (localhost)
- **port** — Dynamically assigned HTTP port
- **binary_name** — Filename (malware.exe, driver.dll, etc.)
- **binary_path** — Full path to binary
- **arch** — Architecture (x86_64, x86, arm64, etc.)
- **registered_at** — Timestamp when instance registered
- **last_heartbeat** — Last heartbeat check timestamp

### Request Routing

1. MCP client calls a tool (e.g., `decompile`) with optional `instance_id` parameter
2. Server routes to the target instance via HTTP JSON-RPC
3. IDA instance processes the request
4. Result returned to client

If `instance_id` is not specified, the active instance is used.

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

## Troubleshooting

### "No IDA instances registered"

Make sure:
1. IDA Pro is running
2. Check IDA's plugin list (Edit → Plugins → Scan) to confirm `ida-multi-mcp` plugin loaded
3. Check IDA console for error messages
4. Run `ida-multi-mcp list` again

### "Instance 'k7m2' not found"

The instance has crashed or expired. Run:
```bash
ida-multi-mcp list
```
to see available instances, then use a valid ID.

### "Instance 'k7m2' expired. Replaced by 'px3a'"

You opened a different binary in that IDA instance. This is expected. Use the new instance ID (`px3a`).

### Plugin doesn't load in IDA

Check:
1. IDA plugins directory exists: `%APPDATA%/Hex-Rays/IDA Pro/plugins/` (Windows)
2. `ida_multi_mcp.py` is in the directory
3. `ida-pro-mcp` package is installed: `pip list | grep ida-pro-mcp`
4. Restart IDA Pro

## Uninstallation

```bash
# Remove plugin and registry
ida-multi-mcp uninstall

# Remove package
pip uninstall ida-multi-mcp

# Remove MCP client configuration
# (Manual step — remove from claude_desktop_config.json, .cursor/mcp.json, etc.)
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Port 0 (auto-assigned) | Eliminates port conflicts, scales to unlimited instances |
| 4-char base36 IDs | Short, readable, 1.68M combinations, easy to remember |
| File-based registry | Simple, cross-process, debuggable, no database dependency |
| Dynamic tool discovery | Future-proof, automatic updates, no hardcoded tool list |
| Dual binary-change detection | Robust fallback if IDA hooks fail |

## Performance

- Registry operations: <1ms (JSON file, file-locked)
- Tool discovery: ~50ms per IDA instance (one-time cache)
- Tool call routing: <5ms (local HTTP JSON-RPC)
- Heartbeat interval: 60 seconds (negligible overhead)

## Limitations

- Supports 127.0.0.1 only (localhost analysis)
- Remote IDA instances not supported in v1.0
- Does not support IDA batch/headless (idalib) mode yet
- Resources (not tools) require manual routing in v1.0

## License

MIT

## Contributing

Contributions welcome! Please ensure:
- Python 3.11+ compatibility
- Cross-platform (Windows, macOS, Linux)
- Clean, readable code
- Tests for new features

## Related Projects

- **ida-pro-mcp** — The underlying IDA plugin providing 71+ tools
- **Claude Code** — MCP client with native support
- **Cursor** — Alternative MCP-enabled editor

## Support

For issues, feature requests, or questions:
- Check the troubleshooting section above
- Review DESIGN.md for architecture details
- Open an issue on GitHub
