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

## Installation

### For Humans

The easiest way to install is to let your AI agent handle it. Copy and paste one of these prompts into your AI tool:

**Claude Code / AmpCode:**
> Install and configure ida-multi-mcp by following the instructions here: https://raw.githubusercontent.com/MeroZemory/ida-multi-mcp/main/docs/installation.md

**Cursor:**
> @Web fetch https://raw.githubusercontent.com/MeroZemory/ida-multi-mcp/main/docs/installation.md and follow the installation steps.

Or install manually:

```bash
# 0. (Recommended) Clean previous install to avoid stale scripts/config
ida-multi-mcp --uninstall
python -m pip uninstall -y ida-multi-mcp

# 1. Install ida-multi-mcp
python -m pip install git+https://github.com/MeroZemory/ida-multi-mcp.git

# 2. Install IDA plugin + configure all MCP clients
ida-multi-mcp --install
```

## Uninstallation

```bash
# 1. Remove IDA plugin + remove MCP client configurations
ida-multi-mcp --uninstall

# (optional) If IDA is installed in a custom location
ida-multi-mcp --uninstall --ida-dir "C:/Program Files/IDA Pro 9.0"

# 2. Remove the Python package
python -m pip uninstall ida-multi-mcp
```

After uninstalling, fully restart IDA Pro and your MCP client(s) so the removed configuration is picked up.

### For AI Agents

Fetch and follow the installation guide:

```bash
curl -s https://raw.githubusercontent.com/MeroZemory/ida-multi-mcp/main/docs/installation.md
```

The guide covers:
1. Package installation (`pip install`)
2. IDA plugin setup + MCP client auto-configuration (`ida-multi-mcp --install`)
3. Verification steps

### Supported MCP Clients

Works with any MCP-compatible client. Tested with:

| Client | Type |
|--------|------|
| Claude Code | CLI |
| Claude Desktop | Desktop |
| Cursor | IDE |
| VS Code (Copilot) | IDE |
| Windsurf | IDE |
| Zed | IDE |
| Augment Code | IDE |
| Cline | Extension |
| Kilo Code | Extension |
| Kiro | IDE |
| LM Studio | Desktop |
| Opencode | CLI |
| Qodo Gen | Extension |
| Roo Code | Extension |
| Trae | IDE |
| Warp | Terminal |
| Amazon Q Developer CLI | CLI |
| Copilot CLI | CLI |
| Gemini CLI | CLI |

### MCP Client Configuration

`ida-multi-mcp --install` automatically configures all detected MCP clients:
- Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Zed, and 20+ more

For clients not auto-detected or to view the configuration JSON, run:
```bash
ida-multi-mcp --config
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
ida-multi-mcp --list
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

### `ida-multi-mcp`
Start the MCP server (stdio). Used by MCP clients. This is the default command.

```bash
ida-multi-mcp
```

### `ida-multi-mcp --list`
List all registered IDA instances.

```bash
ida-multi-mcp --list
```

### `ida-multi-mcp --install [--ida-dir DIR]`
Install the IDA plugin and auto-configure all detected MCP clients (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Zed, and 20+ more).

```bash
ida-multi-mcp --install
ida-multi-mcp --install --ida-dir "C:/Program Files/IDA Pro 9.0"
```

### `ida-multi-mcp --uninstall [--ida-dir DIR]`
Remove the IDA plugin, clean up registry, and remove MCP client configurations.

```bash
ida-multi-mcp --uninstall
```

### `ida-multi-mcp --config`
Print the MCP client configuration JSON for easy reference.

```bash
ida-multi-mcp --config
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
ida-multi-mcp --list
```
to see available instances, then use a valid ID.

### "Instance 'k7m2' expired. Replaced by 'px3a'"

You opened a different binary in that IDA instance. This is expected. Use the new instance ID (`px3a`).

### Plugin doesn't load in IDA

Check:
1. IDA plugins directory exists: `%APPDATA%/Hex-Rays/IDA Pro/plugins/` (Windows)
2. `ida_multi_mcp.py` is in the directory
3. `ida-multi-mcp` package is installed: `pip list | grep ida-multi-mcp`
4. Restart IDA Pro

## Uninstallation

```bash
# Remove plugin, registry, and MCP client configurations
ida-multi-mcp --uninstall

# Remove package
pip uninstall ida-multi-mcp
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

## Acknowledgments

This project was inspired by and builds upon [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by [Duncan Ogilvie (mrexodia)](https://github.com/mrexodia). The IDA tool implementations (71+ tools) originated from ida-pro-mcp and have been absorbed into ida-multi-mcp as a bundled package, adding multi-instance orchestration on top.

The installation approach (AI-agent-friendly installation guides) was influenced by [oh-my-opencode](https://github.com/code-yeongyu/oh-my-opencode) by [Yeongyu Yun (code-yeongyu)](https://github.com/code-yeongyu).

## Related Projects

- **[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)** — The original single-instance IDA MCP plugin (tools originated from here) (MIT License)
- **Claude Code** — MCP client with native support
- **Cursor** — Alternative MCP-enabled editor

## Support

For issues, feature requests, or questions:
- Check the troubleshooting section above
- Review DESIGN.md for architecture details
- Open an issue on GitHub
