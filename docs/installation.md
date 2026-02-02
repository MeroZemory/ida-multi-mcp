# ida-multi-mcp Installation Guide

This guide is for AI agents. Follow each step exactly.

## Prerequisites

- Python 3.11+
- IDA Pro 8.3+ (9.0 recommended)
- pip (Python package manager)

## Step 1: Install ida-multi-mcp

```bash
# (Recommended) Clean previous install to avoid stale scripts/config
ida-multi-mcp --uninstall
python -m pip uninstall -y ida-multi-mcp

python -m pip install git+https://github.com/MeroZemory/ida-multi-mcp.git
```

## Step 2: Install IDA Plugin and Configure MCP Clients

```bash
ida-multi-mcp --install
```

This performs two actions:
1. Copies `ida_multi_mcp.py` to the IDA plugins directory:
   - Windows: `%APPDATA%/Hex-Rays/IDA Pro/plugins/`
   - macOS/Linux: `~/.idapro/plugins/`
2. Auto-configures all detected MCP clients (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Zed, and 20+ more)

If IDA is installed in a custom location:
```bash
ida-multi-mcp --install --ida-dir "C:/Program Files/IDA Pro 9.0"
```

For clients not auto-detected or to view the configuration JSON, run:
```bash
ida-multi-mcp --config
```

## Step 3: Verify

1. Open IDA Pro with any binary — the plugin auto-loads (PLUGIN_FIX)
2. Check the IDA console for: `[ida-multi-mcp] Registered as instance 'xxxx'`
3. Run: `ida-multi-mcp --list` to confirm the instance is visible
4. In your MCP client, try calling `list_instances()` tool

## Coexistence with ida-pro-mcp

If you previously used ida-pro-mcp, note that ida-multi-mcp now bundles all IDA tools internally.
You can remove the original `ida_mcp.py` from the IDA plugins directory to avoid conflicts.
Both can run simultaneously (they bind to different ports), but it's recommended to use only ida-multi-mcp.

## Uninstallation

```bash
ida-multi-mcp --uninstall
pip uninstall ida-multi-mcp
```

The `--uninstall` command automatically removes the IDA plugin, cleans up the registry, and removes MCP client configurations.
