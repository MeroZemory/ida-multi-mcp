# ida-multi-mcp Installation Guide

This guide is for AI agents. Follow each step exactly.

## Prerequisites

- Python 3.11+
- IDA Pro 8.3+ (9.0 recommended)
- pip (Python package manager)

## Step 1: Install ida-multi-mcp

```bash
pip install git+https://github.com/MeroZemory/ida-multi-mcp.git
```

## Step 2: Install IDA Plugin

```bash
ida-multi-mcp --install
```

This copies `ida_multi_mcp.py` to the IDA plugins directory:
- Windows: `%APPDATA%/Hex-Rays/IDA Pro/plugins/`
- macOS/Linux: `~/.idapro/plugins/`

If IDA is installed in a custom location:
```bash
ida-multi-mcp --install --ida-dir "C:/Program Files/IDA Pro 9.0"
```

## Step 3: Configure MCP Client

Add the following to the user's MCP client configuration:

### Claude Code

Run this command:
```bash
claude mcp add ida-multi-mcp -s user -- ida-multi-mcp
```

Or add to `.claude/config.json`:
```json
{
  "mcpServers": {
    "ida-multi-mcp": {
      "command": "ida-multi-mcp"
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "ida-multi-mcp": {
      "command": "ida-multi-mcp"
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "ida-multi-mcp": {
      "command": "ida-multi-mcp"
    }
  }
}
```

### Windsurf

Add to `.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "ida-multi-mcp": {
      "command": "ida-multi-mcp"
    }
  }
}
```

## Step 4: Verify

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

Then remove `ida-multi-mcp` from your MCP client configuration.
