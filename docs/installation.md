# ida-multi-mcp Installation Guide

This guide is for AI agents. Follow each step exactly.

## Prerequisites

- Python 3.11+
- IDA Pro 8.3+ (9.0 recommended)
- pip (Python package manager)

## Important: IDA Python Version Mismatch

IDA Pro bundles or links its own Python interpreter, which **may differ from your system default Python**. For example:
- macOS system Python may be 3.14, but IDA uses homebrew's Python 3.11
- Windows system Python may be 3.13, but IDA uses its bundled Python 3.12

The ida-multi-mcp package must be importable from **IDA's Python**, not just your terminal's Python.

The plugin loader automatically searches common installation paths (pip --user, pipx venvs, homebrew site-packages), but matching the Python version is the most reliable approach.

## Installation

### macOS

**Option A: pipx (recommended for CLI) + pip --user for IDA**

```bash
# 1. Install CLI tool via pipx (runs ida-multi-mcp serve, list, install, etc.)
pipx install git+https://github.com/MeroZemory/ida-multi-mcp.git

# 2. Find which Python version IDA uses (check IDA console or run):
#    Python> import sys; print(sys.version)
#    e.g., "3.11.14" means IDA uses Python 3.11

# 3. Install package for IDA's Python version
#    Replace "python3.11" with IDA's actual Python version
python3.11 -m pip install --user git+https://github.com/MeroZemory/ida-multi-mcp.git

# 4. Install IDA plugin + configure all MCP clients
ida-multi-mcp --install
```

**Option B: pip install --user with IDA's Python only**

```bash
# 1. Install using IDA's Python version directly
python3.11 -m pip install --user --break-system-packages git+https://github.com/MeroZemory/ida-multi-mcp.git

# 2. Install IDA plugin + configure all MCP clients
python3.11 -m ida_multi_mcp --install
```

**How to find IDA's Python version on macOS:**
1. Open IDA Pro with any binary
2. In the IDA console (Output window), run:
   ```
   Python> import sys; print(sys.version)
   ```
3. The first two numbers (e.g., `3.11`) are what you need

### Windows

```bash
# 0. (Recommended) Clean previous install to avoid stale scripts/config
ida-multi-mcp --uninstall
python -m pip uninstall -y ida-multi-mcp

# 1. Install ida-multi-mcp
python -m pip install git+https://github.com/MeroZemory/ida-multi-mcp.git

# 2. Install IDA plugin + configure all MCP clients
ida-multi-mcp --install
```

On Windows, IDA typically uses the system Python or its bundled Python. If using IDA's bundled Python, install to the matching version:

```bash
# If IDA uses Python 3.12 but your system default is different:
py -3.12 -m pip install git+https://github.com/MeroZemory/ida-multi-mcp.git
```

If IDA is installed in a custom location:
```bash
ida-multi-mcp --install --ida-dir "C:/Program Files/IDA Pro 9.0"
```

### Linux

```bash
# 1. Install ida-multi-mcp
pip install --user git+https://github.com/MeroZemory/ida-multi-mcp.git

# 2. Install IDA plugin + configure all MCP clients
ida-multi-mcp --install
```

## MCP Client Configuration

`ida-multi-mcp --install` automatically configures all detected MCP clients:
- Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Zed, and 20+ more

For clients not auto-detected or to view the configuration JSON, run:
```bash
ida-multi-mcp --config
```

## Verify

1. Open IDA Pro with any binary — the plugin auto-loads (PLUGIN_FIX)
2. Check the IDA console for: `[ida-multi-mcp] Registered as instance 'xxxx'`
3. Run: `ida-multi-mcp --list` to confirm the instance is visible
4. In your MCP client, try calling `list_instances()` tool

## Troubleshooting

### "No module named 'ida_multi_mcp.plugin'" in IDA

This means IDA's Python cannot find the installed package. The most common cause is **Python version mismatch**.

1. Check IDA's Python version in the IDA console:
   ```
   Python> import sys; print(sys.version)
   ```
2. Install the package using that exact Python version:
   ```bash
   # macOS example (if IDA uses 3.11):
   python3.11 -m pip install --user git+https://github.com/MeroZemory/ida-multi-mcp.git

   # Windows example (if IDA uses 3.12):
   py -3.12 -m pip install git+https://github.com/MeroZemory/ida-multi-mcp.git
   ```
3. Restart IDA Pro

### Plugin loader shows searched paths

If the loader prints `Searched paths:`, check if any of those paths contain `ida_multi_mcp/`. If none do, the package needs to be installed for IDA's Python version (see above).

## Coexistence with ida-pro-mcp

If you previously used ida-pro-mcp, note that ida-multi-mcp now bundles all IDA tools internally.
You can remove the original `ida_mcp.py` from the IDA plugins directory to avoid conflicts.
Both can run simultaneously (they bind to different ports), but it's recommended to use only ida-multi-mcp.

## Uninstallation

```bash
# Remove IDA plugin, registry, and MCP client configurations
ida-multi-mcp --uninstall

# Remove the Python package
pip uninstall ida-multi-mcp
# If installed via pipx:
pipx uninstall ida-multi-mcp
```

The `--uninstall` command automatically removes the IDA plugin, cleans up the registry, and removes MCP client configurations.
