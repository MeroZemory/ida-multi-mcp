# ida-multi-mcp Installation Guide

This guide is for AI agents. Follow each step exactly.

Last updated: 2026-02-17
Governance reference: `docs/PROJECT_GOVERNANCE.md`
Authority note: this document is operational guidance and must not redefine contracts.

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

## Agent Execution Contract (for AI tools)

When an AI agent follows this guide, it should execute the workflow in this exact order:
1. Run **Pre-flight Auto-Diagnostics** and fix blocking issues.
2. Run platform-specific **Installation** steps.
3. Run **Post-flight Auto-Diagnostics**.
4. If any check fails, run **Auto-Remediation Playbook**, then re-run post-flight checks.
5. Do not report success until all required checks pass.

## Pre-flight Auto-Diagnostics

Run these checks before installing.

### 1) Python / pip baseline

```bash
python --version
python -m pip --version
```

Pass criteria:
- Python is `3.11+`
- `pip` command works for the same interpreter

### 2) CLI availability check (non-blocking)

```bash
ida-multi-mcp --list
```

Interpretation:
- If this fails with command not found, installation is still allowed.
- If this succeeds, record current state for comparison after install.

### 3) IDA plugin directory write check

macOS/Linux:
```bash
test -d ~/.idapro/plugins || mkdir -p ~/.idapro/plugins
test -w ~/.idapro/plugins && echo "plugins dir writable"
```

Windows (PowerShell):
```powershell
if (!(Test-Path "$env:APPDATA\\Hex-Rays\\IDA Pro\\plugins")) { New-Item -ItemType Directory -Path "$env:APPDATA\\Hex-Rays\\IDA Pro\\plugins" | Out-Null }
if (Test-Path "$env:APPDATA\\Hex-Rays\\IDA Pro\\plugins") { "plugins dir exists" }
```

### 4) Optional cleanup of stale installs (recommended)

```bash
ida-multi-mcp --uninstall
```

If command is unavailable, continue with install.

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

If Codex fails to start with a TOML parse error from `%USERPROFILE%\.codex\config.toml`, fix Windows paths as literal TOML strings/keys.

Use this form (safe):
```toml
[projects.'\\?\C:\Git\MeroZemory\tidy-up']
trust_level = "trusted"

[mcp_servers.ida-multi-mcp]
command = 'C:\Users\MeroZemory\AppData\Local\Programs\Python\Python311\python.exe'
args = ["-m", "ida_multi_mcp"]
```

Avoid this form (invalid in TOML):
```toml
[projects.\\?\C:\Git\MeroZemory\tidy-up]  # invalid unquoted key
command = "C:\Users\...\python.exe"       # backslashes parsed as escapes
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

## Post-flight Auto-Diagnostics

Run these checks immediately after installation.

### 1) CLI and module import health

```bash
ida-multi-mcp --config
python -c "import ida_multi_mcp; print(ida_multi_mcp.__version__)"
```

Pass criteria:
- `--config` prints valid JSON
- Python import succeeds

### 2) Plugin deployment health

macOS/Linux:
```bash
ls -l ~/.idapro/plugins/ida_multi_mcp.py
```

Windows (PowerShell):
```powershell
Get-Item "$env:APPDATA\\Hex-Rays\\IDA Pro\\plugins\\ida_multi_mcp.py"
```

Pass criteria:
- loader file exists in IDA plugins directory

### 3) Runtime registration health (requires IDA open with a binary)

```bash
ida-multi-mcp --list
```

Pass criteria:
- at least 1 registered instance appears

### 4) MCP tool-plane health (from AI client)

Required calls:
1. `list_instances()`
2. one safe tool with explicit `instance_id` (e.g. `list_funcs` with small pagination)

Pass criteria:
- both calls succeed without transport/protocol errors

## Auto-Remediation Playbook

If post-flight checks fail, apply fixes in order.

1. Python mismatch suspected:
   - Re-check IDA console Python version (`import sys; print(sys.version)`).
   - Reinstall with that exact version (`python3.11 -m pip install ...` or `py -3.12 -m pip install ...`).
2. Plugin loader missing:
   - Re-run `ida-multi-mcp --install` (or `--install --ida-dir <IDA_DIR>` for custom installs).
3. No instances registered:
   - Restart IDA.
   - Open any binary.
   - Confirm IDA output contains registration log.
   - Re-run `ida-multi-mcp --list`.
4. MCP client cannot call tools:
   - Restart the MCP client process.
   - Re-check client config (`ida-multi-mcp --config`).
5. Still failing:
   - Run clean reinstall:
     - `ida-multi-mcp --uninstall`
     - uninstall package (`pip uninstall ida-multi-mcp` and/or `pipx uninstall ida-multi-mcp`)
     - install again from scratch

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
