# ida-multi-mcp

Multi-instance IDA Pro MCP server for simultaneous reverse engineering of multiple binaries through a single MCP endpoint. Supports both GUI instances and headless analysis via idalib (IDA Pro only).

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.3%2B-orange.svg)
![MCP](https://img.shields.io/badge/MCP-compatible-brightgreen.svg)

## Why ida-multi-mcp?

Analyze multiple binaries in parallel — dropper, payload, C2 — through a single MCP connection. Each IDA Pro instance auto-registers on startup; your LLM client sees every instance without touching its config.

## Quick Start

**Just ask your AI agent to install it.** Copy-paste one of these prompts — it handles the Python version matching, IDA plugin placement, and MCP client registration for you.

**Claude Code / AmpCode:**
> Install and configure ida-multi-mcp by following the instructions here: https://raw.githubusercontent.com/MeroZemory/ida-multi-mcp/main/docs/installation.md

**Cursor:**
> @Web fetch https://raw.githubusercontent.com/MeroZemory/ida-multi-mcp/main/docs/installation.md and follow the installation steps.

Once installed, open your binaries in IDA Pro (instances auto-register) and ask your LLM:
> *"Decompile `main` in malware.exe (k7m2) and compare it with the entry point in dropper.dll (px3a)"*

Prefer to install by hand? See [Manual Installation](#manual-installation) below.

## How It Works

```
MCP Client (Claude, Cursor, etc.)
    │  stdio (MCP Protocol)
    ▼
┌──────────────────────────────────────┐
│  ida-multi-mcp Server (Router)       │
│  - Dynamic tool discovery            │
│  - instance_id routing               │
│  - Management + idalib lifecycle     │
└───┬──────┬──────┬──────┬─────────────┘
    │      │      │      │  HTTP JSON-RPC
    ▼      ▼      ▼      ▼
  IDA #1  IDA #2  IDA #3  idalib #1
  (GUI)   (GUI)   (GUI)   (headless)
```

## Features

- **Zero-configuration instance discovery** — Each IDA Pro instance auto-registers on startup
- **Headless analysis (IDA Pro)** — Open binaries without GUI via `idalib_open` — each session runs as an isolated subprocess
- **Port-collision free** — Uses OS auto-assigned ports (port 0)
- **Dynamic tool discovery** — All 80+ IDA tools available automatically
- **1-call binary triage** — `survey_binary` returns metadata, segments, top strings/functions, imports, and call graph in one call
- **Cross-binary analysis** — Target specific instances via `instance_id` parameter
- **Smart instance tracking** — 4-character IDs (k7m2, px3a, etc.) with automatic binary-change detection
- **IDA 8.3–9.3 compatible** — Built-in version compatibility shims (`compat.py`)
- **File-based registry** — Tracks all active instances (GUI and headless)
- **Graceful fallback** — Handles binary changes, stale instances, and crashes

## Requirements

- Python 3.11 or later
- IDA Pro 8.3+ (9.0 recommended)

## Manual Installation

> Already used the AI-agent prompt in [Quick Start](#quick-start)? You can skip this section.

Pick your platform:

<details>
<summary><b>macOS</b> — requires matching IDA's Python version</summary>

> **Important:** IDA Pro typically uses a different Python version than your system default (e.g., IDA uses Python 3.11 while macOS ships with 3.14). You must install the package for **both** your terminal Python and IDA's Python.

**Step 1: Check IDA's Python version**

Open IDA Pro, then in the IDA console run:
```
Python> import sys; print(sys.version)
```
Note the version (e.g., `3.11`).

**Step 2: Install**

```bash
# 1. Install CLI tool via pipx (for terminal commands)
pipx install git+https://github.com/MeroZemory/ida-multi-mcp.git

# 2. Install package for IDA's Python (replace 3.11 with your IDA's version)
python3.11 -m pip install --user git+https://github.com/MeroZemory/ida-multi-mcp.git

# 3. Install IDA plugin + configure MCP clients
ida-multi-mcp --install

# 4. Configure Claude Code manually (recommended over --install for Claude Code)
claude mcp add ida-multi-mcp -s user -- ida-multi-mcp
```

> **Note:** `ida-multi-mcp --install` registers MCP servers using `python3 -m ida_multi_mcp`, which may point to the wrong Python version on macOS. For Claude Code, use `claude mcp add` as shown above to ensure it uses the pipx-managed CLI directly.

</details>

<details>
<summary><b>Windows</b></summary>

```bash
# 0. (Recommended) Clean previous install to avoid stale scripts/config
ida-multi-mcp --uninstall
python -m pip uninstall -y ida-multi-mcp

# 1. Install ida-multi-mcp
python -m pip install git+https://github.com/MeroZemory/ida-multi-mcp.git

# 2. Install IDA plugin + configure all MCP clients
ida-multi-mcp --install
```

> If IDA uses a different Python version than your default, use `py -3.12` (replace with IDA's version) instead of `python`.
> If you manually edit `%USERPROFILE%\\.codex\\config.toml`, use literal TOML quoting for Windows paths (e.g., `[projects.'\\?\\C:\\path\\to\\repo']`, `command = 'C:\\...\\python.exe'`).

</details>

<details>
<summary><b>Linux</b></summary>

```bash
# 1. Install ida-multi-mcp
pip install --user git+https://github.com/MeroZemory/ida-multi-mcp.git

# 2. Install IDA plugin + configure MCP clients
ida-multi-mcp --install
```

</details>

### AI-agent reference

The canonical installation guide an AI agent should follow is at
[`docs/installation.md`](https://raw.githubusercontent.com/MeroZemory/ida-multi-mcp/main/docs/installation.md). It covers platform-specific package installation, IDA Python version matching, plugin setup via `ida-multi-mcp --install`, and verification.

### Supported MCP Clients

Works with any MCP-compatible client. `ida-multi-mcp --install` auto-configures all detected clients (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Zed, and 20+ more).

<details>
<summary>Full tested client list (19)</summary>

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

</details>

### Manual MCP Client Configuration

For clients not auto-detected or to view the raw configuration JSON:
```bash
ida-multi-mcp --config
```

## Uninstallation

<details>
<summary><b>macOS</b></summary>

```bash
# 1. Remove IDA plugin + MCP client configurations
ida-multi-mcp --uninstall

# 2. Remove packages
pipx uninstall ida-multi-mcp
python3.11 -m pip uninstall -y ida-multi-mcp  # replace 3.11 with IDA's version
```

</details>

<details>
<summary><b>Windows</b></summary>

```bash
# 1. Remove IDA plugin + MCP client configurations
ida-multi-mcp --uninstall

# (optional) If IDA is installed in a custom location
ida-multi-mcp --uninstall --ida-dir "C:\Program Files\IDA Pro 9.0"

# 2. Remove the Python package
python -m pip uninstall -y ida-multi-mcp
```

</details>

After uninstalling, fully restart IDA Pro and your MCP client(s) so the removed configuration is picked up.

## Usage

### Opening Multiple Binaries (GUI Mode)

1. Open IDA Pro and load your first binary (e.g., `malware.exe`)
   - Plugin auto-loads (PLUGIN_FIX flag)
   - Instance auto-registers with 4-char ID (e.g., `k7m2`)

2. Open another IDA Pro instance with a second binary (e.g., `dropper.dll`)
   - Another instance auto-registers (e.g., `px3a`)

3. Repeat for more binaries

### Headless Analysis (IDA Pro Only)

> **Requires IDA Pro license.** IDA Home/Free do not include `idalib`.

Open binaries without a GUI — each session runs as an isolated subprocess:

```
> Use idalib_open to analyze /path/to/malware.exe headlessly
```

The LLM calls `idalib_open(input_path="/path/to/malware.exe")`, which spawns a headless idalib process, waits for auto-analysis, and returns an `instance_id`. From that point, all 80+ IDA tools work exactly as with a GUI instance.

To specify a custom Python with `idapro` installed, start the server with:
```bash
ida-multi-mcp --idalib-python /path/to/python3.11
```

### Viewing Registered Instances

```bash
ida-multi-mcp --list
```

Output:
```
Registered IDA instances (3):

  k7m2
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

Once connected, all 80+ IDA tools are available. **All IDA tool calls require** the `instance_id` parameter to avoid cross-agent contention.

**Analyzing a single instance:**
```
Decompile the main function in malware.exe (k7m2)
```

**Cross-binary analysis:**
```
Decompile main in malware.exe (k7m2) and compare it with the entry point in dropper.dll (px3a)
```

## Management Tools

The server provides built-in management tools:

### list_instances()
Lists all registered instances with metadata (binary name, path, architecture, port, **type**: `gui` or `idalib`).

### refresh_tools()
Re-discovers tools from IDA instances. Use this if you update the IDA plugin.

### get_cached_output(cache_id, offset, size)
Retrieve cached output from a previous tool call that was truncated.

### decompile_to_file(...)
Decompile functions and save results directly to files on disk. Requires `instance_id`.

### idalib_open(input_path, timeout, unsafe) *(IDA Pro only)*
Open a binary in a new headless idalib session. Spawns a subprocess, waits for auto-analysis, registers in the shared registry.

### idalib_close(instance_id) *(IDA Pro only)*
Terminate a headless idalib session and remove it from the registry.

### idalib_list() *(IDA Pro only)*
List all managed headless idalib sessions.

### idalib_status(instance_id) *(IDA Pro only)*
Health/readiness check for a specific idalib session.

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
ida-multi-mcp --idalib-python /path/to/python3  # custom Python for headless sessions
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
ida-multi-mcp --install --ida-dir "C:\Program Files\IDA Pro 9.0"  # Windows custom path
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

Location:
- macOS/Linux: `~/.ida-mcp/instances.json`
- Windows: `%USERPROFILE%\.ida-mcp\instances.json`

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

## Troubleshooting

<details>
<summary>"No IDA instances registered"</summary>

Make sure:
1. IDA Pro is running with a binary loaded
2. Check IDA's plugin list (Edit → Plugins → Scan) to confirm `ida-multi-mcp` plugin loaded
3. Check IDA console for error messages
4. Run `ida-multi-mcp --list` again

</details>

<details>
<summary>"Instance 'k7m2' not found"</summary>

The instance has crashed or expired. Run:
```bash
ida-multi-mcp --list
```
to see available instances, then use a valid ID.

</details>

<details>
<summary>"Instance 'k7m2' expired. Replaced by 'px3a'"</summary>

You opened a different binary in that IDA instance. This is expected. Use the new instance ID (`px3a`).

</details>

<details>
<summary>Plugin doesn't load in IDA / "No module named 'ida_multi_mcp'"</summary>

This usually means IDA's Python cannot find the package due to a **Python version mismatch**.

1. Check IDA's Python version — in the IDA console, run:
   ```
   import sys; print(sys.version)
   ```
2. Install the package for that specific Python version:

   **macOS:**
   ```bash
   # Replace 3.11 with IDA's actual Python version
   python3.11 -m pip install --user git+https://github.com/MeroZemory/ida-multi-mcp.git
   ```

   **Windows:**
   ```bash
   # Replace 3.12 with IDA's actual Python version
   py -3.12 -m pip install git+https://github.com/MeroZemory/ida-multi-mcp.git
   ```

3. Ensure the IDA plugins directory contains `ida_multi_mcp.py`:
   - macOS/Linux: `~/.idapro/plugins/`
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
4. Restart IDA Pro

</details>

<details>
<summary>MCP server fails to connect (macOS)</summary>

If your MCP client shows `Status: failed` for ida-multi-mcp, the registered command may point to the wrong Python version.

1. Check what command is configured (e.g., in `.claude.json`, `.cursor/mcp.json`)
2. If it shows `python3 -m ida_multi_mcp`, replace it with the pipx-managed CLI:

   **Claude Code:**
   ```bash
   claude mcp remove ida-multi-mcp -s user
   claude mcp add ida-multi-mcp -s user -- ida-multi-mcp
   ```

   **Other clients:** Edit the MCP config JSON and change:
   ```json
   {
     "command": "ida-multi-mcp",
     "args": []
   }
   ```

3. Restart the MCP client

</details>

<details>
<summary>Codex fails to start on Windows with TOML parse error</summary>

If Codex prints an error like `invalid unquoted key` for `%USERPROFILE%\.codex\config.toml`, the config contains Windows paths that are not valid TOML syntax.

Use literal quoted keys/strings for Windows paths:

```toml
[projects.'\\?\C:\Git\MeroZemory\tidy-up']
trust_level = "trusted"

[mcp_servers.ida-multi-mcp]
command = 'C:\Users\MeroZemory\AppData\Local\Programs\Python\Python311\python.exe'
args = ["-m", "ida_multi_mcp"]
```

Do not use unquoted `\\?\...` project table keys, and do not use double-quoted Windows paths unless backslashes are escaped.

</details>

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Port 0 (auto-assigned) | Eliminates port conflicts, scales to unlimited instances |
| 4-char base36 IDs | Short, readable, 1.68M combinations, easy to remember |
| File-based registry | Simple, cross-process, debuggable, no database dependency |
| Dynamic tool discovery | Future-proof, automatic updates, no hardcoded tool list |
| Dual binary-change detection | Robust fallback if IDA hooks fail |
| Subprocess-per-binary (idalib) | True parallelism, crash isolation, no in-process DB switching |
| compat.py shims | Single source for IDA 8.3–9.3 API differences |

## Performance

- Registry operations: <1ms (JSON file, file-locked)
- Tool discovery: ~50ms per IDA instance (one-time cache)
- Tool call routing: <5ms (local HTTP JSON-RPC)
- Heartbeat interval: 60 seconds (negligible overhead)

## Limitations

- Supports 127.0.0.1 only (localhost analysis)
- Remote IDA instances not supported in v1.0
- Headless (idalib) mode requires **IDA Pro** — IDA Home/Free do not include `idalib.dll`
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

This project was inspired by and builds upon [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by [Duncan Ogilvie (mrexodia)](https://github.com/mrexodia). The IDA tool implementations (80+ tools) originated from ida-pro-mcp and have been absorbed into ida-multi-mcp as a bundled package, adding multi-instance orchestration and headless idalib support on top.

The installation approach (AI-agent-friendly installation guides) was influenced by [oh-my-opencode](https://github.com/code-yeongyu/oh-my-opencode) by [Yeongyu Yun (code-yeongyu)](https://github.com/code-yeongyu).

## Related Projects

- **[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)** — The original single-instance IDA MCP plugin (tools originated from here) (MIT License)
- **Claude Code** — MCP client with native support
- **Cursor** — Alternative MCP-enabled editor

## Support

For issues, feature requests, or questions:
- Check the troubleshooting section above
- Review `docs/.ssot/architectures/` for architecture details
- Open an issue on GitHub

## Star History

<a href="https://www.star-history.com/?repos=MeroZemory%2Fida-multi-mcp&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/image?repos=MeroZemory/ida-multi-mcp&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/image?repos=MeroZemory/ida-multi-mcp&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/image?repos=MeroZemory/ida-multi-mcp&type=date&legend=top-left" />
 </picture>
</a>
