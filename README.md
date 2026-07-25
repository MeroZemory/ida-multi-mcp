<div align="center">

# ida-multi-mcp

**Reverse-engineer several binaries at once — dropper, payload, C2 — through a single MCP endpoint.**

Every IDA Pro instance auto-registers on startup, so your LLM client sees all of them without touching its config. Includes local, name-independent function-similarity search across binaries.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#requirements)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.5%2B-orange.svg)](#requirements)
[![MCP](https://img.shields.io/badge/MCP-compatible-brightgreen.svg)](#supported-mcp-clients)

</div>

## ✨ What's New

*Newest first.*

- **⚡ Genuinely parallel instances** — the router used to dispatch one request at a time, so a slow call on one binary stalled every other binary behind it. Requests now run on a worker pool with only the stdout writes serialized. Measured against two live instances: a call to instance B while instance A was busy went from **3.41 s → 0.01 s**. ([#27](https://github.com/MeroZemory/ida-multi-mcp/pull/27))
- **⏱️ Slow scans no longer freeze an instance** — a long C-level SDK call (`find_bytes`, `decompile`, string building) could hold IDA's main thread far past the tool timeout, because a Python-level timeout cannot preempt C. The deadline now fires IDA's own `set_cancelled()`, which those calls poll and honour; `find`/`find_bytes` report `cursor.cancelled` so a partial page is distinguishable from a finished one. ([#28](https://github.com/MeroZemory/ida-multi-mcp/pull/28))
- **🔎 Function similarity search (BCSD)** — locate the same or similar function *within a binary or across instances* (patch diffing, library-function ID, variant hunting). Name-independent signals that survive stripping — instruction-shingle MinHash + imported-API / string / constant anchors + CFG structure/shape — with an optional on-demand **local neural** recall (jTrans embeddings) for cross-compiler twins. All local, no cloud. → [details](#function-similarity-bcsd)

## Contents

**Start here** — [Quick Start](#quick-start) · [How It Works](#how-it-works) · [Features](#features) · [Requirements](#requirements) · [Manual Installation](#manual-installation)

**Using it** — [Usage](#usage) · [Function Similarity (BCSD)](#function-similarity-bcsd) · [Limitations](#limitations)

**Reference** *(collapsed below)* — [Management Tools](#management-tools) · [CLI Commands](#cli-commands) · [Architecture](#architecture) · [Instance IDs](#instance-ids-explained) · [Design Decisions](#design-decisions) · [Performance](#performance) · [Troubleshooting](#troubleshooting) · [Uninstallation](#uninstallation)

## Quick Start

**Just ask your AI agent to install it.** Copy-paste one of these prompts — it handles the Python version matching, IDA plugin placement, and MCP client registration for you.

**Claude Code / Codex:**
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

- 🔌 **Zero-configuration discovery** — every IDA Pro instance auto-registers on startup; nothing to add to your MCP client config
- ⚡ **Parallel across instances** — requests to different binaries are dispatched concurrently, so one slow call does not stall the rest
- 🖥️ **Headless analysis (IDA Pro)** — open binaries without a GUI via `idalib_open`; each session is an isolated subprocess
- 🔎 **Function-similarity search** — `similar_functions` / `compare_functions` rank BCSD matches (instruction-shingle MinHash + API/string/constant anchors + CFG/shape) within a binary or across instances. Optional **neural recall** (jTrans embeddings) recovers anchor-less cross-compiler twins that lexical/structural signals miss — `pip install ida-multi-mcp[neural]` + `IDA_MCP_SIM_NEURAL=1` (model auto-downloads to `~/.ida-mcp/models/`)
- 🩺 **1-call binary triage** — `survey_binary` returns metadata, segments, top strings/functions, imports, and call graph in one call
- 🔀 **Cross-binary analysis** — target any instance via the `instance_id` parameter
- 🧰 **Dynamic tool discovery** — 90 IDA tools, no hardcoded list. 73 are exposed by default; the 16 debugger tools sit behind an `?ext=dbg` gate
- 🏷️ **Smart instance tracking** — 4-character IDs (`k7m2`, `px3a`) with automatic binary-change detection
- 🧯 **Graceful fallback** — handles binary changes, stale instances, and crashes with actionable errors
- 🔒 **Localhost only** — loopback-bound with Host/Origin validation; no remote surface
- 🧩 **IDA 8.5–9.3 compatible** — `compat.py` shims the APIs that moved between releases (entry points, `inf_*` accessors, type ordinals, UDM lookup, `guess_tinfo`) and warns on IDA 9.0 SP0, which shipped without several of them

## Requirements

- Python 3.11 or later
- IDA Pro 8.5+ (9.1 or later recommended)

> **IDA 9.0 SP0 (build 240925) is not supported.** That build shipped without `func_t.get_name`, `func_t.get_prototype`, and `tinfo_t.get_udm`, which several tools call directly. Use IDA 9.0 SP1 (build 241217) or later.

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

Works with any MCP-compatible client. `ida-multi-mcp --install` auto-configures all detected clients (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Zed, and 20 more).

<details>
<summary>Full auto-configured client list (26)</summary>

| Client | Type |
|--------|------|
| Claude Code | CLI |
| Claude Desktop | Desktop |
| Cursor | IDE |
| VS Code (Copilot) | IDE |
| Windsurf | IDE |
| Zed | IDE |
| Antigravity IDE | IDE |
| Augment Code | IDE |
| Cline | Extension |
| Kilo Code | Extension |
| Kiro | IDE |
| LM Studio | Desktop |
| BoltAI | Desktop |
| Perplexity | Desktop |
| Opencode | CLI |
| Qodo Gen | Extension |
| Roo Code | Extension |
| Trae | IDE |
| Warp | Terminal |
| Amazon Q Developer CLI | CLI |
| Copilot CLI | CLI |
| Gemini CLI | CLI |
| Qwen Coder | CLI |
| Codex | CLI |
| Crush | CLI |
| Factory Droid | CLI |

</details>

### Manual MCP Client Configuration

For clients not auto-detected or to view the raw configuration JSON:
```bash
ida-multi-mcp --config
```

<details>
<summary><b>Uninstallation — per-platform removal steps</b></summary>

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

</details>

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

The LLM calls `idalib_open(input_path="/path/to/malware.exe")`, which spawns a headless idalib process, waits for auto-analysis, and returns an `instance_id`. From that point, every IDA tool works exactly as with a GUI instance.

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

Once connected, every IDA tool is available. Tool calls take an `instance_id` to say which binary to act on. It is **required whenever two or more instances are registered**, so concurrent agents cannot collide; with exactly one instance registered it may be omitted and that instance is selected automatically.

**Analyzing a single instance:**
```
Decompile the main function in malware.exe (k7m2)
```

**Cross-binary analysis:**
```
Decompile main in malware.exe (k7m2) and compare it with the entry point in dropper.dll (px3a)
```

**Function similarity (patch diff, library ID, variant hunting):**
```
Index malware.exe (k7m2) and dropper.dll (px3a), then find the function in dropper.dll most similar to sub_140001000 in malware.exe
```

<details>
<summary><b>Management Tools — list_instances, refresh_tools, idalib_*, similarity tools</b></summary>

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

</details>

## Function Similarity (BCSD)
Local, cross-instance binary code similarity — no cloud, no external service. Signals are name-independent (survive stripping): instruction-shingle MinHash, IDF-weighted imported-API / string / constant anchors, and CFG structure/shape, plus symbol-gated pseudocode tokens. An optional `[neural]` extra adds on-demand jTrans embeddings for anchor-less cross-compiler matches.

- **`index_functions(instance_id, rebuild=False)`** — build/refresh the searchable index for a binary (content-hash keyed, persisted under `~/.ida-mcp/index/`, incremental, backgroundable).
- **`index_status(instance_id)`** — index readiness, function count, staleness, and background progress.
- **`similar_functions(instance_id, func, top_k=20, scope="binary"|"instances"|"all")`** — rank the most similar functions within the binary or across instances; returns a per-signal breakdown and confidence label.
- **`compare_functions(a, b)`** — direct pairwise similarity between two functions (optionally across instances).


<details>
<summary><b>Instance IDs Explained — how the 4-char IDs are derived and when they change</b></summary>

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

</details>

<details>
<summary><b>CLI Commands — <code>--list</code>, <code>--install</code>, <code>--uninstall</code>, <code>--config</code></b></summary>

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

</details>

<details>
<summary><b>Architecture — registry layout, plugin directory, routing, health monitoring</b></summary>

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

</details>

<details>
<summary><b>Troubleshooting — plugin not loading, wrong Python, stale instances, Codex TOML</b></summary>

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

</details>

<details>
<summary><b>Design Decisions — the trade-offs behind the architecture</b></summary>

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Port 0 (auto-assigned) | Eliminates port conflicts, scales to unlimited instances |
| 4-char base36 IDs | Short, readable, 1.68M combinations, easy to remember |
| File-based registry | Simple, cross-process, debuggable, no database dependency |
| Dynamic tool discovery | Future-proof, automatic updates, no hardcoded tool list |
| Dual binary-change detection | Robust fallback if IDA hooks fail |
| Subprocess-per-binary (idalib) | True parallelism, crash isolation, no in-process DB switching |
| compat.py shims | Single source for IDA 8.5–9.3 API differences |
| Worker pool for stdio dispatch | Instances are separate processes; serializing at the router wasted that. Only stdout writes are locked (`IDA_MCP_STDIO_WORKERS`) |
| Deadline fires IDA's `set_cancelled()` | A Python-level timeout cannot preempt a C SDK call; IDA's own cancel flag can (`IDA_MCP_CANCEL_GRACE_SEC`) |

</details>

<details>
<summary><b>Performance — benchmarks on a 736K-function binary</b></summary>

## Performance

Benchmarked against a large game client (736K functions, x86-64, IDA 9.3):

| Metric | Value |
|---|---:|
| Total tool latency (28 tools) | **32.0 s** |
| Total response payload | 373 KB |
| Estimated token cost | ~93K tokens |

| Category | Latency | Tokens |
|---|---:|---:|
| Triage (`survey_binary`) | 17.0 s | ~77K |
| Query (`func_query`, `imports_query`) | 7.5 s | ~2.4K |
| Navigation (`list_funcs`, `find_*`, `xrefs_*`) | 5.5 s | ~8.5K |
| Analysis (`decompile`, `analyze_function`) | 41 ms | ~3.7K |
| Modification (`set_comments`, `append_comments`) | 4 ms | ~125 |

Infrastructure overhead:
- Registry operations: <1ms (JSON file, file-locked)
- Tool discovery: ~50ms per IDA instance (one-time cache)
- Tool call routing: <5ms (local HTTP JSON-RPC)
- Heartbeat interval: 60 seconds (negligible overhead)

**Cross-instance dispatch.** Measured against two live GUI instances, issuing a call to
instance B while instance A was busy for ~3.7 s:

| | Before ([#27](https://github.com/MeroZemory/ida-multi-mcp/pull/27)) | After |
|---|---:|---:|
| Response time for the call to instance B | 3.41 s | **0.01 s** |

[Full benchmark report with per-tool detail &rarr;](docs/benchmark-report.md)

</details>

## Limitations

- **Localhost only.** The router binds loopback and refuses non-loopback instances; remote IDA instances are not supported.
- **stdio transport only.** The router speaks stdio to the MCP client — there is no HTTP/SSE endpoint for remote or containerized clients.
- **Headless (idalib) requires IDA Pro.** IDA Home and IDA Free do not ship `idalib`.
- **Concurrency is *across* instances, not within one.** IDA executes on a single main thread, so two calls to the *same* instance still queue.
- **Cancellation is not forwarded to IDA.** `notifications/cancelled` reaches the router, but the router→IDA hop is a blocking HTTP request; the per-tool deadline is what bounds a runaway call.
- **Resources (as opposed to tools) require manual routing.**

## License

MIT

## Contributing

Contributions welcome! Please ensure:
- Python 3.11+ compatibility
- Cross-platform (Windows, macOS, Linux)
- Clean, readable code
- Tests for new features

## Acknowledgments

This project was inspired by and builds upon [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by [Duncan Ogilvie (mrexodia)](https://github.com/mrexodia). The IDA tool implementations originated from ida-pro-mcp and have been absorbed into ida-multi-mcp as a bundled package, adding multi-instance orchestration and headless idalib support on top. Fixes still flow both ways — see [`docs/ida-pro-mcp/comparison.md`](docs/ida-pro-mcp/comparison.md) for what has been adopted from upstream and what has been sent back.

Upstream has since grown its own multi-session story: `idalib-mcp` is now a supervisor that keeps each open database in a persistent worker process, requires an explicit `database` argument per call, and can adopt an already-running worker or GUI for the same path. The two projects have converged on explicit session routing but differ in approach — ida-multi-mcp discovers GUI instances through a shared file registry that each IDA plugin auto-registers with on startup, so no per-database endpoint configuration is needed on the client side.

## Related Projects

- **[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)** — The upstream IDA MCP plugin this project forked its tool implementations from; now also ships a multi-session `idalib-mcp` supervisor (MIT License)
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
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=MeroZemory/ida-multi-mcp&type=date&theme=dark&legend=top-left&sealed_token=rq_Qr8vB0W0iPa6IsP6zgxDrvFUrJZDwONt5NQxHUjXeoM9y3FNwaYlKwRERctHIR_uLnG6L6ne4Eh4h2srY73COsCSTty0k8JfOKGard7f2w3sTdJiPStA8VzzHOcdrUTOZh0oo0jfQfyPHtVvm5F3uIjlkV_aub7DLk_rmflFwemQmMa_ZFFasFHtp" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=MeroZemory/ida-multi-mcp&type=date&legend=top-left&sealed_token=rq_Qr8vB0W0iPa6IsP6zgxDrvFUrJZDwONt5NQxHUjXeoM9y3FNwaYlKwRERctHIR_uLnG6L6ne4Eh4h2srY73COsCSTty0k8JfOKGard7f2w3sTdJiPStA8VzzHOcdrUTOZh0oo0jfQfyPHtVvm5F3uIjlkV_aub7DLk_rmflFwemQmMa_ZFFasFHtp" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=MeroZemory/ida-multi-mcp&type=date&legend=top-left&sealed_token=rq_Qr8vB0W0iPa6IsP6zgxDrvFUrJZDwONt5NQxHUjXeoM9y3FNwaYlKwRERctHIR_uLnG6L6ne4Eh4h2srY73COsCSTty0k8JfOKGard7f2w3sTdJiPStA8VzzHOcdrUTOZh0oo0jfQfyPHtVvm5F3uIjlkV_aub7DLk_rmflFwemQmMa_ZFFasFHtp" />
 </picture>
</a>
