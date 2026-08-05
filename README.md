<div align="center">

# ida-multi-mcp

[![MCP Toplist](https://mcptoplist.com/badge/pulsemcp%2Fmerozemory-ida-multi.svg)](https://mcptoplist.com/server/pulsemcp%2Fmerozemory-ida-multi)

**Reverse-engineer several binaries at once — dropper, payload, C2 — through a single MCP endpoint.**

Every IDA Pro instance auto-registers on startup, so your LLM client sees all of them without touching its config. Includes local, name-independent function-similarity search across binaries.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#requirements)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.5%2B-orange.svg)](#requirements)
[![MCP](https://img.shields.io/badge/MCP-compatible-brightgreen.svg)](#supported-mcp-clients)

</div>

## ✨ What's New

*Newest first.*

- **⏳ Auto-analysis gating** — `analysis_status()` and `analysis_wait()` let an agent find out whether IDA has actually settled before it draws conclusions, and the router attaches a warning to results from analysis-dependent tools while an instance is still analysing. `server_health`'s `auto_analysis_ready` flag was **inverted**, reporting "ready" exactly when analysis was still running. Waiting properly is worth **12,885 functions** on a 23 MB DLL (61,044 → 73,929) that an unwaiting agent would never see. Note the completion flag is a snapshot rather than a latch — [why](#wait-for-auto-analysis-before-you-trust-anything). `idb_save` also no longer takes the save-as path in the GUI.
- **⚡ Genuinely parallel instances** — the router used to dispatch one request at a time, so a slow call on one binary stalled every other binary behind it. Requests now run on a worker pool with only the stdout writes serialized. Measured against two live instances: a call to instance B while instance A was busy went from **3.41 s → 0.01 s**. ([#27](https://github.com/MeroZemory/ida-multi-mcp/pull/27))
- **⏱️ Slow scans no longer freeze an instance** — a long C-level SDK call (`find_bytes`, `decompile`, string building) could hold IDA's main thread far past the tool timeout, because a Python-level timeout cannot preempt C. The deadline now fires IDA's own `set_cancelled()`, which those calls poll and honour; `find`/`find_bytes` report `cursor.cancelled` so a partial page is distinguishable from a finished one. ([#28](https://github.com/MeroZemory/ida-multi-mcp/pull/28))
- **🔎 Function similarity search (BCSD)** — locate the same or similar function *within a binary or across instances* (patch diffing, library-function ID, variant hunting). Name-independent signals that survive stripping — instruction-shingle MinHash + imported-API / string / constant anchors + CFG structure/shape — with an optional on-demand **local neural** recall (jTrans embeddings) for cross-compiler twins. All local, no cloud. → [details](#function-similarity-bcsd)

## Contents

**On this page** — [Quick Start](#quick-start) · [How It Works](#how-it-works) · [Features](#features) · [Requirements](#requirements) · [Manual Installation](#manual-installation) · [Usage](#usage) · [Function Similarity (BCSD)](#function-similarity-bcsd) · [Limitations](#limitations)

**Reference** — [Tools](docs/tools.md) · [CLI](docs/cli.md) · [Architecture](docs/architecture.md) · [Performance](docs/performance.md) · [Troubleshooting](docs/troubleshooting.md)

## Quick Start

**Just ask your AI agent to install it.** Copy-paste one of these prompts — it handles the Python version matching, IDA plugin placement, and MCP client registration for you.

**Claude Code / Codex:**
> Install and configure ida-multi-mcp by following the instructions here: https://raw.githubusercontent.com/MeroZemory/ida-multi-mcp/main/docs/installation.md

**Cursor:**
> @Web fetch https://raw.githubusercontent.com/MeroZemory/ida-multi-mcp/main/docs/installation.md and follow the installation steps.

Once installed, open your binaries in IDA Pro (instances auto-register) and ask your LLM:
> *"Decompile `main` in malware.exe (k7m2) and compare it with the entry point in dropper.dll (px3a)"*

Prefer to install by hand? See [Manual Installation](#manual-installation) below; removing it
again is covered in [Troubleshooting](docs/troubleshooting.md#uninstallation).

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

## Usage

### Opening Multiple Binaries (GUI Mode)

1. Open IDA Pro and load your first binary (e.g., `malware.exe`)
   - Plugin auto-loads (PLUGIN_FIX flag)
   - Instance auto-registers with 4-char ID (e.g., `k7m2`)

2. Open another IDA Pro instance with a second binary (e.g., `dropper.dll`)
   - Another instance auto-registers (e.g., `px3a`)

3. Repeat for more binaries

**Skipping the load dialog.** Opening a new binary normally pops IDA's "Load a new file"
configuration dialog, which blocks before the plugin is running — nothing on the MCP side
can dismiss it. Launch IDA in autonomous mode to accept the defaults and go straight to
analysis:

```bash
ida -A path/to/binary.exe
```

### Wait for auto-analysis before you trust anything

On a freshly opened binary IDA analyses in the background, and **function lists, xrefs and
decompilation are incomplete until it settles**. On an 8.5 MB DLL the function count went
from 9,580 to 13,252 — 28% of the functions did not exist yet. On a 23 MB DLL it was 12,885.

```
analysis_status()               -> {"queue_empty": false, "function_count": 61044}
analysis_wait(timeout_sec=200)  -> {"finished": true, "functions_added": 12884}
```

- **`analysis_status()`** — non-blocking snapshot: queue state, current phase, function
  count so far.
- **`analysis_wait(timeout_sec=120)`** — drives analysis to completion and returns.
  `finished: false` means the wait timed out, not that it failed; call it again.

If you only do one thing, call `analysis_wait` once after opening a binary. The router also
attaches a warning to results from analysis-dependent tools while an instance is still
analysing, so a partial answer is not silently mistaken for a complete one.

<details>
<summary>Why "finished" is a snapshot, not a latch</summary>

`finished` / `queue_empty` come from IDA's `auto_is_ok()`, which answers *"are the analysis
queues empty right now"*. IDA re-queues work as it goes, so the flag can read `true` and then
`false` again moments later — observed directly on a 23 MB DLL, where `analysis_wait`
returned `finished: true` and the very next `analysis_status` reported `false` on the same
idle instance.

Read it as: **`false` means definitely not done**. `true` means nothing is queued at that
instant. The durable signal is `functions_added` reaching 0 across successive calls.

Three phases are involved, which is why this is fiddly. IDA's background analysis does the
bulk on its own and then plateaus without ever flipping the flag; `auto_make_step()` drains
the residual queue; and a final `auto_wait()` pass — 34.5 s on that DLL, adding zero
functions — is the only thing that clears the queues. `analysis_wait` handles all three, in
bounded slices, so the instance stays responsive throughout.

</details>

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

## Function Similarity (BCSD)
Local, cross-instance binary code similarity — no cloud, no external service. Signals are name-independent (survive stripping): instruction-shingle MinHash, IDF-weighted imported-API / string / constant anchors, and CFG structure/shape, plus symbol-gated pseudocode tokens. An optional `[neural]` extra adds on-demand jTrans embeddings for anchor-less cross-compiler matches.

- **`index_functions(instance_id, rebuild=False)`** — build/refresh the searchable index for a binary (content-hash keyed, persisted under `~/.ida-mcp/index/`, incremental, backgroundable).
- **`index_status(instance_id)`** — index readiness, function count, staleness, and background progress.
- **`similar_functions(instance_id, func, top_k=20, scope="binary"|"instances"|"all")`** — rank the most similar functions within the binary or across instances; returns a per-signal breakdown and confidence label.
- **`compare_functions(a, b)`** — direct pairwise similarity between two functions (optionally across instances).


## Documentation

| | |
|---|---|
| [Tools](docs/tools.md) | Management tools, idalib session control, similarity tools |
| [CLI](docs/cli.md) | `--list`, `--install`, `--uninstall`, `--config` |
| [Architecture](docs/architecture.md) | Registry layout, request routing, health monitoring, instance IDs, design trade-offs |
| [Performance](docs/performance.md) | Benchmarks on a 736K-function binary |
| [Troubleshooting](docs/troubleshooting.md) | Plugin not loading, Python mismatch, stale instances, uninstalling |
| [Installation guide](docs/installation.md) | The canonical guide an AI agent should follow |
| [Function similarity examples](docs/function-similarity-usage.md) | Worked BCSD examples against stripped binaries |
| [Upstream comparison](docs/ida-pro-mcp/comparison.md) | What has been adopted from ida-pro-mcp, and contributed back |

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
