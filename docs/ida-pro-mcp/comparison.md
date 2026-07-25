# ida-pro-mcp (upstream) vs ida-multi-mcp — Comparison

Last updated: 2026-07-25 (upstream commit `9236fc6`, reviewed range `d80ed7f..9236fc6` = 88 non-merge commits)

This document tracks what upstream fixes ida-multi-mcp has NOT yet adopted, and where the
two projects have diverged architecturally.

## How to refresh this document

The upstream clone lives at `_ref/ida-pro-mcp` (git-excluded via `.git/info/exclude`).

```bash
git -C _ref/ida-pro-mcp fetch origin
git -C _ref/ida-pro-mcp log --no-merges --oneline <last-reviewed>..origin/main -- src/ida_pro_mcp/ida_mcp/
```

Only `src/ida_pro_mcp/ida_mcp/**` is shared code. Upstream's `server.py`, `installer.py`,
`idalib_server.py`, `idalib_supervisor.py`, and `worker_lifecycle.py` have no counterpart
here — ida-multi-mcp has its own router, registry, and subprocess manager.

---

## Upstream is no longer single-instance

The 2026-04 → 2026-07 range brought a supervisor architecture upstream (`c028108`,
`8545e80`, `22aae5f`). `idalib-mcp` now keeps each open database in a persistent worker
process, requires an explicit `database` argument on every tool call, and adopts an
already-running worker or GUI for the same path instead of opening a second one.

Both projects have converged on explicit session routing. The remaining difference is
discovery: ida-multi-mcp's IDA plugin auto-registers each GUI instance into a shared file
registry (`~/.ida-mcp/instances.json`), so the client needs no per-database endpoint
configuration; upstream routes through a supervisor process that owns the workers.

---

## HIGH Priority — Not Yet Adopted

### 1. `sync.py`: reentrant `@idasync` deadlocks the IDA main thread

**Upstream fix**: `85efdf8` (closes upstream #406).

`_sync_wrapper.runned()` uses a blocking `call_stack.get()` in both the pre-check and the
`finally`. If a `@idasync` function synchronously invokes another `@idasync` function, the
inner call drains the LifoQueue; the outer call's `finally` then parks forever on
`Queue.get()` against an empty queue. IDA's main thread freezes and every subsequent tool
call piles up in `execute_sync` and never returns.

**Current state**: `src/ida_multi_mcp/ida_mcp/sync.py:65` and `:75` still use blocking
`get()`. Upstream's fix is a two-line change to `get_nowait()` with `queue.Empty` handling.

### 2. `sync.py`: no native cancellation — ADOPTED

**Cherry-picked from upstream `55533c4`** (addresses upstream #235).

The Python-level `setprofile` timeout cannot preempt pure-C SDK calls. `ida_search.find_*`,
`ida_bytes.find_bytes`/`bin_search`, `ida_hexrays.decompile*`, `ida_strlist.build_strlist`,
and `ida_auto.auto_wait` all run to natural completion regardless of the deadline, holding
the IDA main thread while every queued tool call times out client-side.

Those same SDK calls poll `user_cancelled()`. `ida_kernwin.set_cancelled()` is THREAD_SAFE,
so upstream schedules a `threading.Timer(timeout, set_cancelled)`, gives the tool a 5s grace
window to format a partial response, then unconditionally `clr_cancelled()` in the `finally`
(the flag is sticky — without the clear, every later `user_cancelled()` returns True forever).

**Status**: ported. `sync_wrapper` now clears the flag at entry, arms a
`threading.Timer(timeout, set_cancelled)`, gives the tool a 5s grace window
(`_NATIVE_CANCEL_GRACE_SEC`) to format a partial response, and clears the sticky flag
unconditionally in the `finally`. `find` and `find_bytes` gained the
`cursor.cancelled` marker so callers can tell "we stopped early" from "end of page".
Upstream's `search_text` changes do not apply — we have no such tool.

### 3. `sync.py`: `idc.batch()` is called from the requesting thread, not the IDA main thread

**Upstream fix**: part of `f0cd877`.

`sync_wrapper()` calls `old_batch = idc.batch(1)` *before* `execute_sync`, i.e. on the HTTP
worker thread, and restores it in a `finally` that also runs off-thread. Upstream moved both
into `runned()` so they execute on the IDA main thread, and added `get_pre_call_batch()` so
tools restore the caller's real prior state instead of a hard-coded default.

**Current state**: `src/ida_multi_mcp/ida_mcp/sync.py:97` and `:126` still call `idc.batch()`
off the main thread.

### 4. IDA 8.5+ APIs used without version guards

**Upstream fix**: `f212140`, `7cca988`, `dd4e730`, plus `compat.py`'s `tinfo_get_udm()`,
`inf_get_*()`, `get_ordinal_limit()`, `get_func_name()`, `get_func_prototype()`.

Our `compat.py` is 65 lines and covers only entry-point APIs and `inf_is_64bit`. These call
sites bypass it and will raise on older or early builds:

| Call | Introduced | Sites |
|---|---|---|
| `ida_ida.inf_get_min_ea` / `inf_get_max_ea` | 8.5 | `api_analysis.py:613,627,628,795,796` |
| `ida_ida.inf_get_omin_ea` / `inf_get_omax_ea` | 8.5 | `utils.py:434,435` |
| `ida_typeinf.get_ordinal_limit` | 8.4 (`get_ordinal_qty` before) | `api_resources.py:177`, `api_types.py:216` |
| `tinfo_t.get_udm` | 8.5, **absent in 9.0 SP0** | `api_modify.py:376`, `api_stack.py:121`, `api_types.py:355` |
| `func_t.get_name` | 8.5, **absent in 9.0 SP0** | `api_resources.py:130` (unguarded; `utils.py:625` has a try/except) |

Upstream additionally *rejects* IDA 9.0 SP0 (build 240925) at import time with an explicit
error listing the missing methods, rather than failing deep inside a tool.

**Current state**: README now documents an 8.5+ floor and the 9.0 SP0 exclusion. Adding the
`compat.py` wrappers would restore the original 8.3+ claim.

---

## MEDIUM Priority — Not Yet Adopted

### 5. `idb_save` uses save-as semantics in the GUI

**Upstream fix**: `6673de9` (closes upstream #446).

Upstream's bug was packing with `DBFL_KILL|DBFL_COMP`, deleting the loose `.id0/.id1/.id2/
.nam/.til` files the GUI is actively using. We pass `flags=0`, so we do **not** have the
corruption bug — but we always pass an explicit `save_path` (`api_core.py:661`), which is a
save-as rather than IDA's native in-place save. Upstream branches on `ida_kernwin.is_idaq()`
and uses `save_database(None, 0)` in the GUI. Worth mirroring; we already detect `is_idaq`.

### 6. Bounded HTTP session registry

**Upstream fix**: `1c97442`.

Upstream's `_http_sessions` was an unbounded `set[str]`; it is now a TTL + max-count LRU dict
(24h / 4096). Our zeromcp copies do not track HTTP sessions at all, so this is currently
moot — but it is the design to copy if session tracking is ever added.

### 7. Richer tool error reporting

**Upstream fix**: `c395db9` (fixes upstream #52) — `rename`, `xrefs`, `decompile`, `set_type`
return actionable messages instead of bare failures. Applies to our `api_analysis.py`,
`api_composite.py`, `api_modify.py`, `api_types.py`, `utils.py`.

---

## Deliberately Not Adopted (architectural divergence)

| Upstream change | Why it does not apply |
|---|---|
| `c028108`, `8545e80`, `22aae5f`, `9fd8d89`, `420cfdb`, `2c4c65b`, `8a0820c`, `e9ccaba` — supervisor architecture | ida-multi-mcp's router + file registry + subprocess-per-binary model already covers this ground differently |
| `e12fbb5` — stale strings cache when switching binaries | Our `idalib_worker.py` is one binary per process; there is no in-process database switch to invalidate |
| `492a569` — SIGTERM/SIGINT handler deadlock in `idalib_server` | Our worker's handler calls `sys.exit(0)` rather than `MCP_SERVER.stop()`, so it does not block on `HTTPServer.shutdown()` |
| `54b0566`, `e802b32` — `rpc.py` truncation metadata | `_install_tools_call_patch()` is disabled here (`rpc.py:155`); the router owns truncation |
| `0916ebf`, `77c3090`, `ca35773`, `bf59293` — sigmaker | Feature we have not ported |
| `c93166b`, `6828fd9`, `397e09c`, `0b2ac19` — trace subsystem | Feature we have not ported |
| `913421a`, `e02eaec`, `aae0afc`, `c6f491d`, `e88bb69`, `37b8a84`, `6dc91a0` — debugger refactor | Our `api_debug.py` diverged; revisit only if debugger tools are actively used |
| `40e585c`, `5368021`, `1be78d0`, `120ae7a` — Kimi/Codex installer targets | Our installer covers 26 clients including Codex, on a different code path |

---

## Already Adopted

| Upstream change | Adopted in |
|---|---|
| BSS-safe reads (`read_bytes_bss_safe` / `read_int_bss_safe`, `2fee279`) | PR #10 |
| Whitespace compaction (`compact_whitespace`) | PR #11 |
| Compact JSON serialization (`separators=(",", ":")`) | PR #11 |
| `parse_address` symbol resolution (`idaapi.get_name_ea` fallback) | PR #12 |
| Lazy caches for functions and globals | PR #14 |
| Headless detection via `is_idaq()` | PR #15 |
| Reentrancy `get_nowait()` + batch on the IDA main thread (`85efdf8`, `f0cd877`) | PR #26 |
| Native cancellation at the tool deadline (`55533c4`) | PR #28 |
| Tool parameter consistency (PR #362 upstream) | Names already match |
| HTTP Host/Origin validation | `http.py`; CORS fallback hardened in PR #17 |
| `@unsafe` gating in idalib | `is_idalib_available()` + worker `--unsafe` |
| `survey_binary`, `api_composite`, `append_comments`, `define_func/code`, `undefine` | PRs #2–#4 |
| `func_query`, `xref_query`, `insn_query`, `analyze_batch`, `imports_query`, `idb_save` | PR #7 |

---

## ida-multi-mcp Unique Features (Not in Upstream)

| Feature | Description |
|---|---|
| Multi-instance router | Single MCP endpoint proxying to N IDA instances |
| `instance_id` routing | Explicit per-call instance targeting |
| Auto-select single instance | Omit `instance_id` when only 1 instance registered |
| Function similarity (BCSD) | `index_functions` / `similar_functions` / `compare_functions`, MinHash + anchors + CFG, optional jTrans neural recall |
| `compare_binaries` | Router-level diff of two instances |
| `classify_functions` | Batch function classification (thunk/wrapper/leaf/dispatcher/complex) |
| `func_profile` | Per-function metrics with sort/pagination |
| `list_cached_outputs` | Browse truncated output cache |
| `decompile_to_file` | Batch decompile to disk (router-orchestrated) |
| idalib subprocess model | One process per binary, true parallelism |
| IDA installation auto-detection | `--install` scans filesystem for IDA directory |
| Benchmark script | `scripts/benchmark.py` for latency + token measurement |

---

## Adoption Roadmap

| # | Item | Upstream commit | Priority | Effort |
|---|---|---|---|---|
| ~~1~~ | ~~`set_cancelled()` at tool deadline~~ — adopted | `55533c4` | HIGH | M |
| ~~2~~ | ~~`get_nowait()` in `call_stack` cleanup~~ — adopted | `85efdf8` | HIGH | S |
| ~~3~~ | ~~Move `idc.batch()` onto the IDA main thread~~ — adopted | `f0cd877` | HIGH | S |
| 4 | `compat.py` guards for 8.4/8.5/9.0-SP0 APIs | `f212140`, `7cca988` | HIGH | M |
| 5 | `idb_save` native in-place save in GUI | `6673de9` | MED | S |
| 6 | Richer error reporting on rename/xrefs/decompile/set_type | `c395db9` | MED | M |
