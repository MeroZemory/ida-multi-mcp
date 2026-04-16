# ida-multi-mcp MCP Tool Surface Improvement Plan

## Context

ida-multi-mcp currently provides 74 IDA tools + 10 resources + 8 management tools = 92 total MCP commands. After three rounds of porting (survey_binary, api_composite x4, api_modify x4) and idalib headless integration, a full review of the tool surface was conducted to plan **additions, improvements, and removals**.

**Goal**: Rather than blindly expanding the tool count, reduce unnecessary overlap and fill only the gaps that genuinely improve LLM reverse-engineering workflows.

---

## Phase 1 — Quick Wins (Cleanup & UX)

### 1.1 EDIT: Auto-select single instance
- **File**: `src/ida_multi_mcp/router.py` (route_request, lines 43-56)
- **What**: When `instance_id` is omitted and the registry contains exactly one instance, auto-select it. Return an error only for 0 or 2+ instances.
- **Why**: Most users run a single IDA instance. Requiring `instance_id` on every call is unnecessary friction — forces an extra `list_instances` round-trip.
- **Size**: S | **Breaking**: No

### 1.2 EDIT: Consolidate register tools (6 → 2)
- **File**: `src/ida_multi_mcp/ida_mcp/api_debug.py`
- **What**: Merge `dbg_regs` / `dbg_regs_remote` / `dbg_gpregs` / `dbg_gpregs_remote` / `dbg_regs_named` / `dbg_regs_named_remote` into two tools: `dbg_regs` (current thread) and `dbg_regs_remote` (specified threads). Add parameters `filter` (all/gp/named) and `names` (comma-separated, used when filter=named).
- **Why**: Six entry points for the same internal helpers — LLMs waste tokens deciding which variant to call. Two parameterized tools cover all use cases.
- **Size**: S | **Breaking**: Yes (deprecation path: keep old names with warning for one release, then remove)

### 1.3 ADD: `xrefs_from` tool
- **File**: `src/ida_multi_mcp/ida_mcp/api_analysis.py`
- **What**: Symmetric counterpart to `xrefs_to`. Currently xrefs-from only exists as a resource (`ida://xrefs/from/{addr}`) — asymmetric with the tool-based `xrefs_to`.
- **Why**: Resources are less discoverable than tools in most MCP clients. Pairing with `xrefs_to` is the natural API shape.
- **Size**: S | **Breaking**: No

### 1.4 REMOVE: Deprecated dispatch stubs
- **File**: `src/ida_multi_mcp/server.py` (lines 172-183)
- **What**: Remove the `get_active_instance` / `set_active_instance` error-returning dispatch code. These tools are not listed in tools/list — pure dead code.
- **Size**: S | **Breaking**: No

### 1.5 EDIT: Extend cache TTL + add listing tool
- **Files**: `src/ida_multi_mcp/cache.py`, `src/ida_multi_mcp/server.py`
- **What**: Increase TTL from 10 min to 30 min (env-var override). Add `list_cached_outputs` management tool returning IDs, age, and size preview.
- **Why**: Truncated output expires before analysts can retrieve it during long sessions. Without a listing tool, losing a cache_id means losing the data.
- **Size**: S | **Breaking**: No

---

## Phase 2 — Upstream Ports (Query Richness)

### 2.1 ADD: `func_query`
- **File**: `src/ida_multi_mcp/ida_mcp/api_core.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_core.py:545`
- **What**: Regex name filter, size range (min/max), type filter (named/unnamed/library/thunk), sort key (size/name/addr/xref_count), pagination.
- **Why**: `list_funcs` only supports glob filtering. Queries like "all unnamed functions >500 bytes sorted by size" are impossible without `py_eval`.
- **Size**: M | **Breaking**: No

### 2.2 ADD: `xref_query`
- **File**: `src/ida_multi_mcp/ida_mcp/api_analysis.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_analysis.py`
- **What**: Unified xref query with direction (to/from/both), type filter (code/data/all), dedup, sort, and pagination.
- **Why**: Combining `xrefs_to` + the `xrefs_from` resource cannot filter or sort results.
- **Size**: M | **Breaking**: No

### 2.3 ADD: `insn_query`
- **File**: `src/ida_multi_mcp/ida_mcp/api_analysis.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_analysis.py`
- **What**: Instruction search by mnemonic, operand values, within function/segment/address-range scope. Internal helpers (`_resolve_insn_scan_ranges`, `_scan_insn_ranges`) already exist in the current project but lack a `@tool` entry point.
- **Why**: Helpers are already present — only the entry point needs wiring. Enables "find all `syscall` instructions" workflows.
- **Size**: S | **Breaking**: No

### 2.4 ADD: `analyze_batch`
- **File**: `src/ida_multi_mcp/ida_mcp/api_analysis.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_analysis.py`
- **What**: Multiple function addresses + selectable sections (decompile/asm/xrefs/strings/constants/callees) in one call. Internally reuses `_analyze_function_internal` from `api_composite.py`.
- **Why**: Analyzing 10 functions currently requires 10 round-trips. Batching in a single IDA main-thread call eliminates per-call overhead.
- **Size**: M | **Breaking**: No

### 2.5 ADD: `imports_query`
- **File**: `src/ida_multi_mcp/ida_mcp/api_core.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_core.py:773`
- **What**: Module name + import name pattern filter + pagination.
- **Why**: Current `imports` tool only provides flat pagination. "Show all kernel32 imports" is impossible.
- **Size**: S | **Breaking**: No

### 2.6 ADD: `idb_save`
- **File**: `src/ida_multi_mcp/ida_mcp/api_core.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_core.py:803`
- **What**: Wraps `ida_loader.save_database()` with optional path.
- **Why**: After renaming/retyping there is no save mechanism — currently requires `py_eval`.
- **Size**: S | **Breaking**: No

### 2.7 ADD: `enum_upsert`
- **File**: `src/ida_multi_mcp/ida_mcp/api_types.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_types.py:185`
- **What**: Idempotent enum create/update. Preserves existing members, supports bitfield.
- **Why**: `declare_type` cannot update enums (full replacement only). Incremental enum construction workflow is blocked.
- **Size**: M | **Breaking**: No

### 2.8 ADD: `server_health` + `server_warmup`
- **File**: `src/ida_multi_mcp/ida_mcp/api_core.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_core.py:348, 355`
- **What**: health — uptime, idb_path, auto_analysis_ready, hexrays_ready. warmup — wait for auto-analysis + build caches + init Hex-Rays.
- **Why**: Diagnostics for multi-instance setups + first-call latency reduction.
- **Size**: S | **Breaking**: No

---

## Phase 3 — Innovative Tools (ida-multi-mcp Unique Value)

### 3.1 ADD: `compare_binaries` (router-level)
- **File**: `src/ida_multi_mcp/tools/management.py`
- **What**: Takes two `instance_id` values, collects `survey_binary` results from both, returns function list / import / string diffs. Classified as added/removed/changed.
- **Why**: The unique value proposition of the multi-instance architecture. Patch diffing, version comparison, variant analysis — currently requires manual side-by-side comparison.
- **Size**: L | **Breaking**: No

### 3.2 ADD: `classify_functions`
- **File**: `src/ida_multi_mcp/ida_mcp/api_analysis.py`
- **What**: Expose `_classify_func` (internal to survey_binary) as a standalone tool. Accepts address list or all non-library functions. Batch classification as thunk/wrapper/leaf/dispatcher/complex.
- **Why**: `survey_binary` only classifies the top 15 by xref count. Full-binary classification is essential for triage prioritization.
- **Size**: M | **Breaking**: No

### 3.3 ADD: `func_profile`
- **File**: `src/ida_multi_mcp/ida_mcp/api_analysis.py`
- **Upstream**: `_ref/ida-pro-mcp/.../api_analysis.py`
- **What**: Per-function profile: basic block count, cyclomatic complexity, instruction count, callee/caller count, string count, size. Supports filter + pagination.
- **Why**: Fills the gap between `list_funcs` (too little info) and `analyze_function` (too expensive per call). Spreadsheet-like view for analysis prioritization.
- **Size**: M | **Breaking**: No

---

## Deferred / Not Adopted

| Item | Reason |
|---|---|
| Remove `int_convert` | LLMs can convert numbers natively, but IDA-context signed/sized interpretation is more accurate. Removal benefit does not justify compatibility cost |
| `entity_query` | Achievable via `func_query` + `imports_query` + `find_regex` combination. Unified query adds complexity for marginal value |
| Merge `find` / `find_bytes` / `find_regex` | Each serves a specialized purpose (structured search / byte patterns / regex). Separation is justified |
| `suggest_names` / `find_vulnerabilities` | The LLM itself performs these roles — they belong in prompt engineering, not tool design |
| `py_exec_file` | Conflicts with current `py_eval` sandbox policy. Security compromise is not acceptable |

---

## Verification

After completing each phase:
1. `python -m pytest tests/ -q` — all unit tests pass
2. Restart IDA, then `list_instances` → `refresh_tools` → verify new tool schemas appear
3. Live-test each new tool against a real binary (e.g., Client_dump_SCY.exe)
4. Regenerate `ida_tool_schemas.json` from live IDA instance
5. Confirm CI 6/6 green, then create PR

---

## Critical Files

| File | Phase | Changes |
|---|---|---|
| `router.py` | 1 | Auto-select single instance |
| `api_debug.py` | 1 | Register tool consolidation |
| `api_analysis.py` | 1, 2, 3 | xrefs_from, analyze_batch, xref_query, insn_query, classify_functions, func_profile |
| `api_core.py` | 2 | func_query, imports_query, idb_save, server_health/warmup |
| `api_types.py` | 2 | enum_upsert |
| `server.py` | 1 | Remove deprecated dispatch, register cache tool |
| `cache.py` | 1 | TTL extension |
| `tools/management.py` | 1, 3 | list_cached_outputs, compare_binaries |

**Net effect**: ~92 → ~90 tools (consolidation -6, new +14, deprecated removal -2). Tool count stays similar but query richness, UX, and multi-instance utility improve significantly.
