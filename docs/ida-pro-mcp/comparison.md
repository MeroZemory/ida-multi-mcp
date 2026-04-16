# ida-pro-mcp (upstream) vs ida-multi-mcp — Comparison

Last updated: 2026-04-16 (upstream commit `d80ed7f`)

This document tracks what upstream features/fixes ida-multi-mcp has NOT yet adopted.

## Current Coverage

After PRs #2–#8, ida-multi-mcp has ported or implemented equivalents of most upstream tools. The remaining gaps are **bugfixes, optimizations, and minor features** rather than major missing tool categories.

---

## HIGH Priority — Correctness & Token Cost

### 1. BSS/Virtual Memory Read Bug

**Upstream fix**: commit `2fee279` — `read_bytes_bss_safe()` and `read_int_bss_safe()` helpers in `utils.py`.

**Problem**: `ida_bytes.get_bytes()` returns `0xFF` for unloaded BSS/virtual memory regions. Upstream now returns `0x00` for these addresses, which is the correct semantic (BSS is zero-initialized).

**Current state**: ida-multi-mcp uses raw `ida_bytes.get_bytes()` in `api_memory.py` and `api_types.py`, so reading BSS globals returns incorrect `0xFF` byte fills.

**Impact**: Any memory read of uninitialized globals or BSS data is wrong. Affects `get_bytes`, `get_int`, `get_global_value`, `read_struct`.

### 2. Token Optimization — Whitespace Compaction

**Upstream fix**: PR #341 — `compact_whitespace()` function in `utils.py`.

**What it does**: Collapses multiple spaces/tabs in decompiler and disassembly output while preserving string literals. Reduces response payload size.

**Current state**: ida-multi-mcp sends raw Hex-Rays/disasm output with original whitespace, inflating token cost.

**Impact**: `decompile` and `disasm` responses are larger than necessary. On a 736K-function binary, this can add up.

### 3. Token Optimization — Compact JSON Serialization

**Upstream fix**: PR #341 — `separators=(",", ":")` in zeromcp JSON serialization.

**What it does**: Removes spaces after `:` and `,` in all JSON-RPC responses. ~15-20% reduction in wire bytes.

**Current state**: ida-multi-mcp uses default `json.dumps()` with spaces (`", ": "`).

**Impact**: Every tool response is larger than necessary. Combined with whitespace compaction, upstream achieves significant token savings.

---

## MEDIUM Priority — Usability & Performance

### 4. parse_address Symbol Name Resolution

**Upstream fix**: PR #349 — `parse_address()` now calls `idaapi.get_name_ea()` as fallback.

**What it does**: Allows passing symbol names (e.g., `"main"`, `"CreateFileW"`) directly to any tool that takes an address parameter. If hex parsing fails, tries name lookup.

**Current state**: ida-multi-mcp's `parse_address()` only accepts hex/decimal strings. Passing a function name like `"main"` fails with an error.

**Impact**: Users must look up addresses before calling tools. Upstream allows natural name-based workflows.

### 5. Lazy Cache Initialization

**Upstream fix**: commit `c25459b` — removed `init_caches()` from plugin load path.

**What it does**: Strings cache is built lazily on first access instead of at plugin startup. Reduces IDA startup time.

**Current state**: ida-multi-mcp calls `init_caches()` eagerly on plugin load (`__init__.py` exports it, plugin calls it on Ctrl+M).

**Impact**: Plugin startup is slower, especially on large binaries. Not a correctness issue.

### 6. idalib Detection via `is_idaq()`

**Upstream fix**: commit `b8be030` — uses `ida_kernwin.is_idaq()` instead of `sys.modules` check.

**What it does**: Cleaner headless mode detection. `is_idaq()` returns `False` when running under idalib (no GUI).

**Current state**: ida-multi-mcp uses `ida_major` version checks and separate `idalib_worker.py` architecture (subprocess model), so this is less relevant.

**Impact**: LOW — architectural difference makes this a minor code quality item.

---

## Already Adopted (No Action Needed)

| Upstream Change | Status |
|---|---|
| Tool parameter consistency (PR #362): `int_convert`, `list_globals`, `set_comments`, `dbg_step_into/over` naming | Already uses these names |
| HTTP Host/Origin validation (PR #352) | Already implemented in `http.py` |
| `@unsafe` flag gating in idalib (PR #335) | Implemented via `is_idalib_available()` + worker `--unsafe` flag |
| `survey_binary` | Ported (PR #2) |
| `api_composite` (4 tools) | Ported (PR #3) |
| `append_comments`, `define_func/code`, `undefine` | Ported (PR #4) |
| `func_query`, `xref_query`, `insn_query`, `analyze_batch` | Implemented (PR #7) |
| `imports_query`, `idb_save`, `enum_upsert` | Implemented (PR #7) |
| `server_health`, `server_warmup` | Implemented (PR #7) |
| IDA 8.3–9.3 compat shims | `compat.py` with try/import fallback |

---

## ida-multi-mcp Unique Features (Not in Upstream)

| Feature | Description |
|---|---|
| Multi-instance router | Single MCP endpoint proxying to N IDA instances |
| `instance_id` routing | Explicit per-call instance targeting |
| Auto-select single instance | Omit `instance_id` when only 1 instance registered |
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

| # | Item | Priority | Effort |
|---|---|---|---|
| 1 | BSS read fix (`read_bytes_bss_safe`) | HIGH | S |
| 2 | Whitespace compaction (`compact_whitespace`) | HIGH | S |
| 3 | Compact JSON serialization | HIGH | S |
| 4 | `parse_address` symbol resolution | MED | S |
| 5 | Lazy cache initialization | MED | S |
| 6 | `is_idaq()` detection | LOW | S |
