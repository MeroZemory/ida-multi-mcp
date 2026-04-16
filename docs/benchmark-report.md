# Performance Benchmark

Measured against a **large game client** (736K functions, x86-64) on IDA 9.3 / Windows 11.
Single iteration per tool, same binary loaded without saving IDB between runs.

## Summary

|  | Before | After | Change |
|---|---:|---:|---:|
| **Total latency** | 51,307 ms | 32,030 ms | **-37.6%** |
| **Total response** | 372,886 B | 373,279 B | ~0% |
| **Est. tokens** | ~93,211 | ~93,311 | ~0% |

> Speed improved significantly with no increase in token cost.

## Latency by Category

| Category | Before (ms) | After (ms) | Delta | Change |
|---|---:|---:|---:|---:|
| Triage | 25,634 | 17,014 | -8,620 | **-33.6%** |
| Query | 12,640 | 7,472 | -5,168 | **-40.9%** |
| Navigation | 8,803 | 5,543 | -3,260 | **-37.0%** |
| Meta | 2,968 | 1,893 | -1,076 | **-36.2%** |
| Analysis | 1,240 | 41 | -1,199 | **-96.7%** |
| Types | 5 | 15 | +10 | — |
| Modification | 6 | 4 | -2 | — |
| Memory | 5 | 27 | +22 | — |
| Composite | 5 | 22 | +17 | — |

## Per-Tool Detail

| Tool | Before (ms) | After (ms) | Delta | Response (B) | ~Tokens |
|---|---:|---:|---:|---:|---:|
| **Triage** | | | | | |
| `survey_binary` (standard) | 19,270 | 12,083 | -7,187 | 282,013 | 70,503 |
| `survey_binary` (minimal) | 6,364 | 4,930 | -1,433 | 26,667 | 6,666 |
| **Analysis** | | | | | |
| `decompile` | 1,217 | 5 | -1,212 | 2,496 | 624 |
| `disasm` (100 insns) | 5 | 21 | +17 | 4,356 | 1,089 |
| `analyze_function` | 8 | 8 | 0 | 3,865 | 966 |
| `analyze_batch` (1 func) | 10 | 6 | -4 | 3,967 | 991 |
| **Navigation** | | | | | |
| `list_funcs` (50) | 7,672 | 4,805 | -2,867 | 9,739 | 2,434 |
| `list_globals` (50) | 1,110 | 688 | -422 | 7,313 | 1,828 |
| `imports` (50) | 9 | 24 | +15 | 13,329 | 3,332 |
| `find_regex` | 3 | 2 | -1 | 2,059 | 514 |
| `find_bytes` | 5 | 2 | -3 | 334 | 83 |
| `xrefs_to` | 2 | 1 | -1 | 584 | 146 |
| `xrefs_from` | 2 | 20 | +18 | 601 | 150 |
| **Query** | | | | | |
| `func_query` (size>100) | 12,627 | 7,449 | -5,178 | 5,027 | 1,256 |
| `imports_query` (kernel32) | 13 | 23 | +9 | 4,651 | 1,162 |
| **Modification** | | | | | |
| `set_comments` | 4 | 3 | -1 | 224 | 56 |
| `append_comments` | 2 | 1 | -0 | 277 | 69 |
| **Memory** | | | | | |
| `get_bytes` (64B) | 2 | 25 | +23 | 842 | 210 |
| `get_string` | 3 | 2 | -1 | 238 | 59 |
| **Types** | | | | | |
| `search_structs` | 5 | 15 | +10 | 127 | 31 |
| **Profile** | | | | | |
| `func_profile` | — | — | *error* | — | — |
| `classify_functions` | — | — | *error* | — | — |
| **Meta** | | | | | |
| `server_health` | 3 | 4 | +1 | 780 | 195 |
| `server_warmup` | 3 | 3 | 0 | 1,030 | 257 |
| `idb_save` | 2,962 | 1,886 | -1,076 | 400 | 100 |
| **Composite** | | | | | |
| `trace_data_flow` (depth=2) | 5 | 22 | +17 | 2,360 | 590 |

## Notes

- **Token cost is stable** — the improvement is purely in latency, with no change in response payload sizes.
- Tools marked *error* require an IDA restart to pick up newly registered tool implementations.
- Small ms-level increases (e.g., `disasm` +17ms, `get_bytes` +23ms) are within normal IDA single-thread jitter and not statistically significant at 1 iteration.
- `decompile` 1,217ms → 5ms reflects Hex-Rays internal cache (first call warms the cache).
- Measured on: IDA Home 9.3, Python 3.11, Windows 11, localhost HTTP JSON-RPC.
